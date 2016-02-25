#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
*sshtunnel* - Initiate SSH tunnels via a remote gateway.

Useful when you need to connect to local ports on remote hosts through SSH
tunnel. It works by opening a port forwarding SSH connection in the
background, using threads. The connection(s) are closed when explicitly
calling the `close` method of the returned SSHTunnelForwarder object.

------------------------------------------------------------------------------

                            |
+------------+              |    +----------+               +---------+
|   LOCAL    |              |    |  REMOTE  |               | PRIVATE |
|   SERVER   | <== SSH ========> | GATEWAY  | <== local ==> | HOST    |
+------------+              |    +----------+               +---------+
                            |
                         FIREWALL

------------------------------------------------------------------------------
Fig1: How to connect to PRIVATE HOST through SSH tunnel.

See: `sshtunnel.open_tunnel` function and `sshtunnel.SSHTunnelForwarder` class.

Example 1:

    from sshtunnel import open_tunnel
    with open_tunnel(
        (ssh_host, ssh_port),
        ssh_host_key=None,
        ssh_username=ssh_user,
        ssh_password=ssh_password,
        ssh_private_key=None,
        remote_bind_address=(REMOTE_HOST, REMOTE_PORT)
    ) as server:
        def do_something(port):
            pass

        print("LOCAL PORTS:", server.local_bind_ports)
        do_something(server.local_bind_ports)

Example 2:

    import sshtunnel

    server = SSHTunnelForwarder(ssh_address=('pahaz.urfuclub.ru', 22),
                                ssh_username="pahaz",
                                ssh_password="secret",
                                remote_bind_address=('127.0.0.1', 5555))
    server.start()

    print(server.local_bind_ports)
    # work with `SECRET SERVICE` through `server.local_bind_ports`.

    server.stop()



CLI usage: sshtunnel [-h] [-U SSH_USERNAME] [-p SSH_PORT] [-P SSH_PASSWORD] -R
                     IP:PORT [IP:PORT ...] [-L [IP:PORT [IP:PORT ...]]]
                     [-k SSH_HOST_KEY] [-K RSA_KEY_FILE]
                     [-S RSA_KEY_FILE_PASSWORD] [-t] [-v] [-V] [-x IP:PORT]
                     [-c SSH_CONFIG_FILE] [-z]
                     ssh_address


positional arguments:
  ssh_address          SSH server IP address (GW for SSH tunnels)
                       set with '-- ssh_address' if immediately after -R or -L

optional arguments:
  -h, --help           show this help message and exit
  -U, --username SSH_USERNAME
                       SSH server account username
  -p, --server_port SSH_PORT
                       SSH server TCP port (default: 22)
  -P, --password SSH_PASSWORD
                       SSH server account password
  -R, --remote_bind_address IP:PORT [IP:PORT ...]
                       Remote bind address sequence: ip1:port1 ... ip_n:port_n
                       Equivalent to ssh -Lxxxx:IP_ADDRESS:PORT
                       If omitted, default port is 22.
                       Example: -R 10.10.10.10: 10.10.10.10:5900
  -L, --local_bind_address [IP:PORT [IP:PORT ...]]
                       Local bind address sequence: ip_1:port_1 ... ip_n:port_n
                       Equivalent to ssh -LPORT:xxxxxxxxx:xxxx, being the local
                       IP address optional.
                       By default it will listen in all interfaces (0.0.0.0)
                       and choose a random port.
                       Example: -L :40000
  -k, --ssh_host_key SSH_HOST_KEY
                       Gateway's host key
  -K, --private_key_file SSH_PRIVATE_KEY
                       RSA private key file
  -S, --private_key_file_password RSA_KEY_FILE_PASSWORD
                       RSA private key file password
  -t, --threaded       Allow concurrent connections to each tunnel
  -v, --verbosity      Increase output verbosity (default: ERROR)
  -V, --version        Show version number and quit
  -x, --proxy IP:PORT
                       IP and port of SSH proxy to destination
  -c, --config SSH_CONFIG_FILE
                       SSH configuration file, defaults to SSH_CONFIG_FILE
  -z, --compress       Request server for compression over SSH transport
  -A, --agent           Allow looking for keys from an SSH agent

"""

import sys
import socket
import getpass
import logging
import os
import argparse
import warnings
import threading
from binascii import hexlify
from select import select

import paramiko

if sys.version_info[0] < 3:  # pragma: no cover
    import SocketServer as socketserver
    string_types = basestring,  # noqa
    input_ = raw_input
else:
    import socketserver
    string_types = str
    input_ = input


__version__ = '0.0.7.2'
__author__ = 'pahaz'

__all__ = ('SSHTunnelForwarder', 'BaseSSHTunnelForwarderError',
           'HandlerSSHTunnelForwarderError', 'open_tunnel')

DEFAULT_LOGLEVEL = logging.ERROR  # default level if no logger passed
LOCAL_CHECK_TIMEOUT = 1  # Timeout in seconds for local tunnel side detection
DAEMON = False
TRACE = False
_CONNECTION_COUNTER = 1
_lock = threading.Lock()
SSH_TIMEOUT = None  # timeout (seconds) for the connection to the SSH gateway
SSH_CONFIG_FILE = '~/.ssh/config'

########################
#                      #
#       Utils          #
#                      #
########################


def check_host(host):
    assert isinstance(host, string_types), "IP is not a string ({0})".format(
        type(host).__name__
    )


def check_port(port):
    assert isinstance(port, int), "PORT is not a number"
    assert port >= 0, "PORT < 0 ({0})".format(port)


def check_address(address):
    """
    Checks that the format of the address is correct

    >>> check_address(("127.0.0.1", 22))
    """
    assert isinstance(address, tuple), "ADDRESS is not a tuple ({0})".format(
        type(address).__name__
    )
    check_host(address[0])
    check_port(address[1])


def check_addresses(address_list):
    """
    Checks that the format of the address list is correct

    >>> check_addresses([("127.0.0.1", 22), ("127.0.0.1", 2222)])
    """
    assert isinstance(address_list, (list, tuple))
    for address in address_list:
        check_address(address)


def create_logger(logger=None, loglevel=None):
    """
    Attaches or creates a new logger and creates console handlers if not
    present
    """
    logger = logger or logging.getLogger(
        '{0}.SSHTunnelForwarder'.format(__name__)
    )
    if not logger.handlers:  # if no handlers, add a new one (console)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s | %(levelname)-8s| %(message)s')
        )
        logger.setLevel(loglevel or DEFAULT_LOGLEVEL)
        console_handler.setLevel(loglevel or DEFAULT_LOGLEVEL)
        logger.addHandler(console_handler)
    elif loglevel:  # only override if loglevel was set
        logger.setLevel(loglevel)
        for handler in logger.handlers:
            handler.setLevel(loglevel)

    check_paramiko_handlers()
    return logger


def check_paramiko_handlers(logger=None):
    """
    Add a console handler for paramiko.transport's logger if not present
    """
    paramiko_logger = logging.getLogger('paramiko.transport')
    if not paramiko_logger.handlers:
        if logger:
            paramiko_logger.handlers = logger.handlers
        else:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter('%(asctime)s | %(levelname)-8s| PARAMIKO: '
                                  '%(lineno)03d@%(module)-10s| %(message)s')
            )
            paramiko_logger.addHandler(console_handler)


def _read_private_key_file(pkey_file,
                           pkey_password=None,
                           logger=None):
    """ Get SSH private key from a file given an optional password """
    ssh_private_key = None
    try:
        ssh_private_key = paramiko.RSAKey.from_private_key_file(
            pkey_file,
            password=pkey_password
        )
    except paramiko.PasswordRequiredException:
        if logger:
            logger.error('Password is required for key {0}'
                         .format(pkey_file))
    except paramiko.SSHException:
        if logger:
            logger.error('Private key file could not be loaded. '
                         'Bad key password?')
    finally:
        return ssh_private_key


def address_to_str(address):
    return "{0[0]}:{0[1]}".format(address)


def get_connection_id():
    global _CONNECTION_COUNTER
    with _lock:
        uid = _CONNECTION_COUNTER
        _CONNECTION_COUNTER += 1
    return uid


def remove_none_values(dictionary):
    """ Remove dict keys whose value is None """
    return list(map(dictionary.pop,
                    [i for i in dictionary if dictionary[i] is None]))

########################
#                      #
#       Errors         #
#                      #
########################


class BaseSSHTunnelForwarderError(Exception):
    """ Base exception for Tunnel forwarder errors """
    pass


class HandlerSSHTunnelForwarderError(BaseSSHTunnelForwarderError):
    """ Handler exception for Tunnel forwarder errors """
    pass


########################
#                      #
#       Handlers       #
#                      #
########################


class _ForwardHandler(socketserver.BaseRequestHandler):
    """ Base handler for tunnel connections """
    remote_address = None
    ssh_transport = None
    logger = None

    def handle(self):
        uid = get_connection_id()
        info = 'In #{0} <-- {1}'.format(uid, self.client_address)
        try:
            assert isinstance(self.remote_address, tuple)
            chan = self.ssh_transport.open_channel('direct-tcpip',
                                                   self.remote_address,
                                                   self.request.getpeername())
        except AssertionError:
            msg = 'Remote address MUST be a tuple (ip:port): {0}' \
                .format(self.remote_address)
            self.logger.error(msg)
            raise HandlerSSHTunnelForwarderError(msg)
        except paramiko.SSHException as e:
            msg = '{0} to {1} failed: {2}' \
                .format(info, self.remote_address, repr(e))
            self.logger.error(msg)
            raise HandlerSSHTunnelForwarderError(msg)

        if chan is None:
            msg = '{0} to {1} was rejected ' \
                  'by the SSH server.'.format(info, self.remote_address)
            self.logger.error(msg)
            raise HandlerSSHTunnelForwarderError(msg)

        self.logger.info('{0} connected'.format(info))
        try:
            while True:
                rqst, _, _ = select([self.request, chan], [], [], 5)
                if self.request in rqst:
                    data = self.request.recv(1024)
                    if TRACE:
                        self.logger.info('{0} recv: {1}'
                                         .format(info, repr(data)))
                    chan.send(data)
                    if len(data) == 0:
                        break
                if chan in rqst:
                    data = chan.recv(1024)
                    if TRACE:
                        self.logger.info('{0} recv: {1}'
                                         .format(info, repr(data)))
                    self.request.send(data)
                    if len(data) == 0:
                        break
        except socket.error:
            # Sometimes a RST is sent and a socket error is raised, treat this
            # exception. It was seen that a 3way FIN is processed later on, so
            # no need to make an ordered close of the connection here or raise
            # the exception beyond this point...
            self.logger.warning('{0} sending RST'.format(info))
        except Exception as e:
            self.logger.error('{0} error: {1}'.format(info, repr(e)))
        finally:
            chan.close()
            self.request.close()
            self.logger.info('{0} connection closed.'.format(info))


class _ForwardServer(socketserver.TCPServer):  # Not Threading
    """
    Non-threading version of the forward server
    """
    allow_reuse_address = True  # faster rebinding

    @property
    def local_address(self):
        return self.server_address

    @property
    def local_host(self):
        return self.server_address[0]

    @property
    def local_port(self):
        return self.server_address[1]

    @property
    def remote_address(self):
        return self.RequestHandlerClass.remote_address

    @property
    def remote_host(self):
        return self.RequestHandlerClass.remote_address[0]

    @property
    def remote_port(self):
        return self.RequestHandlerClass.remote_address[1]


class _ThreadingForwardServer(socketserver.ThreadingMixIn, _ForwardServer):
    """
    Allows concurrent connections to each tunnel
    """
    # If True, cleanly stop threads created by ThreadingMixIn when quitting
    daemon_threads = DAEMON


class SSHTunnelForwarder(object):
    """
    Class for forward remote server port throw SSH tunnel to local port.

     - start()
     - stop()
     - local_bind_port (local_bind_ports)
     - local_bind_host (local_bind_hosts)
     - local_bind_address (local_bind_addresses)

    Example:

        >>> server = SSHTunnelForwarder(
                        ('pahaz.urfuclub.ru', 22),
                        ssh_username="pahaz",
                        ssh_password="secret",
                        remote_bind_address=('127.0.0.1', 5555))
        >>> server.start()
        >>> print(server.local_bind_port)
        >>> server.stop()
    """
    is_use_local_check_up = False
    daemon_forward_servers = DAEMON
    daemon_transport = DAEMON

    def local_is_up(self, target):
        """
        Check if local side of the tunnel is up (remote target_host is
        reachable on TCP target_port)

        target: (target_host, target_port)
        Returns: Boolean
        """
        try:
            check_address(target)
        except AssertionError:
            self.logger.warning('Target must be a tuple (ip, port), where ip '
                                'is a string (i.e. "192.168.0.1") and port is '
                                'an integer (i.e. 40000).')
            return False

        (host, port) = target
        reachable_from = []
        self._local_interfaces = self._local_interfaces \
            if host in ['', '0.0.0.0'] \
            else [host]

        for host in self._local_interfaces:
            address = (host, port)
            reachable = self._is_address_reachable(address)
            reachable_text = "" if reachable else "*NOT* "
            self.logger.debug('Local side of the tunnel is {1}reachable from '
                              '({0[0]}:{0[1]})'.format(address,
                                                       reachable_text))
            if reachable:
                reachable_from.append(address)

        if reachable_from:
            reachable_from_text = ', '.join(['{0}:{1}'.format(h, p)
                                             for h, p in reachable_from])
            self.logger.info('Local side of the tunnel ({0[0]}:{0[1]}) '
                             'is UP and reachable from ({1})'
                             .format(target, reachable_from_text))
        else:
            self.logger.warning('Local side of tunnel ({0[0]}:{0[1]}) is DOWN,'
                                ' we will not attempt to connect.'
                                .format(target))
        return reachable

    def make_ssh_forward_handler_class(self, remote_address_):
        """
        Make SSH Handler class.
        """
        _Handler = _ForwardHandler
        if not issubclass(_Handler, socketserver.BaseRequestHandler):
            msg = "base_ssh_forward_handler is not a subclass " \
                  "socketserver.BaseRequestHandler"
            self._raise(BaseSSHTunnelForwarderError, msg)

        class Handler(_Handler):
            """ handler class for remote tunnels """
            remote_address = remote_address_
            ssh_transport = self._transport
            logger = self.logger

        return Handler

    def make_ssh_forward_server_class(self, remote_address_):
        return _ThreadingForwardServer if self._threaded else _ForwardServer

    def make_ssh_forward_server(self, remote_address, local_bind_address):
        """
        Make SSH forward proxy Server class.
        """
        _Handler = self.make_ssh_forward_handler_class(remote_address)
        _Server = self.make_ssh_forward_server_class(remote_address)
        try:
            ssh_forward_server = _Server(local_bind_address, _Handler)
            if ssh_forward_server:
                self._server_list.append(ssh_forward_server)
            else:
                self._raise(
                    BaseSSHTunnelForwarderError,
                    'Problem with make ssh {0} <> {1} forwarder. You can '
                    'suppress this exception by using the '
                    '`raise_exception_if_any_forwarder_have_a_problem` '
                    'argument'.format(address_to_str(local_bind_address),
                                      address_to_str(remote_address))
                )
        except IOError:
            self.logger.error("Couldn't open tunnel {0} <> {1} "
                              "might be in use or destination not reachable."
                              .format(address_to_str(local_bind_address),
                                      address_to_str(remote_address)))

    def __init__(
            self,
            ssh_address_or_host=None,
            ssh_config_file=SSH_CONFIG_FILE,
            ssh_host_key=None,
            ssh_password=None,
            ssh_private_key=None,
            ssh_private_key_password=None,
            ssh_proxy=None,
            ssh_proxy_enabled=True,
            ssh_username=None,
            local_bind_address=None,
            local_bind_addresses=None,
            logger=None,
            raise_exception_if_any_forwarder_have_a_problem=True,
            remote_bind_address=None,
            remote_bind_addresses=None,
            set_keepalive=0,
            threaded=True,  # old version False
            compression=False,  # paramiko default
            allow_agent=False,  # look for keys from an SSH agent
            **kwargs  # for backwards compatibility
    ):
        """
        ssh_arguments:
          (ssh_address or ssh_host)
          ssh_config_file=SSH_CONFIG_FILE
          ssh_host_key=None
          ssh_password=None
          ssh_private_key=None
          ssh_private_key_password=None,
          ssh_proxy=None
          ssh_proxy_enabled=True
          ssh_username=None
          local_bind_address=None
          local_bind_addresses=None,
          logger=__name__
          raise_exception_if_any_forwarder_have_a_problem=True,
          remote_bind_address=None
          remote_bind_addresses=None,
          set_keepalive=0,
          threaded=True
          compression=False,
          allow_agent=False,
          ssh_port=22  # DEPRECATED
          ssh_host=None  # DEPRECATED

        ssh_address is (host, port) or host
        use *remote_bind_addresses* if you want open more than one tunnel else
        use *remote_bind_address*

        *local_bind_address* - (ip, port) If None uses ("0.0.0.0", RANDOM)
        *local_bind_addresses* - [(ip1, port_1), (ip_2, port2), ...] If None
                                 uses [local_bind_address]

        *remote_bind_address* - (ip, port)
        *remote_bind_addresses* -  [(ip1, port_1), (ip_2, port2), ...] If None
                                   uses [remote_bind_address]

        Use `forwarder.local_bind_ports` for getting local forwarding ports.
        Or use `forwarder.local_bind_port` for getting local forwarding port if
        you use only one tunnel.
        """
        self.logger = logger or create_logger()
        # Ensure paramiko.transport has a console handler
        check_paramiko_handlers(logger=logger)

        self.ssh_host_key = ssh_host_key
        self.set_keepalive = set_keepalive
        self.compression = compression

        self._raise_fwd_exc = raise_exception_if_any_forwarder_have_a_problem
        self._threaded = threaded
        self._is_started = False

        # Check if deprecated arguments ssh_address or ssh_host were used
        for deprecated_argument in ['ssh_address', 'ssh_host']:
            ssh_address_or_host = self._get_ssh_address_or_host(
                ssh_address_or_host,
                deprecated_argument,
                kwargs
            )

        if isinstance(ssh_address_or_host, tuple):
            check_address(ssh_address_or_host)
            (self.ssh_host, ssh_port) = ssh_address_or_host
        else:
            self.ssh_host = ssh_address_or_host
            ssh_port = kwargs.pop('ssh_port', None)

        if kwargs:
            raise ValueError('Unknown arguments: {0}'.format(kwargs))

        # remote binds
        self._remote_binds = self._get_binds(remote_bind_address,
                                             remote_bind_addresses)
        # local binds
        self._local_binds = self._get_binds(local_bind_address,
                                            local_bind_addresses,
                                            remote=False)
        self._local_binds = self._consolidate_binds(self._local_binds,
                                                    self._remote_binds)

        (self.ssh_username,
         ssh_private_key,  # still needs to go through _consolidate_auth
         self.ssh_port,
         self.ssh_proxy,
         self.compression) = self.read_ssh_config(
             self.ssh_host,
             ssh_config_file,
             ssh_username,
             ssh_private_key,
             ssh_port,
             ssh_proxy if ssh_proxy_enabled else None,
             compression,
             logger)

        self.ssh_private_keys = self.get_keys(key=ssh_private_key,
                                              allow_agent=allow_agent,
                                              logger=self.logger)

        (self.ssh_password, self.ssh_private_keys) = self._consolidate_auth(
            ssh_password=ssh_password,
            ssh_private_keys=self.ssh_private_keys,
            ssh_private_key_password=ssh_private_key_password,
            logger=logger
        )

        if not self.ssh_port:
            self.ssh_port = 22  # fallback value

        check_host(self.ssh_host)
        check_port(self.ssh_port)
        check_addresses(self._remote_binds)
        check_addresses(self._local_binds)

        self._local_interfaces = self._get_local_interfaces()
        self.logger.info('Connecting to gateway: {0}:{1} as user "{2}".'
                         .format(self.ssh_host,
                                 self.ssh_port,
                                 self.ssh_username))

        self.logger.debug('Concurrent connections allowed: {0}'
                          .format(self._threaded))

    @staticmethod
    def read_ssh_config(ssh_host,
                        ssh_config_file,
                        ssh_username,
                        ssh_private_key,
                        ssh_port,
                        ssh_proxy,
                        compression,
                        logger):
        """
        Read ssh_config_file and tries to look for user (ssh_username),
        identityfile (ssh_private_key), port (ssh_port) and proxycommand
        (ssh_proxy) entries for ssh_host
         """
        ssh_config = paramiko.SSHConfig()

        # Try to read SSH_CONFIG_FILE
        try:
            # open the ssh config file
            with open(os.path.expanduser(ssh_config_file), 'r') as f:
                ssh_config.parse(f)
            # looks for information for the destination system
            hostname_info = ssh_config.lookup(ssh_host)
            # gather settings for user, port and identity file
            # last resort: use the 'login name' of the user
            ssh_username = (
                ssh_username or
                hostname_info.get('user')
            )
            ssh_private_key = (
                ssh_private_key or
                hostname_info.get('identityfile', [None])[0]
            )
            ssh_port = ssh_port or hostname_info.get('port')
            proxycommand = hostname_info.get('proxycommand')
            ssh_proxy = ssh_proxy or (paramiko.ProxyCommand(proxycommand) if
                                      proxycommand else None)
            compression = hostname_info.get('compression', compression)
        except IOError:
            logger.warning(
                'Could not read SSH configuration file: {0}'
                .format(ssh_config_file)
            )
        except AttributeError:  # ssh_config_file is None
            logger.info('Skipping loading of ssh config file')
        finally:
            return (ssh_username or getpass.getuser(),
                    ssh_private_key,
                    ssh_port,
                    ssh_proxy,
                    compression)

    @staticmethod
    def get_keys(key=None, allow_agent=False, logger=None):
        agent_keys = []
        if allow_agent:
            agent = paramiko.Agent()
            agent_keys.extend(agent.get_keys())
            if logger:
                logger.debug('{0} keys loaded from agent'
                             .format(len(agent_keys)))
        if key:  # last one to try
            agent_keys.append(key)
        return agent_keys

    @staticmethod
    def _consolidate_binds(local_binds, remote_binds):
        """
        Fill local_binds with defaults when no value/s were specified,
        leaving paramiko to decide in which local port the tunnel will be open
        """
        count = len(remote_binds) - len(local_binds)
        if count < 0:
            raise ValueError('Too many local bind addresses '
                             '(local_bind_addresses > remote_bind_addresses)')
        local_binds.extend([('0.0.0.0', 0) for x in range(count)])
        return local_binds

    @staticmethod
    def _consolidate_auth(ssh_password=None,
                          ssh_private_keys=None,
                          ssh_private_key_password=None,
                          logger=None):
        """Get sure authentication information is in place"""
        for ssh_private_key in ssh_private_keys:
            if isinstance(ssh_private_key, string_types):
                if os.path.exists(ssh_private_key):
                    ssh_private_key = _read_private_key_file(
                        pkey_file=ssh_private_key,
                        pkey_password=ssh_private_key_password,
                        logger=logger
                    )
                elif logger:
                    logger.warning('Private key file not found: {0}'
                                   .format(ssh_private_key))
                    ssh_private_key = None
        if not ssh_password and not any(ssh_private_keys):
            raise ValueError('No password or private key available!')

        return (ssh_password, ssh_private_keys)

    def _raise(self, exception, reason):
        if self._raise_fwd_exc:
            raise exception(reason)

    def _get_transport(self):
        """Return the SSH transport to the remote gateway"""
        if self.ssh_proxy:
            assert(isinstance(self.ssh_proxy, paramiko.proxy.ProxyCommand))
            self.logger.debug('Connecting via proxy: {0}'
                              .format(repr(self.ssh_proxy.cmd[1])))
            _socket = self.ssh_proxy
            _socket.settimeout(SSH_TIMEOUT)
        else:
            _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _socket.settimeout(SSH_TIMEOUT)
            _socket.connect((self.ssh_host, self.ssh_port))
        transport = paramiko.Transport(_socket)
        transport.set_keepalive(self.set_keepalive)
        transport.use_compression(compress=self.compression)
        transport.daemon = DAEMON

        return transport

    def create_tunnels(self):
        """Create SSH tunnels on top of a transport to the remote gateway"""
        self.tunnel_is_up = {}  # handle status of the other side of the tunnel
        try:
            self._transport = self._get_transport()
            for (rem, loc) in zip(self._remote_binds, self._local_binds):
                self.make_ssh_forward_server(rem, loc)
        except socket.gaierror:  # raised by paramiko.Transport
            msg = 'Could not resolve IP address for {0}, aborting!' \
                .format(self.ssh_host)
            self.logger.error(msg)
            raise BaseSSHTunnelForwarderError(msg)
        except (paramiko.SSHException, socket.error) as e:
            template = 'Could not connect to gateway: {0} ({1})'
            msg = template.format(self.ssh_host, e.args)
            self.logger.error(msg)
            raise BaseSSHTunnelForwarderError(msg)
        except BaseSSHTunnelForwarderError as e:
            msg = 'Make SSH Forwarder problem: {0}'.format(repr(e))
            self.logger.error(msg)
            raise BaseSSHTunnelForwarderError(msg)

    @staticmethod
    def _get_binds(bind_address, bind_addresses, remote=True):
        """
        """
        addr_kind = 'remote' if remote else 'local'

        if not bind_address and not bind_addresses:
            if remote:
                raise ValueError("No {0} bind addresses specified. Use "
                                 "'{0}_bind_address' or '{0}_bind_addresses'"
                                 " argument".format(addr_kind))
            else:
                return []
        elif bind_address and bind_addresses:
            raise ValueError("You can't use both '{0}_bind_address' and "
                             "'{0}_bind_addresses' arguments. Use one of "
                             "them.".format(addr_kind))
        if bind_address:
            return [bind_address]
        else:
            return bind_addresses

    @staticmethod
    def _get_ssh_address_or_host(ssh_address_or_host, arg_name, kwargs):
        """
        Processes optional deprecate arguments to set up ssh_address_or_host
        """
        if arg_name in kwargs:
            warnings.warn("'{0}' is DEPRECATED use 'ssh_address_or_host' or "
                          "1st positional argument".format(arg_name),
                          DeprecationWarning)
            if ssh_address_or_host:
                raise ValueError("You can't use both '{0}' and "
                                 "'ssh_address_or_host'. Please only use one "
                                 "of them".format(arg_name))
            else:
                return kwargs.pop(arg_name)
        return ssh_address_or_host

    def start(self):
        if self._is_started:
            self.logger.warning("Already started!")
            return
        try:
            self._server_list = []  # reset server list
            self.create_tunnels()
            self._connect_to_gateway()
        except paramiko.ssh_exception.AuthenticationException:
            self.logger.error('Could not open connection to gateway')
            self._stop_transport()
            return

        threads = [
            threading.Thread(
                target=self.serve_forever_wrapper, args=(_srv,),
                name="Srv-" + address_to_str(_srv.local_address)
            )
            for _srv in self._server_list
        ]

        for thread in threads:
            thread.daemon = DAEMON
            thread.start()

        self._threads = threads
        if self.is_use_local_check_up:
            self.check_local_side_of_tunnels()
        self._is_started = True

    def _connect_to_gateway(self):
        """
        Open connection to SSH gateway
         - First try with all keys loaded from an SSH agent (if allowed)
         - Then with those passed directly or read from ~/.ssh/config
         - As last resort, try with a provided password
        """
        for key in self.ssh_private_keys:
            self.logger.debug('Trying to log in with key: {0}'
                              .format(hexlify(key.get_fingerprint())))
            try:
                self._transport.connect(hostkey=self.ssh_host_key,
                                        username=self.ssh_username,
                                        pkey=key)
                return
            except paramiko.AuthenticationException:
                self.logger.error('Could not open connection to gateway')
                self._stop_transport()

        if self.ssh_password:  # avoid conflict using both pass and pkey
            self.logger.debug('Logging in with password {0}'
                              .format('*' * len(self.ssh_password)))
            self._transport.connect(hostkey=self.ssh_host_key,
                                    username=self.ssh_username,
                                    password=self.ssh_password)
        else:
            raise paramiko.AuthenticationException(
                'No authentication methods available'
            )

    def check_local_side_of_tunnels(self):
        """
        Check the local side of the tunnels, updating self.tunnel_is_up with
        the result of running self.local_is_up()
        """
        for _srv in self._server_list:
            self.tunnel_is_up[_srv.local_address] = \
                self.local_is_up(_srv.local_address)

        if not any(self.tunnel_is_up.values()):
            self.logger.error("An error occurred while opening tunnels.")

    def serve_forever_wrapper(self, _srv, poll_interval=0.1):
        """
        Wrapper for the server created for a SSH forward
        Tunnels will be marked as up/down in self.tunnel_is_up[bind_port]
        """
        try:
            self.logger.info('Opening tunnel: {0} <> {1}'.format(
                address_to_str(_srv.local_address),
                address_to_str(_srv.remote_address))
            )
            _srv.serve_forever(poll_interval)
        except socket.error as e:
            self.logger.error("Tunnel: {0} <> {1} socket error: {2}".format(
                address_to_str(_srv.local_address),
                address_to_str(_srv.remote_address),
                e)
            )
        except Exception as e:
            self.logger.error("Tunnel: {0} <> {1} error: {2}".format(
                address_to_str(_srv.local_address),
                address_to_str(_srv.remote_address),
                e)
            )
        finally:
            self.logger.info('Tunnel: {0} <> {1} is closed'.format(
                address_to_str(_srv.local_address),
                address_to_str(_srv.remote_address))
            )

    def stop(self):
        """ Shuts the tunnel down. This has to be handled with care:
        - if a port redirection is opened
        - the destination is not reachable
        - we attempt a connection to that tunnel (SYN is sent and acknowledged,
        then a FIN packet is sent and never acknowledged... weird)
        - we try to shutdown: it will not succeed until FIN_WAIT_2 and
        CLOSE_WAIT time out.

        => Handle these scenarios with 'tunnel_is_up', if true _srv.shutdown()
           will be skipped.

        self.tunnel_is_up:  Defines whether or not the other side of the tunnel
                            was reported to be up (and we must close it) or not
                            not (skip `shutdown()` for that tunnel).
                            Example:
                            {('127.0.0.1', 55550): True,
                             ('127.0.0.1', 55551): False}
                            where 55550 and 55551 are the local bind ports
        """
        try:
            self._check_is_started()
        except BaseSSHTunnelForwarderError as e:
            self.logger.warning(e)
            return

        self.logger.info('Closing all open connections...')
        opened_address_text = ', '.join(
            (address_to_str(k.local_address) for k in self._server_list)
        ) or 'None'
        self.logger.debug('Open local addresses: ' + opened_address_text)

        for _srv in self._server_list:
            is_open = _srv.local_address in self.tunnel_is_up if \
                self.is_use_local_check_up else True
            if is_open:
                self.logger.info(
                    'Shutting down tunnel {0}'.format(
                        address_to_str(_srv.local_address)
                    )
                )
                _srv.shutdown()
            _srv.server_close()
        self._stop_transport()
        self._is_started = False

    def _stop_transport(self):
        """Close the underlying transport when nothing more is needed"""
        self._transport.close()
        self._transport.stop_thread()
        self.logger.debug('Transport is closed')

    @property
    def local_bind_port(self):
        # BACKWARD COMPATABILITY
        self._check_is_started()
        if len(self._server_list) != 1:
            raise BaseSSHTunnelForwarderError("Use .local_bind_ports property "
                                              "for more than one tunnel")
        return self.local_bind_ports[0]

    @property
    def local_bind_host(self):
        # BACKWARD COMPATABILITY
        self._check_is_started()
        if len(self._server_list) != 1:
            raise BaseSSHTunnelForwarderError("Use .local_bind_hosts property "
                                              "for more than one tunnel")
        return self.local_bind_hosts[0]

    @property
    def local_bind_address(self):
        # BACKWARD COMPATABILITY
        self._check_is_started()
        if len(self._server_list) != 1:
            raise BaseSSHTunnelForwarderError("Use .local_bind_addresses "
                                              "property for more than one "
                                              "tunnel")
        return self.local_bind_addresses[0]

    @property
    def local_bind_ports(self):
        """
        Returns a list containing the ports of local side of the TCP tunnels
        """
        self._check_is_started()
        return [_server.local_port for _server in self._server_list]

    @property
    def local_bind_hosts(self):
        """
        Returns a list containing the IP addresses listening for the tunnels
        """
        self._check_is_started()
        return [_server.local_host for _server in self._server_list]

    @property
    def local_bind_addresses(self):
        self._check_is_started()
        return [_server.local_address for _server in self._server_list]

    @staticmethod
    def _get_local_interfaces():
        """
        Return all local network interfaces IPs.
        """
        local_if = socket.gethostbyname_ex(socket.gethostname())[-1]
        # In Linux, if /etc/hosts is populated with the hostname it will only
        # return 127.0.0.1
        if '127.0.0.1' not in local_if:
            local_if.append('127.0.0.1')
        return local_if

    def _check_is_started(self):
        if not self._is_started:
            m = 'Server is not started. Please .start() first!'
            raise BaseSSHTunnelForwarderError(m)

    def _is_address_reachable(self, target, timeout=LOCAL_CHECK_TIMEOUT):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            conn.settimeout(timeout)
            conn.connect(target)
            reachable = True
        except socket.error as e:
            self.logger.info('Socket connect({1}:{2}) problem: {0}'
                             .format(e, *target))
            reachable = False
        finally:
            conn.close()
        return reachable

    def __str__(self):
        proxy_str = ('proxy: {0}'.format(self.ssh_proxy.cmd[1]) if
                     self.ssh_proxy else 'no proxy')
        credentials = {
            'password': self.ssh_password,
            'pkeys': [(key.get_name(), hexlify(key.get_fingerprint()))
                      for key in self.ssh_private_keys]
            if self.ssh_private_keys else None
        }
        remove_none_values(credentials)
        template = os.linesep.join(['{0}',
                                    'ssh gateway: {1}:{2}',
                                    '{3}',
                                    'username: {4}',
                                    'authentication: {5}',
                                    'hostkey: {6}',
                                    '{7}started',
                                    'keepalive messages: {8}',
                                    'local tunnel side detection: {9}',
                                    'concurrent connections {10}allowed',
                                    'compression {11}requested',
                                    'logging level: {12}'])
        return (template.format(
            repr(self),
            self.ssh_host, self.ssh_port,
            proxy_str,
            self.ssh_username,
            credentials,
            self.ssh_host_key if self.ssh_host_key else'not checked',
            '' if self._is_started else 'Not ',
            'disabled' if not self.set_keepalive else
            'every {0} sec'.format(self.set_keepalive),
            'enabled' if self.is_use_local_check_up else 'disabled',
            '' if self._threaded else 'not ',
            '' if self.compression else 'not ',
            logging.getLevelName(self.logger.level)
        ))

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def close(self):
        self.stop()


def open_tunnel(*args, **kwargs):
    """
    Open SSH Tunnel

    args:
     (ssh_address, ssh_port)
    kwargs:
     see SSHTunnelForwarder

    ** Example **
    from sshtunnel import open_tunnel
    with open_tunnel(server,
                     ssh_username=SSH_USER,
                     ssh_port=22,
                     ssh_password=SSH_PASSWORD,
                     remote_bind_address=(REMOTE_HOST, REMOTE_PORT)
                     local_bind_address=('', LOCAL_PORT)
                     ) as server:

        def do_something(port):
            pass

        print("LOCAL PORTS:", server.local_bind_port)

        do_something(server.local_bind_port)

    """
    # Remove all "None" input values
    remove_none_values(kwargs)

    # if ssh_config_file is None, skip config file lookup
    if 'ssh_config_file' not in kwargs:  # restore it as None
        kwargs['ssh_config_file'] = None

    # LOGGER - Create a console handler if not passed as argument
    kwargs['logger'] = create_logger(logger=kwargs.get('logger', None),
                                     loglevel=kwargs.pop('debug_level', None))

    # ssh_proxy from CLI comes in (ip, port) format
    if 'ssh_proxy' in kwargs and isinstance(kwargs['ssh_proxy'], tuple):
        proxycmd = 'ssh {0} -W {1}:{2}'.format(':'.join(kwargs['ssh_proxy']),
                                               kwargs['ssh_address'],
                                               kwargs['ssh_port'])
        kwargs['ssh_proxy'] = paramiko.proxy.ProxyCommand(proxycmd)

    ssh_address = kwargs.pop('ssh_address', 'localhost')
    ssh_port = kwargs.pop('ssh_port', None)

    if not args:
        args = ((ssh_address, ssh_port), )
    forwarder = SSHTunnelForwarder(*args, **kwargs)
    return forwarder


def make_ssh_forward_server(remote_address, local_bind_address, ssh_transport,
                            is_threading=False):
    """
    *DEPRECATED* Make SSH forward proxy Server class.
    Not interesting for you.
    """
    warnings.warn("`make_ssh_forward_server` is *DEPRECATED*. Use "
                  "SSHTunnelForwarder.make_ssh_forward_server",
                  DeprecationWarning)
    raise NotImplementedError


def make_ssh_forward_handler(remote_address_, ssh_transport_,
                             base_ssh_forward_handler=None):
    """
    *DEPRECATED* Make SSH Handler class.
    Not interesting for you.
    """
    warnings.warn("`make_ssh_forward_handler` is *DEPRECATED*. Use "
                  "SSHTunnelForwarder.make_ssh_forward_handler_class",
                  DeprecationWarning)
    raise NotImplementedError


def _bindlist(input_str):
    """ Define type of data expected for remote and local bind address lists
        Returns a tuple (ip_address, port) whose elements are (str, int)
    """
    try:
        ip_port = input_str.split(':')
        if len(ip_port) == 1:
            _ip = ip_port[0]
            _port = None
        else:
            (_ip, _port) = ip_port
        if not _ip and not _port:
            raise AssertionError
        elif not _port:
            _port = '22'  # default port if not given
        return _ip, int(_port)
    except ValueError:
        raise argparse.ArgumentTypeError("Address tuple must be of type "
                                         "IP_ADDRESS:PORT")
    except AssertionError:
        raise argparse.ArgumentTypeError("Both IP:PORT can't be missing!")


def _parse_arguments(args=None):
    """
    Parse arguments directly passed from CLI
    """
    parser = argparse.ArgumentParser(
        description='Pure python ssh tunnel utils',
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        'ssh_address', type=str,
        help='SSH server IP address (GW for SSH tunnels)\n'
             'set with "-- ssh_address" if immediately after '
             '-R or -L'
    )

    parser.add_argument(
        '-U', '--username', type=str, dest='ssh_username',
        help='SSH server account username'
    )

    parser.add_argument(
        '-p', '--server_port', type=int, dest='ssh_port',
        help='SSH server TCP port (default: 22)'
    )

    parser.add_argument(
        '-P', '--password', type=str, dest='ssh_password',
        help='SSH server account password'
    )

    parser.add_argument(
        '-R', '--remote_bind_address', type=_bindlist,
        nargs='+', default=[], metavar='IP:PORT',
        required=True,
        dest='remote_bind_addresses',
        help='Remote bind address sequence: '
             'ip_1:port_1 ip_2:port_2 ... ip_n:port_n\n'
             'Equivalent to ssh -Lxxxx:IP_ADDRESS:PORT\n'
             'If omitted, default port is 22.\n'
             'Example: -R 10.10.10.10: 10.10.10.10:5900'
    )

    parser.add_argument(
        '-L', '--local_bind_address', type=_bindlist, nargs='*',
        dest='local_bind_addresses', metavar='IP:PORT',
        help='Local bind address sequence: '
             'ip_1:port_1 ip_2:port_2 ... ip_n:port_n\n'
             'Equivalent to ssh -LPORT:xxxxxxxxx:xxxx, '
             'being the local IP address optional.\n'
             'By default it will listen in all interfaces '
             '(0.0.0.0) and choose a random port.\n'
             'Example: -L :40000'
    )

    parser.add_argument(
        '-k', '--ssh_host_key', type=str,
        help="Gateway's host key"
    )

    parser.add_argument(
        '-K', '--private_key_file', dest='ssh_private_key',
        metavar='RSA_KEY_FILE',
        type=str, help='RSA private key file'
    )

    parser.add_argument(
        '-S', '--private_key_file_password', dest='ssh_private_key_password',
        metavar='RSA_KEY_FILE_PASSWORD',
        type=str, help='RSA private key file password'
    )

    parser.add_argument(
        '-t', '--threaded', action='store_true',
        help='Allow concurrent connections to each tunnel'
    )

    parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='Increase output verbosity (default: {0})'.format(
            logging.getLevelName(DEFAULT_LOGLEVEL)
        )
    )

    parser.add_argument(
        '-V', '--version', action='version',
        version='%(prog)s {version}'.format(version=__version__),
        help='Show version number'
    )

    parser.add_argument(
        '-x', '--proxy', type=_bindlist,
        dest='ssh_proxy', metavar='IP:PORT',
        help='IP and port of SSH proxy to destination'
    )

    parser.add_argument(
        '-c', '--config', type=str,
        default=SSH_CONFIG_FILE, dest='ssh_config_file',
        help='SSH configuration file, defaults to {0}'.format(SSH_CONFIG_FILE)
    )

    parser.add_argument(
        '-z', '--compress', action='store_true', dest='compression',
        help='Request server for compression over SSH transport'
    )

    parser.add_argument(
        '-A', '--agent', action='store_true', dest='allow_agent',
        help='Allow looking for keys from an SSH agent'
    )
    return vars(parser.parse_args(args))


def main(args=None):
    """ Pass input arguments to open_tunnel
        Mandatory: ssh_address, -R (remote bind address list)

        Optional:
        -U (username) we may gather it from SSH_CONFIG_FILE or current username
        -p (server_port), defaults to 22
        -P (password)
        -L (local_bind_address), default to 0.0.0.0:22
        -k (ssh_host_key)
        -K (private_key_file), may be gathered from SSH_CONFIG_FILE
        -S (private_key_file_password)
        -t (threaded), allow concurrent connections over tunnels
        -v (verbose), up to 3 (-vvv) to raise loglevel from ERROR to DEBUG
        -V (version)
        -x (proxy), ProxyCommand's IP:PORT, may be gathered from config file
        -c (ssh_config), ssh configuration file (defaults to SSH_CONFIG_FILE)
        -z (compress)
        -A (allow_agent), allow looking for keys from an Agent
    """
    arguments = _parse_arguments(args)
    verbosity = min(arguments.pop('verbose'), 3)
    levels = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
    arguments.setdefault('debug_level', levels[verbosity])

    with open_tunnel(**arguments) as tunnel:
        if tunnel._is_started:
            input_('''

            Press <Ctrl-C> or <Enter> to stop!

            ''')

if __name__ == '__main__':  # pragma: no cover
    main()
