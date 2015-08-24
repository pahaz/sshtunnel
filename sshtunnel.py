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

Ex 1:

    from sshtunnel import open_tunnel
    with open_tunnel((ssh_host, ssh_port),
                      ssh_host_key=None,
                      ssh_username=ssh_user,
                      ssh_password=ssh_password,
                      ssh_private_key=None,
                      remote_bind_address=(REMOTE_HOST, REMOTE_PORT)) as server:

        def do_something(port):
            pass

        print("LOCAL PORTS:", server.local_bind_ports)

        do_something(server.local_bind_ports)

Ex 2:

    import sshtunnel

    server = SSHTunnelForwarder(ssh_address=('pahaz.urfuclub.ru', 22),
                                ssh_username="pahaz",
                                ssh_password="secret",
                                remote_bind_address=('127.0.0.1', 5555))
    server.start()

    print(server.local_bind_ports)
    # work with `SECRET SERVICE` through `server.local_bind_ports`.

    server.stop()



CLI usage: sshtunnel [-h] [-U SSH_USERNAME] [-p SSH_PORT] [-P SSH_PASSWORD]
                     [-R REMOTE_BIND_ADDRESS_LIST [REMOTE_BIND_ADDRESS_LIST...]]
                     [-L [LOCAL_BIND_ADDRESS_LIST [LOCAL_BIND_ADDRESS_LIST...]]]
                     [-k SSH_HOST_KEY] [-K SSH_PRIVATE_KEY]
                     server

positional arguments:
  server                SSH server IP address (GW for ssh tunnels)

optional arguments:
  -h, --help            show this help message and exit
  -U, --username SSH_USERNAME
                        SSH server account username
  -p, --server_port SSH_PORT
                        SSH server TCP port (default: 22)
  -P, --password SSH_PASSWORD
                        SSH server account password
  -R, --remote_bind_address [IP:PORT [IP:PORT ...]]
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
  -t, --threaded        Allow concurrent connections to each tunnel

"""

import paramiko
import threading
import argparse
import socket
import logging
import sys
import warnings
from select import select
from os.path import expanduser

if sys.version_info.major < 3:
    string_types = basestring,
else:
    string_types = str,

if sys.version_info.major < 3:
    import SocketServer
else:
    import socketserver as SocketServer

__version__ = '0.0.4.4'
__author__ = 'pahaz'

__all__ = ('SSHTunnelForwarder', 'BaseSSHTunnelForwarderError',
           'HandlerSSHTunnelForwarderError', 'open_tunnel')

DEFAULT_LOGLEVEL = 'DEBUG'  # Default level for logging, if no logger passed
LOCAL_CHECK_TIMEOUT = 1  # Timeout in seconds for local tunnel side detection
_CONNECTION_COUNTER = 1
_lock = threading.Lock()


########################
#                      #
#       Utils          #
#                      #
########################


def check_host(host):
    assert isinstance(host, string_types), "IP is not a string ({0})" \
        .format(type(host).__name__)


def check_port(port):
    assert isinstance(port, int), "PORT is not a number"
    assert port >= 0, "PORT < 0 ({0})".format(port)


def check_address(address):
    """
    Checks that the dormat of the address is correct

    >>> check_address(("127.0.0.1", 22))
    """
    assert isinstance(address, tuple), "ADDRESS is not a tuple ({0})" \
        .format(type(address).__name__)
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


def create_logger(logger=None, loglevel=DEFAULT_LOGLEVEL):
    """
    Attaches or creates a new logger and creates console handlers if not present
    """
    logger = logger or logging.getLogger('{}.SSHTunnelForwarder'. \
                                         format(__name__))

    if not logger.handlers:  # if no handlers, add a new one (console)
        logger.setLevel(loglevel)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter( \
            logging.Formatter('%(asctime)s | %(levelname)-8s| %(message)s'))
        logger.addHandler(console_handler)

    # Add a console handler for paramiko.transport's logger if not present
    paramiko_logger = logging.getLogger('paramiko.transport')
    if not paramiko_logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter( \
            logging.Formatter('%(asctime)s | %(levelname)-8s| PARAMIKO: '
                              '%(lineno)03d@%(module)-10s| %(message)s'))
        paramiko_logger.addHandler(console_handler)
    return logger


def address_to_str(address):
    return "{0[0]}:{0[1]}".format(address)


def get_connection_id():
    global _CONNECTION_COUNTER
    with _lock:
        uid = _CONNECTION_COUNTER
        _CONNECTION_COUNTER += 1
    return uid


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


class _ForwardHandler(SocketServer.BaseRequestHandler):
    """ Base handler for tunnel connections """
    remote_address = None
    ssh_transport = None
    logger = None

    def handle(self):
        uid = get_connection_id()
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
            msg = 'Incoming request #{0} to {1} failed: {2}' \
                .format(uid, self.remote_address, repr(e))
            self.logger.debug(msg)
            raise HandlerSSHTunnelForwarderError(msg)

        if chan is None:
            msg = 'Incoming request #{0} to {1} was rejected ' \
                  'by the SSH server.'.format(uid, self.remote_address)
            self.logger.error(msg)
            raise HandlerSSHTunnelForwarderError(msg)

        self.logger.debug('Incoming request #{0}'.format(uid))
        try:
            while True:
                rqst, _, _ = select([self.request, chan], [], [])
                if self.request in rqst:
                    data = self.request.recv(1024)
                    if len(data) == 0:
                        break
                    chan.send(data)
                if chan in rqst:
                    data = chan.recv(1024)
                    if len(data) == 0:
                        break
                    self.request.send(data)
        except socket.error:
            # Sometimes a RST is sent and a socket error is raised, treat this
            # exception. It was seen that a 3way FIN is processed later on, so
            # no need to make an ordered close of the connection here or raise
            # the exception beyond this point...
            self.logger.warning(
                'Incoming request #{0} sending RST'.format(uid))
        except Exception as e:
            self.logger.error('Incoming request #{0} error: {1}'
                              .format(uid, repr(e)))
        finally:
            chan.close()
            self.request.close()
            self.logger.debug('Incoming request #{0} connection closed.'
                              .format(uid))


class _ForwardServer(SocketServer.TCPServer):  # Not Threading
    """
    Non-threading version of the forward server
    """
    allow_reuse_address = True  # faster rebinding

    # - server_address

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


class _ThreadingForwardServer(SocketServer.ThreadingMixIn, _ForwardServer):
    """
    Allows concurrent connections to each tunnel
    """
    # Will cleanly stop threads created by ThreadingMixIn when quitting
    daemon_threads = True


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
                        ssh_address=('pahaz.urfuclub.ru', 22),
                        ssh_username="pahaz",
                        ssh_password="secret",
                        remote_bind_address=('127.0.0.1', 5555))
        >>> server.start()
        >>> print(server.local_bind_port)
        >>> server.stop()
    """
    daemon_forward_servers = True
    daemon_transport = True

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

        host = target[0]
        port = target[1]
        reachable_from = []
        check_reachable_from = self._local_interfaces \
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
            self.logger.debug('Local side of the tunnel ({0[0]}:{0[1]}) '
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
        if not issubclass(_Handler, SocketServer.BaseRequestHandler):
            msg = "base_ssh_forward_handler is not a subclass " \
                  "SocketServer.BaseRequestHandler"
            raise BaseSSHTunnelForwarderError(msg)

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
            return _Server(local_bind_address, _Handler)
        except IOError:
            self.logger.error("Couldn't open tunnel {0} <> {1} "
                              "might be in use or destination not reachable."
                              .format(address_to_str(local_bind_address),
                                      address_to_str(remote_address)))

    def __init__(
            self,
            ssh_address_or_host=None,
            ssh_port=None,

            ssh_host_key=None,
            ssh_username=None,
            ssh_password=None,
            ssh_private_key=None,
            ssh_proxy=None,
            ssh_proxy_enabled=True,

            remote_bind_address=None,
            local_bind_address=None,
            remote_bind_addresses=None,
            local_bind_addresses=None,

            ssh_config_file="~/.ssh/config",
            logger=None,
            threaded=True,  # old version False
            raise_exception_if_any_forwarder_have_a_problem=True,

            **kwargs  # for backwards compatibility
    ):

        """
        ssh_arguments:
          (ssh_address or ssh_host)
          ssh_host_key=None
          ssh_username=None
          ssh_password=None
          ssh_private_key=None
          remote_bind_address=None
          local_bind_address=None
          remote_bind_addresses=None,
          local_bind_addresses=None,
          threaded=True
          ssh_port=22
          ssh_host=None
          ssh_config_file=~/.ssh/config
          ssh_proxy=None
          ssh_proxy_enabled=True
          logger=__name__

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
        Or use `forwarder.local_bind_port` for getting local forwading port if
        you use only one tunnel.
        """
        self.logger = logger or create_logger()

        # ssh host port
        if 'ssh_address' in kwargs:
            warnings.warn("'ssh_address' is DEPRECATED use "
                          "'ssh_address_or_host' or 1st positional argument")
            if ssh_address_or_host is not None:
                raise ValueError("You can`t use 'ssh_address' and "
                                 "'ssh_address_or_host'. Please use one "
                                 "'ssh_address_or_host'")
            else:
                ssh_address_or_host = kwargs.pop('ssh_address')

        if 'ssh_host' in kwargs:
            warnings.warn("'ssh_host' is DEPRECATED use "
                          "'ssh_address_or_host' or 1st positional argument")
            if ssh_address_or_host is not None:
                raise ValueError("You can`t use 'ssh_host' and "
                                 "'ssh_address_or_host'. Please use one "
                                 "'ssh_address_or_host'")
            else:
                ssh_address_or_host = kwargs.pop('ssh_host')

        if isinstance(ssh_address_or_host, tuple):
            ssh_host, ssh_port = ssh_address_or_host[:]
        else:
            ssh_host = ssh_address_or_host

        # remote binds
        if remote_bind_address is None and remote_bind_addresses is None:
            raise ValueError("No remote bind addresses use "
                             "'remote_bind_address' or 'remote_bind_addresses'"
                             " argument")
        elif remote_bind_address is not None and \
                        remote_bind_addresses is not None:
            raise ValueError("You can`t use the 'remote_bind_address' with "
                             "'remote_bind_addresses' argument. Use one of "
                             "them.")
        if remote_bind_address is not None:
            remote_bind_addresses = [remote_bind_address]

        # local binds
        if local_bind_address is None and local_bind_addresses is None:
            local_bind_addresses = []
        elif local_bind_address is not None and \
                        local_bind_addresses is not None:
            raise ValueError("You can`t use the 'local_bind_address' with "
                             "'local_bind_addresses' argument. Use one of "
                             "them.")
        if local_bind_address is not None:
            local_bind_addresses = [local_bind_address]

        if len(local_bind_addresses) > len(remote_bind_addresses):
            raise ValueError('Many local bind addresses (more then remote)')
        elif len(local_bind_addresses) < len(remote_bind_addresses):
            count = len(remote_bind_addresses) - len(local_bind_addresses)
            for x in range(count):
                local_bind_addresses.append(('0.0.0.0', 0))

        if kwargs:
            raise ValueError('Unknown arguments {0:!r}'.format(kwargs))

        del ssh_address_or_host

        if not ssh_password:
            ssh_private_key = \
                paramiko.RSAKey.from_private_key_file(ssh_private_key) \
                    if ssh_private_key else None

            # Check if a private key was supplied or found in ssh_config
            if not ssh_private_key:
                raise ValueError('No password or private key supplied')

        # Try to read ~/.ssh/config
        ssh_config = paramiko.SSHConfig()
        try:
            # open the ssh config file
            with open(expanduser(ssh_config_file), 'r') as f:
                ssh_config.parse(f)
            # looks for information for the destination system
            hostname_info = ssh_config.lookup(ssh_host)
            # gather settings for user, port and identity file
            ssh_username = ssh_username if ssh_username else \
                hostname_info.get('user')
            ssh_private_key = ssh_private_key if ssh_private_key else \
                hostname_info.get('identityfile', [None])[0]
            ssh_port = ssh_port if ssh_port else \
                hostname_info.get('port')
            ssh_proxy = ssh_proxy if ssh_proxy else \
                paramiko.ProxyCommand(hostname_info.get('proxycommand')) if \
                    hostname_info.get('proxycommand') else None
        except IOError:
            self.logger.warning('Could not read SSH configuration file: {0}'
                                .format(ssh_config_file))
        
        if ssh_port is None:
            ssh_port = 22
        
        check_host(ssh_host)
        check_port(ssh_port)
        check_addresses(remote_bind_addresses)
        check_addresses(local_bind_addresses)

        self._server_list = []

        self._ssh_username = ssh_username
        self._ssh_password = ssh_password
        self._ssh_host_key = ssh_host_key
        self._ssh_private_key = ssh_private_key

        self._threaded = threaded

        self._local_interfaces = self._get_local_interfaces()

        self.logger.info('Connecting to gateway: {0}:{1} as user "{2}".'
                         .format(ssh_host, ssh_port, ssh_username))

        ## CREATE THE TUNNELS
        self.tunnel_is_up = {}  # handle status of the other side of the tunnel
        try:
            if ssh_proxy and ssh_proxy_enabled:
                self.logger.debug('Connecting with ProxyCommand {0}'
                                  .format(repr(ssh_proxy.cmd)))
                self._transport = paramiko.Transport(ssh_proxy)
            else:
                self._transport = paramiko.Transport((ssh_host, ssh_port))
            self._transport.daemon = self.daemon_transport
            for r, l in zip(remote_bind_addresses, local_bind_addresses):
                ssh_forward_server = self.make_ssh_forward_server(r, l)
                if ssh_forward_server:
                    self._server_list.append(ssh_forward_server)
                elif raise_exception_if_any_forwarder_have_a_problem:
                    raise BaseSSHTunnelForwarderError(
                        'Problem with make ssh {0} <> {1} forwarder. You can '
                        'suppres this exception by using the '
                        '`raise_exception_if_any_forwarder_have_a_problem` '
                        'argument'.format(address_to_str(l), address_to_str(l))
                    )

        except paramiko.SSHException:
            msg = 'Could not connect to gateway: {0}'.format(ssh_host)
            self.logger.error(msg)
            raise BaseSSHTunnelForwarderError(msg)
        except socket.gaierror:  # raised by paramiko.Transport
            msg = 'Could not resolve IP address for %s, aborting!' \
                .format(ssh_host)
            self.logger.error(msg)
            raise BaseSSHTunnelForwarderError(msg)
        except BaseSSHTunnelForwarderError as e:
            msg = 'Make SSH Forwarder problem: {0}'.format(repr(e))
            self.logger.error(msg)
            raise BaseSSHTunnelForwarderError(msg)

        self.logger.debug('Concurrent connections allowed: %s', self._threaded)
        self._is_started = False

    def start(self):
        if self._is_started:
            self.logger.warning("Try .start() started!")
            return

        try:
            if self._ssh_password:  # avoid conflict using both pass and pkey
                self.logger.debug('Logging in with password %s',
                                  '*' * len(self._ssh_password))
                self._transport.connect(hostkey=self._ssh_host_key,
                                        username=self._ssh_username,
                                        password=self._ssh_password)
            else:
                self.logger.debug('Logging in with RSA key')
                self._transport.connect(hostkey=self._ssh_host_key,
                                        username=self._ssh_username,
                                        pkey=self._ssh_private_key)

        except paramiko.ssh_exception.AuthenticationException:
            self.logger.error('Could not open connection to gateway')
            return

        threads = [
            threading.Thread(
                target=self.serve_forever_wrapper, args=(_srv,),
                name="Srv-" + address_to_str(_srv.local_address))
            for _srv in self._server_list
            ]

        for thread in threads:
            thread.daemon = self.daemon_forward_servers
            thread.start()

        self._threads = threads
        self._is_started = True

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
        
        self.tunnel_is_up :       defines whether or not the other side of the
                                  tunnel was reported to be up (and we must
                                  close it) or not (skip shutdown() for that
                                  tunnel).
                                  Example:
                                  {('127.0.0.1', 55550): True,
                                   ('127.0.0.1', 55551): False}
                                  where 55550 and 55551 are the local bind ports
        """
        if not self._is_started:
            self.logger.warning('Try .stop() stopped!')
            return

        self.logger.info('Closing all open connections...')
        opened_address_text = ', '.join([address_to_str(k) for k, v
                                         in self.tunnel_is_up.items()
                                         if v]) \
                              or 'None'
        self.logger.debug('Opened local addresses: ' + opened_address_text)

        for _srv in self._server_list:
            is_opened = _srv.local_address in self.tunnel_is_up
            local_address_text = address_to_str(_srv.local_address)
            if is_opened:
                self.logger.info('Shutting down tunnel ' + local_address_text)
                _srv.shutdown()
            _srv.server_close()

        self._transport.close()
        self._transport.stop_thread()
        self.logger.debug('Transport is closed')
        self._is_started = False

    @property
    def local_bind_port(self):
        # BACKWARD COMPATABILITY
        self._check_is_started()
        if len(self._server_list) != 1:
            raise BaseSSHTunnelForwarderError("Use .local_bind_ports property "
                                              "for more then one tunnel")
        return self.local_bind_ports[0]

    @property
    def local_bind_host(self):
        # BACKWARD COMPATABILITY
        self._check_is_started()
        if len(self._server_list) != 1:
            raise BaseSSHTunnelForwarderError("Use .local_bind_hosts property "
                                              "for more then one tunnel")
        return self.local_bind_hosts[0]

    @property
    def local_bind_address(self):
        # BACKWARD COMPATABILITY
        self._check_is_started()
        if len(self._server_list) != 1:
            raise BaseSSHTunnelForwarderError("Use .local_bind_addresses "
                                              "property for more then one "
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
        return socket.gethostbyname_ex(socket.gethostname())[2] + ['127.0.0.1']

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

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def open_tunnel(**kwargs):
    """
    Opening SSH Tunnel.

    kwargs: 
     ssh_address='localhost',
     ssh_host_key=None,
     ssh_username=None,
     ssh_password=None,
     ssh_private_key=None,
     remote_bind_address=None,
     local_bind_address=None,
     threaded=False,
     ssh_port=22,
     ssh_config_file=~/.ssh/config,
     logger=None

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
    list(map(kwargs.pop, [item for item in kwargs if not kwargs[item]]))

    ### LOGGER - Create a console handler if not passed as argument
    loglevel = kwargs['debug_level'] if 'debug_level' in kwargs \
        else DEFAULT_LOGLEVEL

    logger = kwargs.pop('logger') if 'logger' in kwargs else None
    kwargs['logger'] = create_logger(logger=logger, loglevel=loglevel)

    ssh_address = kwargs.pop('ssh_address', 'localhost')
    forwarder = SSHTunnelForwarder(ssh_address, **kwargs)
    return forwarder


def make_ssh_forward_server(remote_address, local_bind_address, ssh_transport,
                            is_threading=False):
    """
    *DEPRECATED* Make SSH forward proxy Server class.
    Not interesting for you.
    """
    warnings.warn("`make_ssh_forward_server` is *DEPRECATED*. Use "
                  "SSHTunnelForwarder.make_ssh_forward_server")
    raise NotImplementedError


def make_ssh_forward_handler(remote_address_, ssh_transport_,
                             base_ssh_forward_handler=None):
    """
    *DEPRECATED* Make SSH Handler class.
    Not interesting for you.
    """
    warnings.warn("`make_ssh_forward_handler` is *DEPRECATED*. Use "
                  "SSHTunnelForwarder.make_ssh_forward_handler_class")
    raise NotImplementedError


def bindlist(input_str):
    """ Define type of data expected for remote and local bind address lists
        Returns a tuple (ip_address, port) whose elements are (str, int)
    """
    try:
        _ip, _port = input_str.split(':')
        if not _ip and not _port:
            raise AssertionError
        elif not _port:
            _port = '22'  # default port if not given
        return _ip, int(_port)
    except ValueError:
        raise argparse.ArgumentTypeError("Bind tuple must be IP_ADDRESS:PORT")
    except AssertionError:
        raise argparse.ArgumentTypeError("Both IP:PORT can't be missing!")


if __name__ == '__main__':
    """ Argparse input options for open_tunnel
        Mandatory: ssh_address, -R (remote bind address list)
        
        -U (username) is optional, we may gather it from ~/.ssh/config
        -L (local bind address list) is optional, default to 0.0.0.0:22
    """
    PARSER = \
        argparse.ArgumentParser(description='sshtunnel',
                                formatter_class=argparse.RawTextHelpFormatter)
    PARSER.add_argument('ssh_address', type=str,
                        help='SSH server IP address (GW for ssh tunnels)')

    PARSER.add_argument('-U', '--username', type=str, dest='ssh_username',
                        help='SSH server account username')

    PARSER.add_argument('-p', '--server_port', type=int, dest='ssh_port',
                        help='SSH server TCP port (default: 22)')

    PARSER.add_argument('-P', '--password', type=str, dest='ssh_password',
                        help='SSH server account password')

    PARSER.add_argument('-R', '--remote_bind_address', type=bindlist,
                        nargs='+', default=[], metavar='IP:PORT',
                        required=True,
                        dest='remote_bind_addresses',
                        help='Remote bind address sequence: '
                             'ip_1:port_1 ip_2:port_2 ... ip_n:port_n\n'
                             'Equivalent to ssh -Lxxxx:IP_ADDRESS:PORT\n'
                             'If omitted, default port is 22.\n'
                             'Example: -R 10.10.10.10: 10.10.10.10:5900')

    PARSER.add_argument('-L', '--local_bind_address', type=bindlist, nargs='*',
                        dest='local_bind_addresses', metavar='IP:PORT',
                        help='Local bind address sequence: '
                             'ip_1:port_1 ip_2:port_2 ... ip_n:port_n\n'
                             'Equivalent to ssh -LPORT:xxxxxxxxx:xxxx, '
                             'being the local IP address optional.\n'
                             'By default it will listen in all interfaces '
                             '(0.0.0.0) and choose a random port.\n'
                             'Example: -L :40000')

    PARSER.add_argument('-k', '--ssh_host_key', type=str,
                        help="Gateway's host key")

    PARSER.add_argument('-K', '--private_key_file', dest='ssh_private_key',
                        metavar='RSA_KEY_FILE',
                        type=str, help='RSA private key file')

    PARSER.add_argument('-t', '--threaded', action='store_true',
                        help='Allow concurrent connections to each tunnel')

    PARSER.add_argument('-d', '--debug_level', const=DEFAULT_LOGLEVEL,
                        choices=['DEBUG',
                                 'INFO',
                                 'WARNING',
                                 'ERROR',
                                 'CRITICAL'],
                        help='Debug level (default: %s)' % \
                             DEFAULT_LOGLEVEL,
                        nargs='?')

    ARGS = PARSER.parse_args()

    with open_tunnel(**vars(ARGS)) as my_tunnel:
        print('''
        
        Press <Ctrl-C> or <Enter> to stop!
        
        ''')
        if sys.version_info.major < 3:
            raw_input('')
        else:
            input('')
