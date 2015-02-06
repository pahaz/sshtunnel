#!/usr/bin/env python2
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
|   SERVER   | <== SSH ========> |  GATEWAY | <== local ==> |  HOST   |
+------------+              |    +----------+               +---------+
                            |
                         FIREWALL

------------------------------------------------------------------------------
Fig1: How to connect to PRIVATE HOST through SSH tunnel.

See: `sshtunnel.open` function and `sshtunnel.SSHTunnelForwarder` class.

Ex 1:

    from sshtunnel import open_tunnel
    with open_tunnel(GATEWAY_IP_ADDRESS,
                     ssh_username=SSH_USER,
                     ssh_port=22,
                     ssh_password=SSH_PASSWORD,
                     remote_bind_address_list=[(PRIVATE_HOST, REMOTE_PORT)]
                     local_bind_address_list=[('', LOCAL_PORT)]
                     ) as server:

        def do_something(port):
            pass

        print "LOCAL PORTS:", server.local_bind_ports

        do_something(server.local_bind_ports)

Ex 2:

    from sshtunnel import SSHTunnelForwarder

    server = SSHTunnelForwarder(
        ssh_address = GATEWAY_IP_ADDRESS,
        ssh_username = "pahaz",
        ssh_password = "secret",
        remote_bind_address_list=[('localhost', 5555)])

    server.start()

    print(server.local_bind_ports)
    # work with `SECRET SERVICE` throw `server.local_bind_ports`.

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

"""


import paramiko
import SocketServer
import threading
import argparse
import socket
import logging
from select import select
from os.path import expanduser

__version_info__ = (0, 0, 3)
__version__ = '.'.join(str(i) for i in __version_info__)
__author__ = 'pahaz'
__author__ = 'cameronmaske'
__author__ = 'fernandezcuesta'

__all__ = ('SSHTunnelForwarder', 'BaseSSHTunnelForwarderError',
           'HandlerSSHTunnelForwarderError', 'open_tunnel')

DEFAULT_LOGLEVEL = 'INFO' # Default level for logging, if no logger passed



########################
#                      #
#       Errors         #
#                      #
########################


class BaseSSHTunnelForwarderError(Exception):
    """ Base exception for Tunnel forwarder errors """
    pass


class HandlerSSHTunnelForwarderError(BaseSSHTunnelForwarderError):
    """ Handler exception for Tunnel forwarder errors"""
    pass


########################
#                      #
#       Handlers       #
#                      #
########################


class _BaseHandler(SocketServer.BaseRequestHandler):
    """ Base handler for tunnel connections """
    remote_address = None
    ssh_transport = None
    logger = None

    def handle(self):
        try:
            assert isinstance(self.remote_address, tuple)
            chan = self.ssh_transport.open_channel('direct-tcpip',
                                                   self.remote_address,
                                                   self.request.getpeername())
        except AssertionError:
            msg = 'Remote address MUST be a tuple (ip:port): %s'.\
                  format(self.remote_address)
            self.logger.error(msg)
            raise HandlerSSHTunnelForwarderError(msg)
        except Exception as _exc:
            msg = 'Incoming request to {0} failed: {1}'.format(\
                  self.remote_address, repr(_exc))
            self.logger.error(msg)
            raise HandlerSSHTunnelForwarderError(msg)
        
        if chan is None:
            msg = 'Incoming request to {0} was rejected ' \
                  'by the SSH server.'.format(self.remote_address)
            self.logger.error(msg)
            raise HandlerSSHTunnelForwarderError(msg)

        self.logger.debug('Incoming connection')

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
            self.logger.warning('Sending RST >>>')
        except Exception as ex: #any other exception
            self.logger.error(repr(ex))
        finally:
            chan.close()
            self.request.close()
            self.logger.debug('Connection closed.')





class _ForwardServer(SocketServer.TCPServer):  # Not Threading
    """
    Non-threading version of the forward server
    """
    allow_reuse_address = True   #faster rebinding

    @property
    def bind_port(self):
        """ Return listening TCP port for the forwarder """
        return self.socket.getsockname()[1]

    @property
    def bind_host(self):
        """ Return the listening IP address for the forwarder """
        return self.socket.getsockname()[0]


def check_bind_list(bind_address_list):
    """
    Checks that the format of the bind address list is correct
    """
    assert isinstance(bind_address_list, list)

    for address in bind_address_list:
        assert isinstance(address, tuple)
        assert isinstance(address[1], int)
    


class _ThreadingForwardServer(SocketServer.ThreadingMixIn, _ForwardServer):
    """
    Will cleanly stop threads created by ThreadingMixIn when quitting
    """
    daemon_threads = True    


def create_logger(loggername):
    """
    Attaches or creates a new logger and creates console handlers if not present
    """
    logger = logging.getLogger('{0}.SSHTunnelForwarder'.format(loggername))

    if not logger.handlers:  #if no handlers, add a new one (console)
        logger.setLevel(DEFAULT_LOGLEVEL)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(\
            logging.Formatter('%(asctime)s| %(levelname)-7s| %(message)s'))
        logger.addHandler(console_handler)
     
    # Add a console handler for paramiko.transport's logger if not present
    paramiko_logger = logging.getLogger('paramiko.transport')
    if not paramiko_logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(\
            logging.Formatter('%(asctime)s| %(levelname)-7s| %(message)s'))
        paramiko_logger.addHandler(console_handler)
    return logger
        
       
       
class SSHTunnelForwarder(threading.Thread):
    """
    Class for forward remote server port throw SSH tunnel to local port.

     - start()
     - stop()
     - local_bind_port
     - local_bind_host

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
    

    def remote_is_up(self, target):
        """
        Check if remote target_host is reachable on TCP target_port
        target: (target_host, target_port)
        """
        try:
            assert isinstance(target, tuple)
            assert isinstance(target[0], str)
            assert isinstance(target[1], int)
            self.logger.debug('Checking connection to %s:%s...',
                              target[0],
                              target[1])
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect(target)
            reachable = True
            conn.close()
            
        except AssertionError:
            self.logger.info('Target must be a tuple (ip, port), where ip is '
                             'a string (i.e. "192.168.1.1") and port is an '
                             'integer (i.e. 40000).')
            reachable = False
        except socket.error:
            self.logger.warning('Connection to %s:%s not OK',
                                target[0], target[1])
            reachable = False
        
        return reachable

    
    def make_ssh_forward_server(self, remote_address, local_bind_address,
                                ssh_transport, is_threading=False):
        """
        Make SSH forward proxy Server class.
        """
        self.logger.debug('Thread version: %s', is_threading)
        _handler = self.make_ssh_forward_handler(remote_address, ssh_transport)
        _server = _ThreadingForwardServer if is_threading else _ForwardServer
        try:
            return _server(local_bind_address, _handler)
        except IOError:
            self.logger.error("Couldn't open tunnel to %s:%s, local port %s "
                              "might be in use or destination not reachable.",
                              remote_address[0],
                              remote_address[1],
                              local_bind_address[1])
            raise BaseSSHTunnelForwarderError('Port forward error')


    def make_ssh_forward_handler(self, remote_address_, ssh_transport_,
                                 base_ssh_forward_handler=None):
        """
        Make SSH Handler class.
        """
        my_handler = base_ssh_forward_handler
        if my_handler is None:
            my_handler = _BaseHandler
        if not issubclass(my_handler, SocketServer.BaseRequestHandler):
            msg = "base_ssh_forward_handler is not a subclass " \
                "SocketServer.BaseRequestHandler"
            raise BaseSSHTunnelForwarderError(msg)
        
        class Handler(my_handler):
            """ handler class for remote tunnels """
            remote_address = remote_address_
            ssh_transport = ssh_transport_
            logger = self.logger
    
        return Handler


    def serve_forever_wrapper(self, _srv, poll_interval=1):
        """
        Wrapper for the server created for a SSH forward
        """
        try:
            self.logger.debug('Serve forever %s', _srv.server_address)
            if not self.remote_is_up(_srv.server_address):
                self._tunnel_is_up[_srv.server_address[1]] = False
                raise socket.error('Could not open tunnel, %s not reachable',
                                   _srv.server_address)
            
            self._tunnel_is_up[_srv.server_address[1]] = True
            _srv.serve_forever(poll_interval)
        except socket.error as ex:
            self.logger.error(repr(ex))
        except Exception as ex: #any other exception
            self.logger.error(repr(ex))



    def __init__(self, ssh_address=None, **ssh_arguments):

        """
        ssh_arguments:
          ssh_host_key=None
          ssh_username=None
          ssh_password=None
          ssh_private_key_file=None
          ssh_port=22
          ssh_config_file=~/.ssh/config
          remote_bind_address_list=None
          local_bind_address_list=None
          threaded=False
          logger=__name__
          
        *local_bind_address* - if None uses ("127.0.0.1", RANDOM).
        Use `forwarder.local_bind_ports` for getting local forwarding ports.
        """
        self._server_list = []
        
        ### LOGGER - Create a console handler if not passed as argument
        self.logger = create_logger(ssh_arguments.pop('logger', __name__))

        # Try to read ~/.ssh/config
        ssh_config = paramiko.SSHConfig()
        try:
            # open the ssh config file
            ssh_config.parse(open(expanduser(ssh_arguments.get('ssh_configfile',
                                                               '~/.ssh/config')
                                            ), 'r'))
            # looks for information for the destination system
            hostname_info = ssh_config.lookup(ssh_address)
            # gather settings for user, port and identity file
            ssh_username = hostname_info.get('user', '')
            identityfile = hostname_info.get('identityfile', None)[0]
            tcp_port = hostname_info.get('port', 22)
        except IOError:
            self.logger.warning('Could not read SSH configuration file: %s',
                                format(ssh_arguments.get('ssh_configfile',
                                                         '~/.ssh/config')))


    
        # if a TCP port was specified, override configuration (if found)
        tcp_port = ssh_arguments.get('ssh_port', locals().get('tcp_port', 22))
        
        assert isinstance(tcp_port, int)



        ### BIND ADDRESS LISTS
        self._remote_bind_address_list = ssh_arguments.get(\
                                         'remote_bind_address_list', [])
        local_bind_address_list = ssh_arguments.get('local_bind_address_list',
                                                    [])      
 
        check_bind_list(self._remote_bind_address_list)
        check_bind_list(local_bind_address_list)

        # Listen in all interfaces on a random port if not set
        self._local_bind_address_list = \
            [('', 0) if local_bind_address_list[loc[0]] is None
             else local_bind_address_list[loc[0]] for loc in
             enumerate(self._remote_bind_address_list)]
      
         
        ### AUTHENTICATION
         # if a username was specified, override configuration file's (if any)
        self._ssh_username = ssh_arguments.get('ssh_username',
                                               locals().get('ssh_username', ''))

        # if a key file was specified, override configuration (if found)
        identityfile = ssh_arguments.get('ssh_private_key_file',
                                         locals().get('identityfile', None))

        
        self._ssh_password = ssh_arguments.get('ssh_password', None)

        if not self._ssh_password:
            self._ssh_private_key = \
                paramiko.RSAKey.from_private_key_file(identityfile) \
                if identityfile else None
                
            # Check if a private key was supplied or found in ssh_config
            if not self._ssh_private_key:
                self.logger.error('No authentication method was supplied: '
                                  'ssh_password, ssh_private_key_file.')
                raise AssertionError('No password or private key supplied')
        
        
        ## OTHER
        
        self._threaded = ssh_arguments.get('threaded', False)
        self._ssh_host_key = ssh_arguments.get('ssh_host_key', None)
        self.logger.info('Connecting to gateway: %s:%s as user "%s".',
                         ssh_address, tcp_port, self._ssh_username)


        ## CREATE THE TUNNELS
        try:
            self._transport = paramiko.Transport((ssh_address, tcp_port))
            self._server_list = \
            [self.make_ssh_forward_server(x, self._local_bind_address_list[i], \
             self._transport, is_threading=self._threaded)
             for i, x in enumerate(self._remote_bind_address_list)
             if self.remote_is_up(x)]

        except socket.gaierror: #raised by paramiko.Transport
            self.logger.error('Could not resolve IP address for %s, aborting!',
                              ssh_address)
            raise BaseSSHTunnelForwarderError
        except BaseSSHTunnelForwarderError:  #remove this?
            self.logger.error('Could not initialize tunnels')
#            raise BaseSSHTunnelForwarderError
            

        self._is_started = True if self._server_list and all(self._server_list)\
                           else False
        self._tunnel_is_up = {} # handle status of the other side of the tunnel
        
        super(SSHTunnelForwarder, self).__init__()




    def start(self):
        try:
            if self._ssh_password: #avoid conflict using both pass and pkey
                self.logger.debug('Logging in with password %s',
                                  self._ssh_password)
                self._transport.connect(hostkey=self._ssh_host_key,
                                        username=self._ssh_username,
                                        password=self._ssh_password)
            else:
                self.logger.debug('Logging in with RSA key')
                self._transport.connect(hostkey=self._ssh_host_key,
                                        username=self._ssh_username,
                                        pkey=self._ssh_private_key)        
           
            super(SSHTunnelForwarder, self).start()

        except paramiko.ssh_exception.AuthenticationException:
            self.logger.error('Could not open connection to gateway')
#            self.stop()

   
    def run(self):
        for k, _srv in enumerate(self._server_list):
            self.logger.info('Opening tunnel: %s:%s:%s',
                             _srv.server_address[-1],
                             *self._remote_bind_address_list[k])
        self.logger.debug('Server is %sstarted.',
                          '' if self._is_started else 'not ')
        if not self._is_started:
            self.logger.error("An error occurred while opening tunnels.")
        else:
            threads = [threading.Thread(target=self.serve_forever_wrapper,
                                        args=(_srv,)
                                       ) for _srv in self._server_list]
            for thread in threads:
                thread.daemon = True
                thread.start()
    

    def stop(self):
        """ Shuts the tunnel down. This has to be handled with care:
        - if a port redirection is opened
        - the destination is not reachable
        - we attempt a connection to that tunnel (SYN is sent and acknowledged,
        then a FIN packet is sent and never acknowledged... weird)
        - we try to shutdown: it will not succeed until FIN_WAIT_2 and
        CLOSE_WAIT time out.        
        
        => Handle these scenarios with '_tunnel_is_up', if true _srv.shutdown()
           will be skipped.
        
        self._tunnel_is_up :      defines whether or not the other side of the
                                  tunnel was reported to be up (and we must
                                  close it) or not (skip shutdown() for that
                                  tunnel).
                                  Example:
                                  {55550: True, 55551: False}
                                  where 55550 and 55551 are the local bind ports
        """
        self.logger.info('Closing all open connections...')
        if not self._is_started:
            self.logger.debug('Server was already stopped!')
            return
        
        self.logger.debug('Local ports open: %s', self._tunnel_is_up)
        for _srv in self._server_list:
            try:
                tunn_port = _srv.server_address[1]
                if self._tunnel_is_up[tunn_port]:
                    self.logger.info('Shutting down tunnel on port %s',
                                     tunn_port)
                    _srv.shutdown()
                else:
                    self.logger.warning('Tunnel already went down at port %s',
                                        tunn_port)
            except KeyError:
                pass
            _srv.server_close()
            
        self._transport.close()
        self._transport.stop_thread()
        self.logger.debug('Transport is now closed')
        self._is_started = False

    @property
    def local_bind_ports(self):
        """
        Returns a list containing the ports of local side of the TCP tunnels
        """
        if not self._is_started:
            return []
        return [_server.server_address[1] for _server in self._server_list]

    @property
    def local_bind_hosts(self):
        """
        Returns a list containing the IP addresses listening for the tunnels
        """
        if not self._is_started:
            return []
        return [_server.server_address[0] for _server in self._server_list]

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def open_tunnel(**kwargs):
    """
    Opening SSH Tunnel.

    kwargs:
     server, 
     ssh_username=None,
     ssh_host_key=None,
     ssh_password=None,
     ssh_private_key_file=None,
     ssh_port=22,
     ssh_config_file=~/.ssh/config,
     remote_bind_address_list=None,
     local_bind_address_list=None,
     threaded=False,
     logger=None
          
    ** Example **
    from sshtunnel import open_tunnel
    with open_tunnel(server,
                     ssh_username=SSH_USER,
                     ssh_port=22,
                     ssh_password=SSH_PASSWORD,
                     remote_bind_address_list=[(REMOTE_HOST, REMOTE_PORT)]
                     local_bind_address_list=[('', LOCAL_PORT)]
                     ) as server:

        def do_something(port):
            pass

        print "LOCAL PORTS:", server.local_bind_ports

        do_something(server.local_bind_ports)

    """
    
    lbal = kwargs.get('local_bind_address_list', [])
    rball = len(kwargs.get('remote_bind_address_list', []))


    if not lbal:
        lbal = []
    elif len(lbal) != len(set(lbal)): # get rid of repeated values
        lbal = list(set(lbal))

    lball = len(lbal)
    
    if rball > lball: # set a random port for missing local bindings
        kwargs.update({'local_bind_address_list': \
                       lbal + [('', 0)] * (rball - lball)})
    
    ssh_address = kwargs.pop('server')
    
    # Remove all "None" input values
    map(kwargs.pop, [item for item in kwargs if not kwargs[item]])

    forwarder = SSHTunnelForwarder(ssh_address, **kwargs)
    return forwarder



def bindlist(input_str):
    """ Define type of data expected for remote and local bind address lists
        Returns a tuple (ip_address, port) whose elements are (str, int)
    """
    try:
        _ip, _port = input_str.split(':')
        if not _ip and not _port:
            raise AssertionError
        elif not _port:
            _port = '22'  #default port if not given
        return _ip, int(_port)
    except ValueError:
        raise argparse.ArgumentTypeError("Bind tuple must be IP_ADDRESS:PORT")
    except AssertionError:
        raise argparse.ArgumentTypeError("Both IP:PORT can't be missing!")



if __name__ == '__main__':

    PARSER = \
    argparse.ArgumentParser(description='sshtunnel',
                            formatter_class=argparse.RawTextHelpFormatter)
    PARSER.add_argument('server', type=str,
                        help='SSH server IP address (GW for ssh tunnels)')
   
    PARSER.add_argument('-U', '--username', type=str, dest='ssh_username',
                        help='SSH server account username')

    PARSER.add_argument('-p', '--server_port', type=int, dest='ssh_port',
                        help='SSH server TCP port (default: 22)')
 
    PARSER.add_argument('-P', '--password', type=str, dest='ssh_password',
                        help='SSH server account password')
 
    PARSER.add_argument('-R', '--remote_bind_address', type=bindlist,
                        nargs='+', default=[], metavar='IP:PORT',
                        dest='remote_bind_address_list',
                        help='Remote bind address sequence: '
                             'ip_1:port_1 ip_2:port_2 ... ip_n:port_n\n'
                             'Equivalent to ssh -Lxxxx:IP_ADDRESS:PORT\n'
                             'If omitted, default port is 22.\n'
                             'Example: -R 10.10.10.10: 10.10.10.10:5900')
 
    PARSER.add_argument('-L', '--local_bind_address', type=bindlist, nargs='*',
                        dest='local_bind_address_list', metavar='IP:PORT',
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
                        help='Use ThreadMixIn instead of TCPserver') 

    ARGS = PARSER.parse_args()
 
    with open_tunnel(**vars(ARGS)) as my_tunnel:
        my_tunnel.logger.info('Press Enter to stop')
        raw_input('')
