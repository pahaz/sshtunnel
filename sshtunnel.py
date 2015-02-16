"""*sshtunnel* - Initiate SSH tunnels to remote server.

Useful when you need to connect to local port on remote server throw ssh
tunnel. It works by opening a port forwarding ssh connection in the
background, using threads. The connection(s) are closed when explicitly
calling the `close` method of the returned SSHTunnelForwarder object.

------------------------------------------------------------------------------

                            |
-------------|              |    |----------|               |---------|
    LOCAL    |              |    |  REMOTE  |               | PRIVATE |
    SERVER   | <== SSH ========> |  SERVER  | <== local ==> | SERVER  |
-------------|              |    |----------|               |---------|
                            |
                         FIREWALL

------------------------------------------------------------------------------
Fig1: How to connect to PRIVATE SERVER throw SSH tunnel.

See: `sshtunnel.open` function and `sshtunnel.SSHTunnelForwarder` class.

Ex 1:

    import sshtunnel

    with sshtunnel.open(
            (ssh_host, ssh_port),
            ssh_host_key=None,
            ssh_username=ssh_user,
            ssh_password=ssh_password,
            ssh_private_key=None,
            remote_bind_address=(REMOTE_HOST, REMOTE_PORT)) as server:

        def do_something(port):
            pass

        print "LOCAL PORT:", server.local_bind_port

        do_something(server.local_bind_port)

Ex 2:

    from sshtunnel import SSHTunnelForwarder

    server = SSHTunnelForwarder(
        ssh_address=('pahaz.urfuclub.ru', 22),
        ssh_username="pahaz",
        ssh_password="secret",
        remote_bind_address=('127.0.0.1', 5555))

    server.start()

    print(server.local_bind_port)
    # work with `SECRET SERVICE` throw `server.local_bind_port`.

    server.stop()

"""

import SocketServer
import select
import threading
import logging
import paramiko

__version__ = '0.0.3'
__author__ = 'pahaz'

# NOTE: Not including `open` in __all__ as doing `from sshtunnel import *`
#       would replace the builtin.
__all__ = ('SSHTunnelForwarder', 'BaseSSHTunnelForwarderError',
           'HandlerSSHTunnelForwarderError')


########################
#                      #
#       Errors         #
#                      #
########################


class BaseSSHTunnelForwarderError(Exception):
    pass


class HandlerSSHTunnelForwarderError(BaseSSHTunnelForwarderError):
    pass


########################
#                      #
#       Handlers       #
#                      #
########################


class _BaseHandler(SocketServer.BaseRequestHandler):
    remote_address = None
    ssh_transport = None
    logger = None

    def handle(self):
        assert isinstance(self.remote_address, tuple)

        try:
            chan = self.ssh_transport.open_channel(
                'direct-tcpip',
                self.remote_address,
                self.request.getpeername())
        except Exception as e:
            m = 'Incoming request to {0} failed: {1}'\
                .format(self.remote_address, repr(e))
            self.logger.error(m)
            raise HandlerSSHTunnelForwarderError(m)

        if chan is None:
            m = 'Incoming request to {0} was rejected ' \
                'by the SSH server.'.format(self.remote_address)
            self.logger.error(m)
            raise HandlerSSHTunnelForwarderError(m)

        self.logger.info('Connected!  Tunnel open.')
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)
        chan.close()
        self.request.close()
        self.logger.info('Tunnel closed.')


def make_ssh_forward_handler(remote_address_, ssh_transport_,
                             base_ssh_forward_handler=None):
    """
    Make SSH Handler class.
    Not interesting for you.
    """
    H = base_ssh_forward_handler
    if H is None:
        H = _BaseHandler
    if not issubclass(H, SocketServer.BaseRequestHandler):
        m = "base_ssh_forward_handler is not a subclass " \
            "SocketServer.BaseRequestHandler"
        raise BaseSSHTunnelForwarderError(m)

    logger_ = logging.getLogger(__name__)

    class Handler(H):
        remote_address = remote_address_
        ssh_transport = ssh_transport_
        logger = logger_

    return Handler


class _ForwardServer(SocketServer.TCPServer):  # Not Threading
    allow_reuse_address = True

    @property
    def bind_port(self):
        return self.socket.getsockname()[1]

    @property
    def bind_host(self):
        return self.socket.getsockname()[0]


class _ThreadingForwardServer(SocketServer.ThreadingMixIn, _ForwardServer):
    daemon_threads = False


def make_ssh_forward_server(remote_address, local_bind_address, ssh_transport,
                            is_threading=False):
    """
    Make SSH forward proxy Server class.
    Not interesting for you.
    """
    Handler = make_ssh_forward_handler(remote_address, ssh_transport)
    Server = _ThreadingForwardServer if is_threading else _ForwardServer
    server = Server(local_bind_address, Handler)
    return server


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

    def __init__(self,
                 ssh_address=None,
                 ssh_host_key=None,
                 ssh_username=None,
                 ssh_password=None,
                 ssh_private_key=None,
                 remote_bind_address=None,
                 local_bind_address=None,
                 threaded=False):
        """
        Address is (host, port)

        *local_bind_address* - if is None uses ("127.0.0.1", RANDOM).
        Use `forwarder.local_bind_port` for getting local forwarding port.
        """
        assert isinstance(remote_bind_address, tuple)

        if local_bind_address is None:
            # use random local port
            local_bind_address = ('', 0)

        self._local_bind_address = local_bind_address
        self._remote_bind_address = remote_bind_address
        self._ssh_private_key = ssh_private_key
        self._ssh_password = ssh_password
        self._ssh_username = ssh_username
        self._ssh_host_key = ssh_host_key

        self._transport = paramiko.Transport(ssh_address)
        self._server = make_ssh_forward_server(
            self._remote_bind_address,
            self._local_bind_address,
            self._transport,
            is_threading=threaded
        )
        # self._transport.setDaemon(False) # don`t work =(
        # TODO: fix daemon mod for transport. Main thread don`t close.
        self._is_started = False
        super(SSHTunnelForwarder, self).__init__()

    def start(self):
        # print 'DEMON?', self._transport.isDaemon()
        self._transport.connect(
            hostkey=self._ssh_host_key,
            username=self._ssh_username,
            password=self._ssh_password,
            pkey=self._ssh_private_key)
        super(SSHTunnelForwarder, self).start()
        self._is_started = True

    def run(self):
        self._server.serve_forever()

    def stop(self):
        if not self._is_started:
            m = 'Server don`t started! Please .start() first!'
            raise BaseSSHTunnelForwarderError(m)
        self._server.shutdown()
        self._transport.close()

    @property
    def local_bind_port(self):
        if not self._is_started:
            m = 'Server don`t started! Please .start() first!'
            raise BaseSSHTunnelForwarderError(m)
        return self._server.bind_port

    @property
    def local_bind_host(self):
        if not self._is_started:
            m = 'Server don`t started! Please .start() first!'
            raise BaseSSHTunnelForwarderError(m)
        return self._server.bind_host

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def open(ssh_address=None,
         ssh_host_key=None,
         ssh_username=None,
         ssh_password=None,
         ssh_private_key=None,
         remote_bind_address=None,
         local_bind_address=None,
         threaded=False):
    """
    Opening SSH Tunnel.

    Ex:
        import sshtunnel

        with sshtunnel.open(
                (ssh_host, ssh_port),
                ssh_host_key=None,
                ssh_username=ssh_user,
                ssh_password=ssh_password,
                ssh_private_key=None,
                remote_bind_address=(REMOTE_HOST, REMOTE_PORT)) as server:

            def do_something(port):
                pass

            print "LOCAL PORT:", server.local_bind_port

            do_something(server.local_bind_port)

    """
    f = SSHTunnelForwarder(
        ssh_address,
        ssh_host_key,
        ssh_username,
        ssh_password,
        ssh_private_key,
        remote_bind_address,
        local_bind_address,
        threaded=threaded)
    return f


if __name__ == '__main__':
    pass
    # TODO: this!
