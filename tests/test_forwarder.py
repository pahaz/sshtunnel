from __future__ import with_statement

import logging
import random
import select
import socket
import threading
import time
import unittest

import paramiko
from os import path

import sshtunnel
from sshtunnel import SSHTunnelForwarder

# UTILS


def get_random_string(length=12):
    """
    >>> r = get_random_string(1)
    >>> r in asciis
    True
    >>> r = get_random_string(2)
    >>> [r[0] in asciis, r[1] in asciis]
    [True, True]
    """
    ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
    ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    digits = '0123456789'
    asciis = ascii_lowercase + ascii_uppercase + digits
    return ''.join([random.choice(asciis) for _ in range(length)])


# TESTS

SSH_USERNAME = get_random_string()
SSH_PASSWORD = get_random_string()
SSH_DSS = b'\x44\x78\xf0\xb9\xa2\x3c\xc5\x18\x20\x09\xff\x75\x5b\xc1\xd2\x6c'
SSH_RSA = b'\x60\x73\x38\x44\xcb\x51\x86\x65\x7f\xde\xda\xa2\x2b\x5a\x57\xd5'
ECDSA = b'\x25\x19\xeb\x55\xe6\xa1\x47\xff\x4f\x38\xd2\x75\x6f\xa5\xd5\x60'
FINGERPRINTS = {
    'ssh-dss': SSH_DSS,
    'ssh-rsa': SSH_RSA,
    'ecdsa-sha2-nistp256': ECDSA,
}

here = path.abspath(path.dirname(__file__))
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())
sshtunnel.TRACE = True


def get_test_data_path(x):
    return path.join(here, x)


class NullServer (paramiko.ServerInterface):
    def __init__(self, *args, **kwargs):
        # Allow tests to enable/disable specific key types
        self.__allowed_keys = kwargs.pop('allowed_keys', [])
        super(NullServer, self).__init__(*args, **kwargs)

    def check_channel_forward_agent_request(self, channel):
        log.debug('NullServer.check_channel_forward_agent_request() {0}'
                  .format(channel))
        return False

    def get_allowed_auths(self, username):
        log.debug('NullServer.get_allowed_auths() {0}'.format(repr(username)))
        if username == SSH_USERNAME:
            return 'publickey,password'
        return 'publickey'

    def check_auth_password(self, username, password):
        log.debug('NullServer.check_auth_password() {0}'
                  .format(repr(username)))
        if username == SSH_USERNAME and password == SSH_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log.debug('NullServer.check_auth_publickey() {0}'
                  .format(repr(username)))
        try:
            expected = FINGERPRINTS[key.get_name()]
        except KeyError:
            return paramiko.AUTH_FAILED
        if (
            key.get_name() in self.__allowed_keys and
            key.get_fingerprint() == expected
        ):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        log.debug('NullServer.check_channel_request()'.format(kind, chanid))
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        log.debug('NullServer.check_channel_exec_request()'
                  .format(channel, command))
        return True

    def check_port_forward_request(self, address, port):
        log.debug('NullServer.check_port_forward_request()'
                  .format(address, port))
        return True

    def check_global_request(self, kind, msg):
        log.debug('NullServer.check_port_forward_request()'.format(kind, msg))
        return True

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        log.debug('NullServer.check_channel_direct_tcpip_request(chanid={0}) '
                  '{1} -> {2}'
                  .format(chanid, origin, destination))
        return paramiko.OPEN_SUCCEEDED


class SSHClientTest(unittest.TestCase):
    def make_socket(self):
        s = socket.socket()
        s.bind(('localhost', 0))
        s.listen(5)
        addr, port = s.getsockname()
        return s, addr, port

    def setUp(self):
        self.ssockl, self.saddr, self.sport = self.make_socket()
        self.esockl, self.eaddr, self.eport = self.make_socket()
        log.info("Sockets for SSH server: {0}:{1}"
                 .format(self.saddr, self.sport))
        log.info("Sockets for ECHO server: {0}:{1}"
                 .format(self.eaddr, self.eport))
        self.event = threading.Event()

    def tearDown(self):
        for attr in "server tc ts socks ssockl esockl".split():
            if hasattr(self, attr):
                log.info('tearDown() {0}'.format(attr))
                getattr(self, attr).close()

    def _run_ssh_server(self, delay=0):
        self.socks, addr = self.ssockl.accept()
        self.ts = paramiko.Transport(self.socks)
        host_key = paramiko.RSAKey.from_private_key_file(
            get_test_data_path('testrsa.key')
        )
        self.ts.add_server_key(host_key)
        server = NullServer(allowed_keys=FINGERPRINTS.keys())
        if delay:
            time.sleep(delay)
        threading.Thread(target=self._do_forwarding).start()
        self.ts.start_server(self.event, server)

    def _run_echo_server(self):
        socks = [self.esockl]
        log.info('ECHO RUN on {0}'.format(self.esockl.getsockname()))
        try:
            while 1:
                inputready, _, _ = select.select(socks, [], [])
                for s in inputready:
                    if s == self.esockl:
                        # handle the server socket
                        try:
                            client, address = self.esockl.accept()
                            log.info('ECHO accept() {0}'.format(address))
                        except OSError:
                            break
                        socks.append(client)
                    else:
                        # handle all other sockets
                        try:
                            data = client.recv(1000)
                            log.info('ECHO recv() {0}'.format(data))
                            if data:
                                client.send(data)
                        except OSError:
                            continue
                        finally:
                            client.close()
                            socks.remove(client)
        except Exception as e:
            log.info('ECHO down {0}'.format(repr(e)))
        finally:
            for s in socks:
                s.close()

    def _do_forwarding(self, timeout=None):
        schan = self.ts.accept(timeout=timeout)
        info = "FORWARDING schan <> echo"
        log.info(info + " accept()")
        echo = socket.create_connection(
            (self.eaddr, self.eport)
        )
        try:
            while True:
                rqst, _, _ = select.select([schan, echo], [], [])
                if schan in rqst:
                    data = schan.recv(1024)
                    log.debug('{0} -->: {1}'.format(info, repr(data)))
                    if len(data) == 0:
                        break
                    echo.send(data)
                if echo in rqst:
                    data = echo.recv(1024)
                    log.debug('{0} <--: {1}'.format(info, repr(data)))
                    if len(data) == 0:
                        break
                    schan.send(data)
        except socket.error:
            # Sometimes a RST is sent and a socket error is raised, treat this
            # exception. It was seen that a 3way FIN is processed later on, so
            # no need to make an ordered close of the connection here or raise
            # the exception beyond this point...
            log.warning('{0} sending RST'.format(info))
        except Exception as e:
            log.error('{0} error: {1}'.format(info, repr(e)))
        finally:
            schan.close()
            echo.close()
            log.debug('{0} connection closed.'.format(info))

    def _run_echo_and_ssh(self, server):
        threading.Thread(target=self._run_echo_server).start()
        threading.Thread(target=self._run_ssh_server).start()

        self.server = server
        self.server.is_use_local_check_up = False

        self.server.start()

        # Authentication successful?
        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual(SSH_USERNAME, self.ts.get_username())
        self.assertEqual(True, self.ts.is_authenticated())

    def test_connect_by_username_password(self):
        server = SSHTunnelForwarder(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=log,
        )

        self._test_server(server)

    def test_connect_by_rsa_key(self):
        server = SSHTunnelForwarder(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_private_key=get_test_data_path('testrsa.key'),
            remote_bind_address=(self.eaddr, self.eport),
            logger=log,
        )

        self._test_server(server)

    def _test_server(self, server):
        self._run_echo_and_ssh(server)
        MESSAGE = get_random_string().encode()
        LOCAL_BIND_ADDR = ('127.0.0.1', self.server.local_bind_port)
        log.info('try connect!')
        s = socket.create_connection(LOCAL_BIND_ADDR)
        log.info('connected from {0}! try send!'.format(s.getsockname()))
        s.send(MESSAGE)
        log.info('sent!')
        z = (s.recv(1000))
        self.assertEqual(z, MESSAGE)
        s.close()
