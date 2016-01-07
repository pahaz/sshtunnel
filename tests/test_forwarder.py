from __future__ import with_statement

import logging
import random
import select
import socket
import threading
import time
import unittest
import warnings

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

sshtunnel.TRACE = True


def get_test_data_path(x):
    return path.join(here, x)


class MockLoggingHandler(logging.Handler):
    """Mock logging handler to check for expected logs.

    Messages are available from an instance's `messages` dict, in order,
    indexed by a lowercase log level string (e.g., 'debug', 'info', etc.).
    """

    def __init__(self, *args, **kwargs):
        self.messages = {'debug': [], 'info': [], 'warning': [], 'error': [],
                         'critical': []}
        super(MockLoggingHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        "Store a message from ``record`` in the instance's ``messages`` dict."
        self.acquire()
        try:
            self.messages[record.levelname.lower()].append(record.getMessage())
        finally:
            self.release()

    def reset(self):
        self.acquire()
        try:
            for message_list in self.messages:
                self.messages[message_list] = []
        finally:
            self.release()


class NullServer (paramiko.ServerInterface):
    def __init__(self, *args, **kwargs):
        # Allow tests to enable/disable specific key types
        self.__allowed_keys = kwargs.pop('allowed_keys', [])
        self.log = kwargs.pop('log', sshtunnel.create_logger(loglevel='DEBUG'))
        super(NullServer, self).__init__(*args, **kwargs)

    def check_channel_forward_agent_request(self, channel):
        self.log.debug('NullServer.check_channel_forward_agent_request() {0}'
                       .format(channel))
        return False

    def get_allowed_auths(self, username):
        self.log.debug('NullServer.get_allowed_auths() %s',
                       repr(username))
        if username == SSH_USERNAME:
            return 'publickey,password'
        return 'publickey'

    def check_auth_password(self, username, password):
        self.log.debug('NullServer.check_auth_password() {0}'
                       .format(repr(username)))
        if username == SSH_USERNAME and password == SSH_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.log.debug('NullServer.check_auth_publickey() {0}'
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
        self.log.debug('NullServer.check_channel_request()'
                       .format(kind, chanid))
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        self.log.debug('NullServer.check_channel_exec_request()'
                       .format(channel, command))
        return True

    def check_port_forward_request(self, address, port):
        self.log.debug('NullServer.check_port_forward_request()'
                       .format(address, port))
        return True

    def check_global_request(self, kind, msg):
        self.log.debug('NullServer.check_port_forward_request()'
                       .format(kind, msg))
        return True

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.log.debug('NullServer.check_channel_direct_tcpip_request'
                       '(chanid={0}) {1} -> {2}'
                       .format(chanid, origin, destination))
        return paramiko.OPEN_SUCCEEDED


class SSHClientTest(unittest.TestCase):
    def make_socket(self):
        s = socket.socket()
        s.bind(('localhost', 0))
        s.listen(5)
        addr, port = s.getsockname()
        return s, addr, port

    @classmethod
    def setUpClass(cls):
        super(SSHClientTest, cls).setUpClass()
        cls.log = logging.getLogger(sshtunnel.__name__)
        cls._sshtunnel_log_handler = MockLoggingHandler(level='DEBUG')
        cls.log.addHandler(cls._sshtunnel_log_handler)
        cls.sshtunnel_log_messages = cls._sshtunnel_log_handler.messages

    def setUp(self):
        super(SSHClientTest, self).setUp()
        self.log.info('setUp()')
        self.ssockl, self.saddr, self.sport = self.make_socket()
        self.esockl, self.eaddr, self.eport = self.make_socket()
        self.log.info("Sockets for SSH server: {0}:{1}"
                      .format(self.saddr, self.sport))
        self.log.info("Sockets for ECHO server: {0}:{1}"
                      .format(self.eaddr, self.eport))
        self.event = threading.Event()
        self.threads = []
        self.is_echo_server_working = False
        self._sshtunnel_log_handler.reset()

    def tearDown(self):
        self.log.info('tearDown()')
        self.stop_echo_server()
        for attr in "server tc ts socks ssockl esockl".split():
            if hasattr(self, attr):
                self.log.info('tearDown() {0}'.format(attr))
                getattr(self, attr).close()
        for x in self.threads:
            self.log.info('thread {0} - is_alive={1}'.format(x, x.is_alive()))

    def _run_ssh_server(self, delay=0):
        self.socks, addr = self.ssockl.accept()
        self.ts = paramiko.Transport(self.socks)
        host_key = paramiko.RSAKey.from_private_key_file(
            get_test_data_path('testrsa.key')
        )
        self.ts.add_server_key(host_key)
        server = NullServer(allowed_keys=FINGERPRINTS.keys(), log=self.log)
        if delay:
            time.sleep(delay)
        t = threading.Thread(target=self._do_forwarding, name='ssh-forwarding')
        t.daemon = False
        self.threads.append(t)
        t.start()
        self.ts.start_server(self.event, server)

    def stop_echo_server(self):
        self.is_echo_server_working = False

    def start_echo_server(self):
        t = threading.Thread(target=self._run_echo_server, name='echo-server')
        t.daemon = False
        self.threads.append(t)
        t.start()

    def _run_echo_server(self):
        socks = [self.esockl]
        self.is_echo_server_working = True
        self.log.info('ECHO RUN on {0}'.format(self.esockl.getsockname()))
        try:
            while self.is_echo_server_working:
                inputready, _, _ = select.select(socks, [], [], 10)
                for s in inputready:
                    if s == self.esockl:
                        # handle the server socket
                        try:
                            client, address = self.esockl.accept()
                            self.log.info('ECHO accept() {0}'.format(address))
                        except OSError:
                            self.log.info('ECHO accept() OSError')
                            break
                        socks.append(client)
                    else:
                        # handle all other sockets
                        try:
                            data = s.recv(1000)
                            self.log.info('ECHO recv({0}) send(%s)',
                                          data)
                            s.send(data)
                        except OSError:
                            self.log.warning('ECHO OSError')
                            continue
                        finally:
                            s.close()
                            socks.remove(s)
        except Exception as e:
            self.log.info('ECHO except {0}'.format(repr(e)))
        finally:
            self.is_echo_server_working = False
            for s in socks:
                s.close()
            self.log.info('ECHO down')

    def _do_forwarding(self, timeout=None):
        schan = self.ts.accept(timeout=timeout)
        info = "FORWARDING schan <> echo"
        self.log.info(info + " accept()")
        echo = socket.create_connection(
            (self.eaddr, self.eport)
        )
        try:
            while True:
                rqst, _, _ = select.select([schan, echo], [], [], 10)
                if schan in rqst:
                    data = schan.recv(1024)
                    self.log.debug('{0} -->: {1}'.format(info, repr(data)))
                    echo.send(data)
                    if len(data) == 0:
                        break
                if echo in rqst:
                    data = echo.recv(1024)
                    self.log.debug('{0} <--: {1}'.format(info, repr(data)))
                    schan.send(data)
                    if len(data) == 0:
                        break
        except socket.error:
            # Sometimes a RST is sent and a socket error is raised, treat this
            # exception. It was seen that a 3way FIN is processed later on, so
            # no need to make an ordered close of the connection here or raise
            # the exception beyond this point...
            self.log.warning('{0} sending RST'.format(info))
        except Exception as e:
            self.log.error('{0} error: {1}'.format(info, repr(e)))
        finally:
            if schan:
                schan.close()
            echo.close()
            self.log.debug('{0} connection closed.'.format(info))

    def _run_echo_and_ssh(self, server):
        self.start_echo_server()
        t = threading.Thread(target=self._run_ssh_server, name='ssh-server')
        t.daemon = False
        self.threads.append(t)
        t.start()

        self.server = server
        self.server.is_use_local_check_up = False

        self.server.start()

        # Authentication successful?
        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual(SSH_USERNAME, self.ts.get_username())
        self.assertEqual(True, self.ts.is_authenticated())

    def randomize_eport(self):
        return self.eport + random.randint(1, 999)

    def test_connect_by_username_password(self):
        server = SSHTunnelForwarder(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        )
        self._test_server(server)

    def test_connect_by_rsa_key(self):
        server = SSHTunnelForwarder(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_private_key=get_test_data_path('testrsa.key'),
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        )

        self._test_server(server)

    def _test_server(self, server):
        self._run_echo_and_ssh(server)
        MESSAGE = get_random_string().encode()
        LOCAL_BIND_ADDR = ('127.0.0.1', self.server.local_bind_port)
        self.log.info('_test_server(): try connect!')
        s = socket.create_connection(LOCAL_BIND_ADDR)
        self.log.info('_test_server(): connected from {0}! try send!'
                      .format(s.getsockname()))
        s.send(MESSAGE)
        self.log.info('_test_server(): sent!')
        z = (s.recv(1000))
        self.assertEqual(z, MESSAGE)
        s.close()

    def test_sshaddress_and_sshaddresssorhost_mutually_exclusive(self):
        """
        Test that deprecate argument ssh_address cannot be used together with
        ssh_address_or_host
        """
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                ssh_address_or_host=(self.saddr, self.sport),
                ssh_address=(self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
            )

    def test_sshhost_and_sshaddresssorhost_mutually_exclusive(self):
        """
        Test that deprecate argument ssh_host cannot be used together with
        ssh_address_or_host
        """
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                (self.saddr, self.sport),  # as 1st positional argument
                ssh_host=(self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
            )

    def test_sshaddressorhost_may_not_be_a_tuple(self):
        """
        Test that when ssh_address_or_host contains just the address part
        (and not the port), we'll look at the contents of ssh_port (if any)
        """
        server = SSHTunnelForwarder(
            self.saddr,
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
        )
        self.assertEqual(server._transport.getpeername()[1], 22)

    def test_unknown_argument_raises_exception(self):
        """Test that an exception is raised when setting an invalid argument"""
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                self.saddr,
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                i_do_not_exist=0
            )

    def test_more_local_than_remote_bind_sizes_raise_exception(self):
        """
        Test that when the number of local_bind_addresses exceed number of
        remote_bind_addresses, an exception is raised
        """
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                self.saddr,
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                local_bind_addresses=[('127.0.0.1', self.eport),
                                      ('127.0.0.1', self.randomize_eport())]
             )

    def test_localbindaddress_and_localbindaddresses_mutually_exclusive(self):
        """
        Test that arguments local_bind_address and local_bind_addresses cannot
        be used together
        """
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                local_bind_address=('127.0.0.1', self.eport),
                local_bind_addresses=[('127.0.0.1', self.eport),
                                      ('127.0.0.1', self.randomize_eport())]
            )

    def test_remotebindaddress_and_remotebindaddresses_are_exclusive(self):
        """
        Test that arguments remote_bind_address and remote_bind_addresses
        cannot be used together
        """
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                remote_bind_addresses=[(self.eaddr, self.eport),
                                       (self.eaddr, self.randomize_eport())]
            )

    def test_no_remote_bind_address_raises_exception(self):
        """
        When no remote_bind_address or remote_bind_addresses are specified, a
        ValueError exception should be raised
        """
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                use_ssh_config=False
            )

    def test_reading_from_a_bad_sshconfigfile_does_not_raise_error(self):
        """
        Test that when a bad ssh_config file is found, a warning is shown
        but no exception is raised
        """
        ssh_config_file = 'not_existing_file'

        SSHTunnelForwarder(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            local_bind_address=('127.0.0.1', self.randomize_eport()),
            ssh_config_file=ssh_config_file
        )
        logged_message = 'Could not read SSH configuration file: {}'.format(
                             ssh_config_file
                         )
        self.assertIn(logged_message, self.sshtunnel_log_messages['warning'])

    def test_not_setting_password_or_pkey_raises_error(self):
        """
        Test that when a no authentication method is specified, an exception is
        raised
        """
        with self.assertRaises(ValueError):
            SSHTunnelForwarder(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                remote_bind_address=(self.eaddr, self.eport),
                use_ssh_config=False
            )

    def test_deprecate_warnings_are_shown(self):
        """Test that when using deprecate arguments a warning is logged"""
        warnings.simplefilter("always")  # don't ignore DeprecationWarnings
        with warnings.catch_warnings(record=True) as w:
            for deprecated_arg in ['ssh_address', 'ssh_host']:
                eval(
                    SSHTunnelForwarder.__name__ + '({}={})'.format(
                        deprecated_arg,
                        '(self.saddr, self.sport),'
                        'ssh_username=SSH_USERNAME,'
                        'ssh_password=SSH_PASSWORD,'
                        'remote_bind_address=(self.eaddr, self.eport)'
                    )
                )
                logged_message = "'{}' is DEPRECATED use " \
                                 "'ssh_address_or_host' or 1st positional " \
                                 "argument".format(deprecated_arg)
                self.assertTrue(issubclass(w[-1].category, DeprecationWarning))
                self.assertEqual(logged_message, w[-1].message.message)

            with self.assertRaises(NotImplementedError):
                sshtunnel.make_ssh_forward_server('remote_address',
                                                  'local_bind_address',
                                                  'ssh_transport')
                self.assertTrue(issubclass(w[-1].category, DeprecationWarning))
                self.assertEqual(logged_message, w[-1].message.message)

            with self.assertRaises(NotImplementedError):
                sshtunnel.make_ssh_forward_handler('remote_address',
                                                   'ssh_transport')
                self.assertTrue(issubclass(w[-1].category, DeprecationWarning))
                self.assertEqual(logged_message, w[-1].message.message)

    def test_gateway_unreachable_raises_exception(self):
        """
        BaseSSHTunnelForwarderError is raised when not able to reach the
        ssh gateway
        """
        with self.assertRaises(sshtunnel.BaseSSHTunnelForwarderError):
            SSHTunnelForwarder(
                (self.saddr, self.randomize_eport()),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                use_ssh_config=False
            )

    def test_gateway_ip_unresolvable_raises_exception(self):
        """
        BaseSSHTunnelForwarderError is raised when not able to resolve the
        ssh gateway IP address
        """
        with self.assertRaises(sshtunnel.BaseSSHTunnelForwarderError):
            SSHTunnelForwarder(
                (SSH_USERNAME, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                use_ssh_config=False
            )

    def test_running_start_twice_logs_warning(self):
        """Test that when running start() twice a warning is shown"""
        server = SSHTunnelForwarder(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport)
        )
        self._test_server(server)
        self.assertNotIn('Already started!',
                         self.sshtunnel_log_messages['warning'])
        server.start()  # 2nd start should prompt the warning
        self.assertIn('Already started!',
                      self.sshtunnel_log_messages['warning'])

    def test_wrong_auth_to_gateway_logs_error(self):
        """
        Test that when connecting to the ssh gateway with wrong credentials,
        an error is logged
        """
        with self.assertRaises(AssertionError):
            server = SSHTunnelForwarder(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD[::-1],
                remote_bind_address=(self.eaddr, self.randomize_eport())
            )
            self._test_server(server)
            self.assertIn('Could not open connection to gateway',
                          self.sshtunnel_log_messages['error'])
