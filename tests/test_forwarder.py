from __future__ import with_statement

import argparse
import getpass
import logging
import os
import random
import re
import select
import shutil
import socket
import sys
import threading
import warnings
from contextlib import contextmanager
from functools import partial
from os import linesep, path

try:
    from unittest import mock
    from unittest.mock import patch
except ImportError:
    from mock import mock, patch

import paramiko
import pytest

import sshtunnel

if sys.version_info[0] == 2:
    from cStringIO import StringIO
else:
    from io import StringIO


sshtunnel.TUNNEL_TIMEOUT = 1


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


def get_test_data_path(x):
    return str(path.join(path.abspath(path.dirname(__file__)), x))


@contextmanager
def capture_stdout_stderr():
    out, err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = out, err
        yield [out, err]
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        out.seek(0)
        err.seek(0)


# Ensure that ``ssh_config_file is None`` during tests, exceptions are not
# raised and pkey loading from an SSH agent is disabled
open_tunnel = partial(
    sshtunnel.open_tunnel,
    mute_exceptions=False,
    ssh_config_file=None,
    allow_agent=False,
    skip_tunnel_checkup=True,
    host_pkey_directories=[],
)

# CONSTANTS

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
DAEMON_THREADS = False
THREADS_TIMEOUT = 5.0
PKEY_FILE = 'testrsa.key'
ENCRYPTED_PKEY_FILE = 'testrsa_encrypted.key'
TEST_CONFIG_FILE = 'testconfig'
TEST_UNIX_SOCKET = get_test_data_path('test_socket')

sshtunnel.TRACE = True
sshtunnel.SSH_TIMEOUT = 1.0


# TESTS


class MockLoggingHandler(logging.Handler, object):
    """Mock logging handler to check for expected logs.

    Messages are available from an instance's `messages` dict, in order,
    indexed by a lowercase log level string (e.g., 'debug', 'info', etc.).
    """

    def __init__(self, *args, **kwargs):
        self.messages = {
            k: [] for k in [
                'debug', 'info', 'warning', 'error', 'critical', 'trace'
            ]
        }
        logging.Handler.__init__(self, *args, **kwargs)

    def emit(self, record):
        self.messages[record.levelname.lower()].append(record.getMessage())

    def reset(self):
        for k in self.messages:
            self.messages[k] = []


class NullServer(paramiko.ServerInterface):
    def __init__(self, *args, **kwargs):
        # Allow tests to enable/disable specific key types
        self.__allowed_keys = kwargs.pop('allowed_keys', [])
        self.log = kwargs.pop('log', sshtunnel.create_logger(loglevel='DEBUG'))
        super(NullServer, self).__init__(*args, **kwargs)

    def check_channel_forward_agent_request(self, channel):
        self.log.debug(
            'NullServer.check_channel_forward_agent_request() {0}'.format(
                channel
            )
        )
        return False

    def get_allowed_auths(self, username):
        allowed_auths = 'publickey{0}'.format(
            ',password' if username == SSH_USERNAME else ''
        )
        self.log.debug(
            'NullServer >> allowed auths for {0}: {1}'.format(
                username, allowed_auths
            )
        )
        return allowed_auths

    def check_auth_password(self, username, password):
        _ok = username == SSH_USERNAME and password == SSH_PASSWORD
        self.log.debug(
            'NullServer >> password for {0} {1}OK'.format(
                username, '' if _ok else 'NOT-'
            )
        )
        return paramiko.AUTH_SUCCESSFUL if _ok else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        try:
            expected = FINGERPRINTS[key.get_name()]
            _ok = (
                key.get_name() in self.__allowed_keys
                and key.get_fingerprint() == expected
            )
        except KeyError:
            _ok = False
        self.log.debug(
            'NullServer >> pkey authentication for {0} {1}OK'.format(
                username, '' if _ok else 'NOT-'
            )
        )
        return paramiko.AUTH_SUCCESSFUL if _ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        self.log.debug(
            'NullServer.check_channel_request({0}, {1})'.format(kind, chanid)
        )
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        self.log.debug(
            'NullServer.check_channel_exec_request({0}, {1})'.format(
                channel, command
            )
        )
        return True

    def check_port_forward_request(self, address, port):
        self.log.debug(
            'NullServer.check_port_forward_request({0}, {1})'.format(
                address, port
            )
        )
        return True

    def check_global_request(self, kind, msg):
        self.log.debug(
            'NullServer.check_global_request(kind={0})'.format(kind)
        )
        return True

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.log.debug(
            'NullServer.check_channel_direct_tcpip_request'
            '(chanid={0}) {1} -> {2}'.format(chanid, origin, destination)
        )
        return paramiko.OPEN_SUCCEEDED


class TestSSHClient:
    @staticmethod
    def make_socket():
        s = socket.socket()
        s.bind(('localhost', 0))
        s.listen(5)
        addr, port = s.getsockname()
        return s, addr, port

    @pytest.fixture(autouse=True, scope='function')
    def setup_ssh_environment(self, request):
        socket.setdefaulttimeout(sshtunnel.SSH_TIMEOUT)
        self.log = logging.getLogger(sshtunnel.__name__)
        self.log = sshtunnel.create_logger(logger=self.log, loglevel='DEBUG')

        if not any(
            isinstance(h, MockLoggingHandler) for h in self.log.handlers
        ):
            self._sshtunnel_log_handler = MockLoggingHandler(level='DEBUG')
            self.log.addHandler(self._sshtunnel_log_handler)
        else:
            self._sshtunnel_log_handler = next(
                h
                for h in self.log.handlers
                if isinstance(h, MockLoggingHandler)
            )

        self.sshtunnel_log_messages = self._sshtunnel_log_handler.messages
        # set verbose format for logging
        _fmt = '%(asctime)s| %(levelname)-4.3s|%(threadName)10.9s/%(lineno)04d@%(module)-10.9s| %(message)s'  # noqa: E501 line-too-long
        for handler in self.log.handlers:
            handler.setFormatter(logging.Formatter(_fmt))

        self.log.debug('*' * 80)
        self.log.info('setUp for: {0}'.format(request.node.name.upper()))

        self.ssockl, self.saddr, self.sport = self.make_socket()
        self.esockl, self.eaddr, self.eport = self.make_socket()

        self.log.info(
            'Socket for ssh-server: {0}:{1}'.format(self.saddr, self.sport)
        )
        self.log.info(
            'Socket for echo-server: {0}:{1}'.format(self.eaddr, self.eport)
        )

        self.ssh_event = threading.Event()
        self.running_threads = []
        self.threads = {}
        self.is_server_working = False
        self._sshtunnel_log_handler.reset()

        yield

        self.log.info('tearDown for: {0}'.format(request.node.name.upper()))
        self.stop_echo_and_ssh_server()

        for thread_name in list(self.running_threads):
            x = self.threads.get(thread_name)
            if x:
                self.log.info(
                    'thread {0} ({1})'.format(
                        thread_name, 'alive' if x.is_alive() else 'defunct'
                    )
                )
                self.wait_for_thread(x, who='tearDown')
                if not x.is_alive():
                    self.log.info('thread {0} now stopped'.format(thread_name))

        for attr in ['server', 'tc', 'ts', 'socks', 'ssockl', 'esockl']:
            val = getattr(self, attr, None)
            if val and hasattr(val, 'close'):
                self.log.info('tearDown() closing {0}'.format(attr))
                try:
                    val.close()
                except (socket.error, OSError) as e:
                    self.log.debug('Error closing {0}: {1}'.format(attr, e))

    def wait_for_thread(self, thread, timeout=THREADS_TIMEOUT, who=None):
        if thread.is_alive():
            self.log.debug(
                '{0}waiting for {1} to end...'.format(
                    '{0} '.format(who) if who else '', thread.name
                )
            )
            thread.join(timeout)

    def _do_forwarding(self, timeout=sshtunnel.SSH_TIMEOUT):
        schan = None
        echo = None
        info = 'forward-server schan <> echo'

        self.log.debug('forward-server Start')
        # wait for SSH server's transport
        self.ssh_event.wait(THREADS_TIMEOUT)

        try:
            schan = self.ts.accept(timeout=timeout)
            if schan is None:
                self.log.error(
                    '%s: Failed to accept SSH channel (timeout)', info
                )
                return

            echo = socket.create_connection(
                (self.eaddr, self.eport), timeout=timeout
            )
            self.log.info('%s established', info)

            while self.is_server_working:
                # select.select only accepts objects with .fileno() on win
                try:
                    r_list = [obj for obj in [schan, echo] if obj is not None]
                    if not r_list:
                        break

                    rqst, _, _ = select.select(r_list, [], [], timeout)
                except (ValueError, TypeError) as e:
                    self.log.error('%s: Select error: %s', info, e)
                    break

                if schan in rqst:
                    data = schan.recv(1024)
                    if not data:  # Connection closed
                        break
                    self.log.debug('%s -->: %s', info, repr(data))
                    echo.sendall(data)

                if echo in rqst:
                    data = echo.recv(1024)
                    if not data:  # Connection closed
                        break
                    self.log.debug('%s <--: %s', info, repr(data))
                    schan.sendall(data)

        except (socket.error, Exception) as e:
            self.log.error('%s: Error during forwarding: %r', info, e)

        finally:
            for obj in [schan, echo]:
                if obj:
                    try:
                        obj.close()
                    except paramiko.SSHException:
                        pass
            self.log.debug('%s connections closed.', info)

    def _run_ssh_server(self):
        self.log.info('ssh-server Start')
        try:
            self.socks, addr = self.ssockl.accept()
        except socket.timeout:
            self.log.error('ssh-server connection timed out!')
            self.running_threads.remove('ssh-server')
            return
        self.ts = paramiko.Transport(self.socks)
        host_key = paramiko.RSAKey.from_private_key_file(
            get_test_data_path(PKEY_FILE)
        )
        self.ts.add_server_key(host_key)
        server = NullServer(allowed_keys=FINGERPRINTS.keys(), log=self.log)
        t = threading.Thread(target=self._do_forwarding, name='forward-server')
        t.daemon = DAEMON_THREADS
        self.running_threads.append(t.name)
        self.threads[t.name] = t
        t.start()
        self.ts.start_server(self.ssh_event, server)
        self.wait_for_thread(t, who='ssh-server')
        self.log.info('ssh-server shutting down')
        self.running_threads.remove('ssh-server')

    def start_echo_and_ssh_server(self):
        self.is_server_working = True
        self.start_echo_server()
        t = threading.Thread(target=self._run_ssh_server, name='ssh-server')
        t.daemon = DAEMON_THREADS
        self.running_threads.append(t.name)
        self.threads[t.name] = t
        t.start()

    def stop_echo_and_ssh_server(self):
        self.log.info('Sending STOP signal')
        self.is_server_working = False

    def _check_server_auth(self):
        # Check if authentication to server was successfulZ
        self.ssh_event.wait(sshtunnel.SSH_TIMEOUT)  # wait for transport
        assert self.ssh_event.is_set()
        assert self.ts.is_active()
        assert self.ts.get_username() == SSH_USERNAME
        assert self.ts.is_authenticated()

    @contextmanager
    def _test_server(self, *args, **kwargs):
        self.start_echo_and_ssh_server()
        server = open_tunnel(*args, **kwargs)
        server.start()
        self._check_server_auth()
        yield server
        server._stop_transport()

    def _run_echo_server(self, timeout=sshtunnel.SSH_TIMEOUT):
        self.log.info('echo-server Started')
        self.ssh_event.wait(timeout)  # wait for transport
        socks = [self.esockl]
        try:
            while self.is_server_working:
                inputready, _, _ = select.select(socks, [], [], timeout)
                for s in inputready:
                    if s == self.esockl:
                        # handle the server socket
                        try:
                            client, address = self.esockl.accept()
                            self.log.info(
                                'echo-server accept() {0}'.format(address)
                            )
                        except OSError:
                            self.log.info('echo-server accept() OSError')
                            break
                        socks.append(client)
                    else:
                        # handle all other sockets
                        try:
                            data = s.recv(1000)
                            self.log.info(
                                'echo-server echoing {0}'.format(data)
                            )
                            s.send(data)
                        except OSError:
                            self.log.warning('echo-server OSError')
                            continue
                        finally:
                            s.close()
                            socks.remove(s)
            self.log.info('<<< echo-server received STOP signal')
        except Exception as e:
            self.log.info('echo-server got Exception: {0}'.format(repr(e)))
        finally:
            self.is_server_working = False
            if 'forward-server' in self.threads:
                t = self.threads['forward-server']
                self.wait_for_thread(t, who='echo-server')
                self.running_threads.remove('forward-server')
            for s in socks:
                s.close()
            self.log.info('echo-server shutting down')
            self.running_threads.remove('echo-server')

    def start_echo_server(self):
        t = threading.Thread(target=self._run_echo_server, name='echo-server')
        t.daemon = DAEMON_THREADS
        self.running_threads.append(t.name)
        self.threads[t.name] = t
        t.start()

    @staticmethod
    def randomize_eport():
        return random.randint(49152, 65535)

    def test_echo_server(self):
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ) as server:
            message = get_random_string().encode()
            local_bind_addr = ('127.0.0.1', server.local_bind_port)
            self.log.info('_test_server(): try connect!')
            s = socket.create_connection(local_bind_addr)
            self.log.info(
                '_test_server(): connected from {0}! try send!'.format(
                    s.getsockname()
                )
            )
            s.send(message)
            self.log.info('_test_server(): sent!')
            z = s.recv(1000)
            assert z == message
            s.close()

    def test_connect_by_username_password(self):
        """Test connecting using username/password as authentication"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ):
            pass  # no exceptions are raised

    def test_connect_by_rsa_key_file(self):
        """Test connecting using a RSA key file"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_pkey=get_test_data_path(PKEY_FILE),
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ):
            pass  # no exceptions are raised

    def test_connect_by_paramiko_key(self):
        """Test connecting when ssh_private_key is a paramiko.RSAKey"""
        ssh_key = paramiko.RSAKey.from_private_key_file(
            get_test_data_path(PKEY_FILE)
        )
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_pkey=ssh_key,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ):
            pass

    def test_open_tunnel(self):
        """Test wrapper method mainly used from CLI"""
        server = sshtunnel.open_tunnel(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
            ssh_config_file=None,
            allow_agent=False,
            host_pkey_directories=[],
        )
        assert server.ssh_host == self.saddr
        assert server.ssh_port == self.sport
        assert server.ssh_username == SSH_USERNAME
        assert server.ssh_password == SSH_PASSWORD
        assert server.logger == self.log
        self.start_echo_and_ssh_server()
        server.start()
        self._check_server_auth()
        server.stop()

    def test_open_tunnel_block_on_close_deprecation(self):
        """Ensure block_on_close keyword argument posts deprecation warning."""
        with pytest.warns(
            DeprecationWarning,
            match=re.escape(
                'You should use either .stop() or .stop(force=True)'
            ),
        ):
            sshtunnel.open_tunnel(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                block_on_close=True,
            )

    def test_sshaddress_and_sshaddressorhost_mutually_exclusive(self):
        """
        Test that deprecate argument ssh_address cannot be used together with
        ssh_address_or_host
        """
        with pytest.warns(DeprecationWarning), pytest.raises(ValueError):
            open_tunnel(
                ssh_address_or_host=(self.saddr, self.sport),
                ssh_address=(self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
            )

    def test_sshhost_and_sshaddressorhost_mutually_exclusive(self):
        """
        Test that deprecate argument ssh_host cannot be used together with
        ssh_address_or_host
        """
        with pytest.warns(DeprecationWarning), pytest.raises(ValueError):
            open_tunnel(
                ssh_address_or_host=(self.saddr, self.sport),
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
        server = open_tunnel(
            self.saddr,
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
        )
        assert server.ssh_port == 22

    def test_unknown_argument_raises_exception(self):
        """Test that an exception is raised when setting an invalid argument"""
        with pytest.raises(ValueError):
            open_tunnel(
                self.saddr,
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                i_do_not_exist=0,
            )

    def test_more_local_than_remote_bind_sizes_raises_exception(self):
        """
        Test that when the number of local_bind_addresses exceed number of
        remote_bind_addresses, an exception is raised
        """
        with pytest.raises(ValueError):
            open_tunnel(
                self.saddr,
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                local_bind_addresses=[
                    ('127.0.0.1', self.eport),
                    ('127.0.0.1', self.randomize_eport()),
                ],
            )

    def test_localbindaddress_and_localbindaddresses_mutually_exclusive(self):
        """
        Test that arguments local_bind_address and local_bind_addresses cannot
        be used together
        """
        with pytest.raises(ValueError):
            open_tunnel(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                local_bind_address=('127.0.0.1', self.eport),
                local_bind_addresses=[
                    ('127.0.0.1', self.eport),
                    ('127.0.0.1', self.randomize_eport()),
                ],
            )

    def test_localbindaddress_host_is_optional(self):
        """
        Test that the host part of the local_bind_address tuple may be omitted
        and instead all the local interfaces (0.0.0.0) will be listening
        """
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            local_bind_address=('', self.randomize_eport()),
        ) as server:
            assert server.local_bind_host == '0.0.0.0'

    def test_localbindaddress_port_is_optional(self):
        """
        Test that the port part of the local_bind_address tuple may be omitted
        and instead a random port will be chosen
        """
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            local_bind_address=('127.0.0.1',),
        ) as server:
            assert isinstance(server.local_bind_port, int)

    def test_remotebindaddress_and_remotebindaddresses_are_exclusive(self):
        """
        Test that arguments remote_bind_address and remote_bind_addresses
        cannot be used together
        """
        with pytest.raises(ValueError):
            open_tunnel(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                remote_bind_addresses=[
                    (self.eaddr, self.eport),
                    (self.eaddr, self.randomize_eport()),
                ],
            )

    def test_no_remote_bind_address_raises_exception(self):
        """
        When no remote_bind_address or remote_bind_addresses are specified, a
        ValueError exception should be raised
        """
        with pytest.raises(ValueError):
            open_tunnel(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
            )

    def test_reading_from_a_bad_sshconfigfile_does_not_raise_error(self):
        """
        Test that when a bad ssh_config file is found, a warning is shown
        but no exception is raised
        """
        ssh_config_file = 'not_existing_file'

        open_tunnel(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            local_bind_address=('127.0.0.1', self.randomize_eport()),
            logger=self.log,
            ssh_config_file=ssh_config_file,
        )
        logged_message = 'Could not read SSH configuration file: {0}'.format(
            ssh_config_file
        )
        assert logged_message in self.sshtunnel_log_messages['warning']

    def test_not_setting_password_or_pkey_raises_error(self):
        """
        Test that when a no authentication method is specified, an exception is
        raised
        """
        with pytest.raises(ValueError):
            open_tunnel(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                remote_bind_address=(self.eaddr, self.eport),
                ssh_config_file=None,
            )

    @pytest.mark.parametrize(
        'deprecated_arg',
        [
            'ssh_address',
            'ssh_host',
            'raise_exception_if_any_forwarder_have_a_problem',
            'ssh_private_key',
        ],
    )
    def test_deprecation_warnings_are_shown(self, deprecated_arg):
        """
        Deprecated arguments should log the correct DeprecationWarning.
        """

        replacement = sshtunnel._DEPRECATIONS[deprecated_arg]
        expected_msg = "'{0}' is DEPRECATED use '{1}' instead".format(
            deprecated_arg, replacement
        )

        _kwargs = {
            'ssh_username': SSH_USERNAME,
            'ssh_password': SSH_PASSWORD,
            'remote_bind_address': (self.eaddr, self.eport),
            deprecated_arg: (self.saddr, self.sport),
        }

        if deprecated_arg not in ('ssh_address', 'ssh_host'):
            _kwargs['ssh_address_or_host'] = (self.saddr, self.sport)

        with pytest.warns(DeprecationWarning, match=expected_msg):
            open_tunnel(**_kwargs)

    def test_gateway_unreachable_raises_exception(self):
        """
        BaseSSHTunnelForwarderError is raised when not able to reach the
        ssh gateway
        """
        with pytest.raises(sshtunnel.BaseSSHTunnelForwarderError):
            with open_tunnel(
                (self.saddr, self.randomize_eport()),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                ssh_config_file=None,
            ):
                pass

    def test_gateway_ip_unresolvable_raises_exception(self):
        """
        BaseSSHTunnelForwarderError is raised when not able to resolve the
        ssh gateway IP address
        """
        with pytest.raises(sshtunnel.BaseSSHTunnelForwarderError):
            with open_tunnel(
                (SSH_USERNAME, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD,
                remote_bind_address=(self.eaddr, self.eport),
                ssh_config_file=None,
            ):
                pass
        assert (
            'Could not resolve IP address for {0}, aborting!'.format(
                SSH_USERNAME
            )
            in self.sshtunnel_log_messages['error']
        )

    def test_running_start_twice_logs_warning(self):
        """Test that when running start() twice a warning is shown"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
        ) as server:
            assert (
                'Already started!'
                not in self.sshtunnel_log_messages['warning']
            )
            server.logger.error(server.is_active)
            server.logger.error(server.is_alive)
            server.start()  # 2nd start should prompt the warning
            assert 'Already started!' in self.sshtunnel_log_messages['warning']

    def test_stop_before_start_logs_warning(self):
        """
        Test that running .stop() on an already stopped server logs a warning
        """
        server = open_tunnel(
            '10.10.10.10',
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=('10.0.0.1', 8080),
            mute_exceptions=True,
            logger=self.log,
        )
        server.stop()
        assert (
            'Server is not started. Please .start() first!'
            in self.sshtunnel_log_messages['warning']
        )

    def test_wrong_auth_to_gateway_logs_error(self):
        """
        Test that when connecting to the ssh gateway with wrong credentials,
        an error is logged
        """
        with pytest.raises(sshtunnel.BaseSSHTunnelForwarderError):
            with self._test_server(
                (self.saddr, self.sport),
                ssh_username=SSH_USERNAME,
                ssh_password=SSH_PASSWORD[::-1],
                remote_bind_address=(self.eaddr, self.randomize_eport()),
                logger=self.log,
            ):
                pass
        assert (
            'Could not open connection to gateway'
            in self.sshtunnel_log_messages['error']
        )

    def test_missing_pkey_file_logs_warning(self):
        """
        Test that when the private key file is missing, a warning is logged
        """
        bad_pkey = 'this_file_does_not_exist'
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            ssh_pkey=bad_pkey,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ):
            assert (
                'Private key file not found: {0}'.format(bad_pkey)
                in self.sshtunnel_log_messages['warning']
            )

    def test_connect_via_proxy(self):
        """Test connecting using a ProxyCommand"""
        proxycmd = paramiko.proxy.ProxyCommand(
            'ssh proxy -W {0}:{1}'.format(self.saddr, self.sport)
        )
        server = open_tunnel(
            self.saddr,
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            ssh_proxy=proxycmd,
            ssh_proxy_enabled=True,
            logger=self.log,
        )
        assert server.ssh_proxy.cmd[1] == 'proxy'

    def test_can_skip_loading_sshconfig(self):
        """Test that we can skip loading the ~/.ssh/config file"""
        server = open_tunnel(
            (self.saddr, self.sport),
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            ssh_config_file=None,
            logger=self.log,
        )
        assert server.ssh_username == getpass.getuser()
        assert (
            'Skipping loading of ssh configuration file'
            in self.sshtunnel_log_messages['info']
        )

    def test_local_bind_port(self):
        """Test local_bind_port property"""
        s = socket.socket()
        s.bind(('localhost', 0))
        addr, port = s.getsockname()
        s.close()
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            local_bind_address=(addr, port),
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ) as server:
            assert isinstance(server.local_bind_port, int)
            assert server.local_bind_port == port

    def test_local_bind_host(self):
        """Test local_bind_host property"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            local_bind_address=(self.saddr, 0),
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ) as server:
            assert isinstance(server.local_bind_host, str)
            assert server.local_bind_host == self.saddr

    def test_local_bind_address(self):
        """Test local_bind_address property"""
        s = socket.socket()
        s.bind(('localhost', 0))
        addr, port = s.getsockname()
        s.close()
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            local_bind_address=(addr, port),
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ) as server:
            assert isinstance(server.local_bind_address, tuple)
            assert server.local_bind_address == (addr, port)

    def test_local_bind_ports(self):
        """Test local_bind_ports property"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_addresses=[
                (self.eaddr, self.eport),
                (self.saddr, self.sport),
            ],
            logger=self.log,
        ) as server:
            assert isinstance(server.local_bind_ports, list)
            with pytest.raises(sshtunnel.BaseSSHTunnelForwarderError):
                self.log.info(server.local_bind_port)

        # Single bind should still produce a 1 element list
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ) as server:
            assert isinstance(server.local_bind_ports, list)

    def test_local_bind_hosts(self):
        """Test local_bind_hosts property"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            local_bind_addresses=[(self.saddr, 0)] * 2,
            remote_bind_addresses=[
                (self.eaddr, self.eport),
                (self.saddr, self.sport),
            ],
            logger=self.log,
        ) as server:
            assert isinstance(server.local_bind_hosts, list)
            assert server.local_bind_hosts == ([self.saddr] * 2)
            with pytest.raises(sshtunnel.BaseSSHTunnelForwarderError):
                self.log.info(server.local_bind_host)

    def test_local_bind_addresses(self):
        """Test local_bind_addresses property"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            local_bind_addresses=[(self.saddr, 0)] * 2,
            remote_bind_addresses=[
                (self.eaddr, self.eport),
                (self.saddr, self.sport),
            ],
            logger=self.log,
        ) as server:
            assert isinstance(server.local_bind_addresses, list)
            assert server.local_bind_addresses == list(
                zip([self.saddr] * 2, server.local_bind_ports)
            )
            with pytest.raises(sshtunnel.BaseSSHTunnelForwarderError):
                self.log.info(server.local_bind_address)

    def test_check_tunnels(self):
        """Test method checking if tunnels are up"""
        remote_address = (self.eaddr, self.eport)
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=remote_address,
            logger=self.log,
            skip_tunnel_checkup=False,
        ) as server:
            assert (
                'Tunnel to {0} is UP'.format(remote_address)
                in self.sshtunnel_log_messages['debug']
            )

        server.check_tunnels()
        assert (
            'Tunnel to {0} is DOWN'.format(remote_address)
            in self.sshtunnel_log_messages['debug']
        )
        # Calling local_is_up() should also return the same
        server.skip_tunnel_checkup = True
        server.local_is_up((self.saddr, self.sport))
        assert (
            'Tunnel to {0} is DOWN'.format(remote_address)
            in self.sshtunnel_log_messages['debug']
        )

        assert not server.local_is_up('not a valid address')
        assert (
            'Target must be a tuple (IP, port), where IP '
            'is a string (i.e. "192.168.0.1") and port is '
            'an integer (i.e. 40000). Alternatively '
            'target can be a valid UNIX domain socket.'
            in self.sshtunnel_log_messages['warning']
        )

    @mock.patch('sshtunnel.input_', return_value=linesep)
    def test_cli_main_exits_when_pressing_enter(self, input):
        """Test that _cli_main() function quits when Enter is pressed"""
        self.start_echo_and_ssh_server()
        sshtunnel._cli_main(
            args=[
                self.saddr,
                '-U',
                SSH_USERNAME,
                '-P',
                SSH_PASSWORD,
                '-p',
                str(self.sport),
                '-R',
                '{0}:{1}'.format(self.eaddr, self.eport),
                '-c',
                '',
                '-n',
            ],
            host_pkey_directories=[],
        )
        self.stop_echo_and_ssh_server()

    def test_read_private_key_file(self):
        """Test that an encrypted private key can be opened"""
        encr_pkey = get_test_data_path(ENCRYPTED_PKEY_FILE)
        pkey = sshtunnel.SSHTunnelForwarder.read_private_key_file(
            encr_pkey, pkey_password='sshtunnel', logger=self.log
        )
        _pkey = paramiko.RSAKey.from_private_key_file(
            get_test_data_path(PKEY_FILE)
        )
        assert pkey == _pkey

        # Using a wrong password returns None
        assert (
            sshtunnel.SSHTunnelForwarder.read_private_key_file(
                encr_pkey, pkey_password='bad password', logger=self.log
            )
            is None
        )
        assert (
            'Private key file ({0}) could not be loaded as type '
            '{1} or bad password'.format(encr_pkey, type(_pkey))
            in self.sshtunnel_log_messages['debug']
        )
        # Using no password on an encrypted key returns None
        assert (
            sshtunnel.SSHTunnelForwarder.read_private_key_file(
                encr_pkey, logger=self.log
            )
            is None
        )
        assert (
            'Password is required for key {0}'.format(encr_pkey)
            in self.sshtunnel_log_messages['error']
        )

    def test_unix_domains(self):
        """Test use of UNIX domain sockets in local binds"""

        if os.name != 'posix':
            pytest.skip('UNIX sockets not supported on this platform')

        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            local_bind_address=TEST_UNIX_SOCKET,
            logger=self.log,
        ) as server:
            assert server.local_bind_address == TEST_UNIX_SOCKET

    def test_tracing_logging(self):
        """
        Test that Tracing mode may be enabled for more fine-grained logs
        """
        self.log = sshtunnel.create_logger(logger=self.log, loglevel='TRACE')
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
        ) as server:
            server.logger = sshtunnel.create_logger(
                logger=server.logger, loglevel='TRACE'
            )
            message = get_random_string(100).encode()
            # Windows raises WinError 10049 if trying to connect to 0.0.0.0
            s = socket.create_connection(('127.0.0.1', server.local_bind_port))
            s.send(message)
            s.recv(100)
            s.close()
            log = 'send to {0}'.format((self.eaddr, self.eport))

        assert any(log in msg for msg in self.sshtunnel_log_messages['trace'])
        # set loglevel back to the original value
        self.log = sshtunnel.create_logger(logger=self.log, loglevel='DEBUG')

    def test_tunnel_bindings_contain_active_tunnels(self):
        """
        Test that `tunnel_bindings` property returns only the active tunnels
        """
        remote_ports = [self.randomize_eport(), self.randomize_eport()]
        local_ports = [self.randomize_eport(), self.randomize_eport()]
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_addresses=[
                (self.eaddr, remote_ports[0]),
                (self.eaddr, remote_ports[1]),
            ],
            local_bind_addresses=[
                ('127.0.0.1', local_ports[0]),
                ('127.0.0.1', local_ports[1]),
            ],
            skip_tunnel_checkup=False,
        ) as server:
            assert server.local_bind_ports == local_ports
            assert server.tunnel_bindings[(self.eaddr, remote_ports[0])] == (
                '127.0.0.1',
                local_ports[0],
            )
            assert server.tunnel_bindings[(self.eaddr, remote_ports[1])] == (
                '127.0.0.1',
                local_ports[1],
            )

    def check_make_ssh_forward_server_sets_daemon(self, case):
        self.start_echo_and_ssh_server()
        tunnel = sshtunnel.open_tunnel(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            logger=self.log,
            ssh_config_file=None,
            allow_agent=False,
            host_pkey_directories=[],
        )
        try:
            tunnel.daemon_forward_servers = case
            tunnel.start()
            for server in tunnel._server_list:
                assert server.daemon_threads == case
        finally:
            tunnel.stop()

    def test_make_ssh_forward_server_sets_daemon_true(self):
        """
        Test `make_ssh_forward_server` respects `daemon_forward_servers=True`
        """
        self.check_make_ssh_forward_server_sets_daemon(True)

    def test_make_ssh_forward_server_sets_daemon_false(self):
        """
        Test `make_ssh_forward_server` respects `daemon_forward_servers=False`
        """
        self.check_make_ssh_forward_server_sets_daemon(False)

    def test_get_keys(self, tmpdir):
        """Test loading keys from the paramiko Agent"""
        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            local_bind_address=('', self.randomize_eport()),
            logger=self.log,
        ) as server:
            keys = server.get_keys(logger=self.log)
            assert isinstance(keys, list)
            assert not any(
                'keys loaded from agent' in msg
                for msg in self.sshtunnel_log_messages['info']
            )

        with self._test_server(
            (self.saddr, self.sport),
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=(self.eaddr, self.eport),
            local_bind_address=('', self.randomize_eport()),
            logger=self.log,
        ) as server:
            keys = server.get_keys(logger=self.log, allow_agent=True)
            assert isinstance(keys, list)
            assert any(
                'keys loaded from agent' in msg
                for msg in self.sshtunnel_log_messages['info']
            )

        shutil.copy(get_test_data_path(PKEY_FILE), str(tmpdir.join('id_rsa')))

        keys = sshtunnel.SSHTunnelForwarder.get_keys(
            self.log,
            host_pkey_directories=[str(tmpdir)],
        )
        assert isinstance(keys, list)
        assert any(
            '1 key(s) loaded' in msg
            for msg in self.sshtunnel_log_messages['info']
        )

    def test_get_keys_check_error(self, tmpdir):
        """Test if warning is shown if an OS error occurs while reading keys"""
        tmpdir.join('id_rsa').write('this file exists')

        with patch(
            'sshtunnel.SSHTunnelForwarder.read_private_key_file'
        ) as mock_read:
            mock_read.side_effect = OSError()
            sshtunnel.SSHTunnelForwarder.get_keys(
                logger=self.log, host_pkey_directories=[str(tmpdir)]
            )

        assert any(
            'Private key file' in msg and 'check error' in msg
            for msg in self.sshtunnel_log_messages['warning']
        )


class TestAuxiliary:
    """Set of tests that do not need the mock SSH server or logger"""

    @staticmethod
    def _test_parser(parser):
        assert parser['ssh_address'] == '10.10.10.10'
        assert parser['ssh_username'] == getpass.getuser()
        assert parser['ssh_port'] == 22
        assert parser['ssh_password'] == SSH_PASSWORD
        assert parser['remote_bind_addresses'] == [
            ('10.0.0.1', 8080),
            ('10.0.0.2', 8080),
        ]
        assert parser['local_bind_addresses'] == [('', 8081), ('', 8082)]
        assert parser['ssh_host_key'] == str(SSH_DSS)
        assert parser['ssh_private_key'] == __file__
        assert parser['ssh_private_key_password'] == SSH_PASSWORD
        assert parser['threaded']
        assert parser['verbose'] == 3
        assert parser['ssh_proxy'] == ('10.0.0.2', 22)
        assert parser['ssh_config_file'] == 'ssh_config'
        assert parser['compression']
        assert not parser['allow_agent']

    def test_parse_arguments_short(self):
        """Test CLI argument parsing with short parameter names"""
        args = [
            '10.10.10.10',  # ssh_address
            '-U={0}'.format(getpass.getuser()),  # GW username
            '-p=22',  # GW SSH port
            '-P={0}'.format(SSH_PASSWORD),  # GW password
            '-R',
            '10.0.0.1:8080',
            '10.0.0.2:8080',  # remote bind list
            '-L',
            ':8081',
            ':8082',  # local bind list
            '-k={0}'.format(SSH_DSS),  # hostkey
            '-K={0}'.format(__file__),  # pkey file
            '-S={0}'.format(SSH_PASSWORD),  # pkey password
            '-t',  # concurrent connections (threaded)
            '-vvv',  # triple verbosity
            '-x=10.0.0.2:',  # proxy address
            '-c=ssh_config',  # ssh configuration file
            '-z',  # request compression
            '-n',  # disable SSH agent key lookup
        ]
        parser = sshtunnel._parse_arguments(args)
        self._test_parser(parser)

        with capture_stdout_stderr():  # silence stderr
            # First argument is mandatory
            with pytest.raises(SystemExit):
                parser = sshtunnel._parse_arguments(args[1:])
            # -R argument is mandatory
            with pytest.raises(SystemExit):
                parser = sshtunnel._parse_arguments(args[:4] + args[5:])

    def test_parse_arguments_long(self):
        """Test CLI argument parsing with long parameter names"""
        parser = sshtunnel._parse_arguments(
            [
                '10.10.10.10',  # ssh_address
                '--username={0}'.format(getpass.getuser()),  # GW username
                '--server_port=22',  # GW SSH port
                '--password={0}'.format(SSH_PASSWORD),  # GW password
                '--remote_bind_address',
                '10.0.0.1:8080',
                '10.0.0.2:8080',
                '--local_bind_address',
                ':8081',
                ':8082',  # local bind list
                '--ssh_host_key={0}'.format(SSH_DSS),  # hostkey
                '--private_key_file={0}'.format(__file__),  # pkey file
                '--private_key_password={0}'.format(SSH_PASSWORD),
                '--threaded',  # concurrent connections (threaded)
                '--verbose',
                '--verbose',
                '--verbose',  # triple verbosity
                '--proxy',
                '10.0.0.2:22',  # proxy address
                '--config',
                'ssh_config',  # ssh configuration file
                '--compress',  # request compression
                '--noagent',  # disable SSH agent key lookup
            ]
        )
        self._test_parser(parser)

    def test_bindlist(self):
        """
        Test that _bindlist enforces IP:PORT format for local and remote binds
        """
        assert sshtunnel._bindlist('10.0.0.1:8080') == ('10.0.0.1', 8080)
        # Missing port in tuple is filled with port 22
        assert sshtunnel._bindlist('10.0.0.1:') == ('10.0.0.1', 22)
        assert sshtunnel._bindlist('10.0.0.1') == ('10.0.0.1', 22)
        with pytest.raises(argparse.ArgumentTypeError):
            sshtunnel._bindlist('10022:10.0.0.1:22')
        with pytest.raises(argparse.ArgumentTypeError):
            sshtunnel._bindlist(':')

    def test_raise_fwd_ext(self):
        """Test that we can silence the exceptions on sshtunnel creation"""
        server = open_tunnel(
            '10.10.10.10',
            ssh_username=SSH_USERNAME,
            ssh_password=SSH_PASSWORD,
            remote_bind_address=('10.0.0.1', 8080),
            mute_exceptions=True,
        )
        # This should not raise an exception
        server._raise(sshtunnel.BaseSSHTunnelForwarderError, 'test')

        server._raise_fwd_exc = True  # now exceptions are not silenced
        with pytest.raises(sshtunnel.BaseSSHTunnelForwarderError):
            server._raise(sshtunnel.BaseSSHTunnelForwarderError, 'test')

    def test_show_running_version(self):
        """Test that _cli_main() function quits when Enter is pressed"""
        with capture_stdout_stderr() as (out, err):
            with pytest.raises(SystemExit):
                sshtunnel._cli_main(args=['-V'])
        if sys.version_info < (3, 4):
            version = err.getvalue().split()[-1]
        else:
            version = out.getvalue().split()[-1]
        assert version == sshtunnel.__version__

    def test_remove_none_values(self):
        """Test removing keys from a dict where values are None"""
        test_dict = {'key1': 1, 'key2': None, 'key3': 3, 'key4': 0}
        sshtunnel._remove_none_values(test_dict)
        assert test_dict == {'key1': 1, 'key3': 3, 'key4': 0}

    def test_read_ssh_config(self):
        """Test that we can gather host information from a config file"""
        (
            ssh_hostname,
            ssh_username,
            ssh_private_key,
            ssh_port,
            ssh_proxy,
            compression,
        ) = sshtunnel.SSHTunnelForwarder._read_ssh_config(
            'test',
            get_test_data_path(TEST_CONFIG_FILE),
        )
        assert ssh_hostname == 'test'
        assert ssh_username == 'test'
        assert PKEY_FILE == ssh_private_key
        assert ssh_port == 22  # fallback value
        assert ssh_proxy.cmd[-2:] == ['test:22', 'sshproxy']
        assert compression

        # passed parameters are not overriden by config
        (
            ssh_hostname,
            ssh_username,
            ssh_private_key,
            ssh_port,
            ssh_proxy,
            compression,
        ) = sshtunnel.SSHTunnelForwarder._read_ssh_config(
            'other', get_test_data_path(TEST_CONFIG_FILE), compression=False
        )
        assert ssh_hostname == '10.0.0.1'
        assert ssh_port == 222
        assert not compression

    def test_str(self):
        server = open_tunnel(
            'test',
            ssh_pkey=get_test_data_path(PKEY_FILE),
            remote_bind_address=('10.0.0.1', 8080),
        )
        _str = str(server).split(linesep)
        assert repr(server) == str(server)
        assert 'ssh gateway: test:22' in _str
        assert 'proxy: no' in _str
        assert 'username: {0}'.format(getpass.getuser()) in _str
        assert 'status: not started' in _str

    def test_process_deprecations(self):
        """Test processing deprecated API attributes"""
        kwargs = {
            'ssh_host': '10.0.0.1',
            'ssh_address': '10.0.0.1',
            'ssh_private_key': 'testrsa.key',
            'raise_exception_if_any_forwarder_have_a_problem': True,
        }
        for item in kwargs:
            with pytest.warns(
                DeprecationWarning,
                match="'{0}' is DEPRECATED use '.+' instead".format(item),
            ):
                assert kwargs[
                    item
                ] == sshtunnel.SSHTunnelForwarder._process_deprecated(
                    None, item, kwargs.copy()
                )
        # use both deprecated and not None new attribute should raise exception
        for item in kwargs:
            with warnings.catch_warnings(), pytest.raises(
                ValueError, match="You can't use both '.+' and '.+'"
            ):
                warnings.simplefilter('ignore', category=DeprecationWarning)
                sshtunnel.SSHTunnelForwarder._process_deprecated(
                    'some value', item, kwargs.copy()
                )
        # deprecated attribute not in deprecation list should raise exception
        with warnings.catch_warnings(), pytest.raises(
            ValueError, match='item not included in deprecations list'
        ):
            warnings.simplefilter('ignore', category=DeprecationWarning)
            sshtunnel.SSHTunnelForwarder._process_deprecated(
                'some value', 'item', kwargs.copy()
            )


@pytest.mark.parametrize(
    ('address', 'os_name', 'path_exists', 'expected_error', 'match'),
    [
        (
            -1,
            'posix',
            False,
            ValueError,
            'ADDRESS is not a tuple, string, or character buffer',
        ),
        (
            'not/a/path',
            'posix',
            False,
            ValueError,
            'ADDRESS not a valid socket domain socket',
        ),
        (
            '/tmp/unix.sock',
            'nt',
            True,
            ValueError,
            'Platform does not support UNIX domain sockets',
        ),
        ('/tmp/unix.sock', 'posix', True, None, None),
        (('10.0.0.1', 8080), 'posix', True, None, None),
    ],
)
def test_check_address_combined(
    address, os_name, path_exists, expected_error, match
):
    with patch('os.name', os_name), patch(
        'os.path.exists', return_value=path_exists
    ), patch('os.access', return_value=path_exists):
        if expected_error:
            with pytest.raises(expected_error, match=match):
                sshtunnel.check_address(address)
        else:
            # Should not raise any exception
            sshtunnel.check_address(address)


@pytest.mark.parametrize(
    ('address_list', 'is_remote', 'expected_error', 'match'),
    [
        ([('10.0.0.1', 10000), '/tmp/unix-socket'], False, None, None),
        (
            [('10.0.0.1', 10000), '/tmp/unix-socket'],
            True,
            AssertionError,
            'UNIX domain sockets not allowed',
        ),
        ([('10.0.0.1', 10000), 123], False, AssertionError, None),
    ],
)
def test_check_addresses_combined(
    address_list, is_remote, expected_error, match
):
    with patch('os.name', 'posix'), \
         patch('os.path.exists', return_value=True), \
         patch('os.access', return_value=True):
        if expected_error:
            with pytest.raises(expected_error, match=match):
                sshtunnel.check_addresses(address_list, is_remote=is_remote)
        else:
            sshtunnel.check_addresses(address_list, is_remote=is_remote)
