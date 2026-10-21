"""
Integration test: reach a service through a bastion using ``ProxyJump``

Two real ``sshd`` instances are started on the loopback interface: a bastion
(127.0.0.1) and a target gateway (127.0.0.2). The ssh config file reaches the
target only via ``ProxyJump bastion``, and the tunnel is built on top of it.
The test is skipped if ``sshd``, ``ssh`` or ``ssh-keygen`` are not available.
"""
import os
import time
import socket
import getpass
import tempfile
import threading
import subprocess
import unittest
from shutil import rmtree, which

import sshtunnel

SSHD = which('sshd') or next(
    (p for p in ('/usr/sbin/sshd', '/usr/local/sbin/sshd')
     if os.path.exists(p)), None)

SSHD_CONFIG = """\
ListenAddress {address}
Port {port}
HostKey {host_key}
AuthorizedKeysFile {authorized_keys}
PidFile none
UsePAM no
StrictModes no
PasswordAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding yes
LogLevel DEBUG1
"""

SSH_CONFIG = """\
Host bastion
  HostName 127.0.0.1
  Port {bastion_port}
  User {user}
  IdentityFile {key}
Host target
  HostName 127.0.0.2
  Port {target_port}
  User {user}
  IdentityFile {key}
  ProxyJump bastion
Host *
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
"""


def get_free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_for_port(address, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(address, 0.5).close()
            return
        except socket.error:
            time.sleep(0.1)
    raise RuntimeError('{0} is not listening'.format(address))


class EchoServer(threading.Thread):
    """ Accepts connections and sends back what it receives """
    def __init__(self):
        super(EchoServer, self).__init__()
        self.daemon = True
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(5)
        self.address = self.sock.getsockname()

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except socket.error:
                return
            data = conn.recv(1024)
            conn.sendall(data)
            conn.close()


@unittest.skipUnless(SSHD and which('ssh') and which('ssh-keygen'),
                     'sshd, ssh and ssh-keygen are required')
class ProxyJumpIntegrationTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.sshd = []
        cls.echo = EchoServer()
        cls.echo.start()
        try:
            cls._start_servers()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def _keygen(cls, name):
        path = os.path.join(cls.tmp, name)
        subprocess.check_call(['ssh-keygen', '-q', '-t', 'ed25519',
                               '-N', '', '-f', path])
        return path

    @classmethod
    def _start_sshd(cls, name, address, port):
        host_key = cls._keygen(name + '_host_key')
        config = os.path.join(cls.tmp, name + '_sshd_config')
        with open(config, 'w') as f:
            f.write(SSHD_CONFIG.format(address=address, port=port,
                                       host_key=host_key,
                                       authorized_keys=cls.authorized_keys))
        log = open(os.path.join(cls.tmp, name + '.log'), 'w')
        privsep = '/run/sshd'
        if not os.path.isdir(privsep) and os.geteuid() == 0:
            os.makedirs(privsep)
        proc = subprocess.Popen([SSHD, '-D', '-e', '-f', config],
                                stdout=log, stderr=subprocess.STDOUT)
        cls.sshd.append((proc, log))
        wait_for_port((address, port))

    @classmethod
    def _start_servers(cls):
        cls.key = cls._keygen('client_key')
        cls.authorized_keys = os.path.join(cls.tmp, 'authorized_keys')
        with open(cls.key + '.pub') as src:
            with open(cls.authorized_keys, 'w') as dst:
                dst.write(src.read())
        cls.bastion_port = get_free_port()
        cls.target_port = get_free_port()
        cls._start_sshd('bastion', '127.0.0.1', cls.bastion_port)
        cls._start_sshd('target', '127.0.0.2', cls.target_port)
        cls.ssh_config = os.path.join(cls.tmp, 'ssh_config')
        with open(cls.ssh_config, 'w') as f:
            f.write(SSH_CONFIG.format(bastion_port=cls.bastion_port,
                                      target_port=cls.target_port,
                                      user=getpass.getuser(),
                                      key=cls.key))

    @classmethod
    def tearDownClass(cls):
        for proc, log in cls.sshd:
            proc.terminate()
            proc.wait()
            log.close()
        cls.echo.sock.close()
        rmtree(cls.tmp, ignore_errors=True)

    def _read_log(self, name):
        with open(os.path.join(self.tmp, name + '.log')) as f:
            return f.read()

    def test_tunnel_through_bastion(self):
        """ The target gateway is only reachable via the bastion """
        with sshtunnel.open_tunnel(
            'target',
            ssh_config_file=self.ssh_config,
            remote_bind_address=self.echo.address,
            skip_tunnel_checkup=True,
        ) as server:
            self.assertEqual(server.ssh_host, '127.0.0.2')
            self.assertEqual(server.ssh_port, self.target_port)
            self.assertIsNotNone(server.ssh_proxy)
            self.assertTrue(server.is_active)

            sock = socket.create_connection(
                ('127.0.0.1', server.local_bind_port), 5)
            sock.sendall(b'through the bastion')
            self.assertEqual(sock.recv(1024), b'through the bastion')
            sock.close()

        # the bastion opened a forwarding channel to the target sshd...
        self.assertIn('127.0.0.2 port {0}'.format(self.target_port),
                      self._read_log('bastion'))
        # ...and the connection to the echo server came from the target
        self.assertNotIn('port {0}'.format(self.echo.address[1]),
                         self._read_log('bastion'))


if __name__ == '__main__':
    unittest.main()
