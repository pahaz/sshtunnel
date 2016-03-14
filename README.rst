|CircleCI| |AppVeyor| |coveralls| |version|

|DwnMonth| |DwnWeek| |DwnDay|

|pyversions| |license|

**Author**: `Pahaz Blinov`_

**Repo**: https://github.com/pahaz/sshtunnel/

Inspired by https://github.com/jmagnusson/bgtunnel, but it doesn't work on
Windows.

See also: https://github.com/paramiko/paramiko/blob/master/demos/forward.py

Requirements
-------------

* `paramiko`_

Installation
============

`sshtunnel`_ is on PyPI, so simply run:

::

    pip install sshtunnel

or ::

    easy_install sshtunnel

to have it installed in your environment.

For installing from source, clone the
`repo <https://github.com/pahaz/sshtunnel>`_ and run::

    python setup.py install

Testing the package
-------------------

In order to run the tests you first need
`tox <https://testrun.org/tox/latest/>`_ and run::

    python setup.py test

Usage scenarios
===============

One of the typical scenarios where ``sshtunnel`` is helpful is depicted in the
figure below. User may need to connect a port of a remote server (i.e. 8080)
where only SSH port (usually port 22) is reachable. ::

    ----------------------------------------------------------------------

                                |
    -------------+              |    +----------+
        LOCAL    |              |    |  REMOTE  | :22 SSH
        CLIENT   | <== SSH ========> |  SERVER  | :8080 web service
    -------------+              |    +----------+
                                |
                             FIREWALL (only port 22 is open)

    ----------------------------------------------------------------------

**Fig1**: How to connect to a service blocked by a firewall through SSH tunnel.


If allowed by the SSH server, it is also possible to reach a private server
(from the perspective of ``REMOTE SERVER``) not directly visible from the
outside (``LOCAL CLIENT``'s perspective). ::

    ----------------------------------------------------------------------

                                |
    -------------+              |    +----------+               +---------
        LOCAL    |              |    |  REMOTE  |               | PRIVATE
        CLIENT   | <== SSH ========> |  SERVER  | <== local ==> | SERVER
    -------------+              |    +----------+               +---------
                                |
                             FIREWALL

    ----------------------------------------------------------------------

**Fig2**: How to connect to ``PRIVATE SERVER`` through SSH tunnel.


Usage examples
==============

API allows either initializing the tunnel and starting it or using a ``with``
context, which will take care of starting **and stopping** the tunnel:

Example 1
---------

.. code-block:: py

    from sshtunnel import SSHTunnelForwarder

    server = SSHTunnelForwarder(
        ('pahaz.urfuclub.ru', 22),
        ssh_username="pahaz",
        ssh_password="secret",
        remote_bind_address=('127.0.0.1', 5555)
    )

    server.start()

    print(server.local_bind_port)
    # work with `SECRET SERVICE` through `server.local_bind_port`.

    server.stop()

Example 2
---------

Example of a port forwarding for the Vagrant MySQL local port:

.. code-block:: py

    from sshtunnel import SSHTunnelForwarder
    from time import sleep

    with SSHTunnelForwarder(
        ('localhost', 2222),
        ssh_username="vagrant",
        ssh_password="vagrant",
        remote_bind_address=('127.0.0.1', 3306)
    ) as server:

        print(server.local_bind_port)
        while True:
            # press Ctrl-C for stopping
            sleep(1)

    print('FINISH!')

Or simply using the CLI:

.. code-block:: console

    $ python -m sshtunnel -U vagrant -P vagrant -L :3306 -R 127.0.0.1:3306 -p 2222 localhost

CLI usage
=========

::

    usage: sshtunnel [-h] [-U SSH_USERNAME] [-p SSH_PORT] [-P SSH_PASSWORD] -R
                     IP:PORT [IP:PORT ...] [-L [IP:PORT [IP:PORT ...]]]
                     [-k SSH_HOST_KEY] [-K KEY_FILE] [-S KEY_PASSWORD] [-t]
                     [-v] [-V] [-x IP:PORT] [-c SSH_CONFIG_FILE] [-z] [-n]
                     ssh_address

    Pure python ssh tunnel utils

    positional arguments:
      ssh_address           SSH server IP address (GW for ssh tunnels)
                            set with "-- ssh_address" if immediately after -R or -L

    optional arguments:
      -h, --help            show this help message and exit
      -U, --username SSH_USERNAME
                            SSH server account username
      -p, --server_port SSH_PORT
                            SSH server TCP port (default: 22)
      -P, --password SSH_PASSWORD
                            SSH server account password
      -R, --remote_bind_address IP:PORT [IP:PORT ...]
                            Remote bind address sequence: ip_1:port_1 ip_2:port_2 ... ip_n:port_n
                            Equivalent to ssh -Lxxxx:IP_ADDRESS:PORT
                            If omitted, default port is 22.
                            Example: -R 10.10.10.10: 10.10.10.10:5900
      -L, --local_bind_address [IP:PORT [IP:PORT ...]]
                            Local bind address sequence: ip_1:port_1 ip_2:port_2 ... ip_n:port_n
                            Equivalent to ssh -LPORT:xxxxxxxxx:xxxx, being the local IP address optional.
                            By default it will listen in all interfaces (0.0.0.0) and choose a random port.
                            Example: -L :40000
      -k, --ssh_host_key SSH_HOST_KEY
                            Gateway's host key
      -K, --private_key_file KEY_FILE
                            RSA/DSS/ECDSA private key file
      -S, --private_key_file_password KEY_PASSWORD
                            RSA/DSS/ECDSA private key password
      -t, --threaded        Allow concurrent connections to each tunnel
      -v, --verbosity       Increase output verbosity (default: ERROR)
      -V, --version         Show version number and quit
      -x, --proxy IP:PORT   IP and por for SSH proxy to destination
      -c, --config SSH_CONFIG_FILE
                            SSH configuration file, defaults to ~/.ssh/config
      -z, --compress        Request server for compression over SSH transport
      -n, --noagent         Disable looking for keys from an SSH agent


.. _Pahaz Blinov: https://github.com/pahaz
.. _sshtunnel: https://pypi.python.org/pypi/sshtunnel
.. _paramiko: http://www.paramiko.org/
.. |CircleCI| image:: https://circleci.com/gh/pahaz/sshtunnel.svg?style=svg
   :target: https://circleci.com/gh/pahaz/sshtunnel
.. |AppVeyor| image:: https://ci.appveyor.com/api/projects/status/fnse52dfw60p4cnx?svg=true&passingText=Windows%20-%20OK&failingText=Windows%20-%20Fail
   :target: https://ci.appveyor.com/project/fernandezcuesta/sshtunnel
.. |coveralls| image:: https://coveralls.io/repos/github/pahaz/sshtunnel/badge.svg?branch=master
   :target: https://coveralls.io/github/pahaz/sshtunnel?branch=master
.. |DwnMonth| image:: https://img.shields.io/pypi/dm/sshtunnel.svg
.. |DwnWeek| image:: https://img.shields.io/pypi/dw/sshtunnel.svg
.. |DwnDay| image:: https://img.shields.io/pypi/dd/sshtunnel.svg
.. |pyversions| image:: https://img.shields.io/pypi/pyversions/sshtunnel.svg
.. |version| image:: https://img.shields.io/pypi/v/sshtunnel.svg
   :target: `sshtunnel`_
.. |license| image::  https://img.shields.io/pypi/l/sshtunnel.svg
   :target: https://github.com/pahaz/sshtunnel/blob/master/LICENSE
