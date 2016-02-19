|CircleCI| |coveralls| |version|

|DwnMonth| |DwnWeek| |DwnDay|

|pyversions| |license|

**Author**: `Pahaz Blinov`_

**Repo**: https://github.com/pahaz/sshtunnel/

Inspired by https://github.com/jmagnusson/bgtunnel but it doesn't work on
Windows.

See also: https://github.com/paramiko/paramiko/blob/master/demos/forward.py

Requirements
-------------

* `paramiko`_

Installation
============

::

    pip install sshtunnel

or ::

    easy_install sshtunnel

Install from source::

    python setup.py develop

Testing the package
-------------------

.. code-block:: bash

    python setup.py test

Usage examples: SSH tunnel to remote server
===========================================

Useful when you need to connect to a local port on remote server through ssh
tunnel. It works by opening a port forwarding ssh connection in the
background, using threads. The connection(s) are closed when explicitly
calling the `close` method of the returned SSHTunnelForwarder object.::

    ----------------------------------------------------------------------

                                |
    -------------+              |    +----------+               +---------
        LOCAL    |              |    |  REMOTE  |               | PRIVATE
        CLIENT   | <== SSH ========> |  SERVER  | <== local ==> | SERVER
    -------------+              |    +----------+               +---------
                                |
                             FIREWALL

    ----------------------------------------------------------------------

**Fig1**: How to connect to ``PRIVATE SERVER`` through SSH tunnel.


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

.. code-block:: bash

    python -m sshtunnel -U vagrant -P vagrant -L :3306 -R 127.0.0.1:3306 -p 2222 localhost

API/arguments
=============

``SSHTunnelForwarder`` arguments
--------------------------------

This is an incomplete list of arguments.  See ``__init__()`` method of
``SSHTunnelForwarder`` class in ``sshtunnel.py`` for a full list.

``ssh_proxy = None``
--------------------

Accepts a |paramiko.ProxyCommand|_
object where all SSH traffic will be passed through.
See either the |paramiko.ProxyCommand|_ documentation
or ``ProxyCommand`` in ``ssh_config(5)`` for more information.

 Note: ``ssh_proxy`` overrides any ``ProxyCommand`` sourced from the user
 ``ssh_config``.

 Note: ``ssh_proxy`` is ignored if ``ssh_proxy_enabled != True``.

``ssh_proxy_enabled = True``
----------------------------

If True (default) and user's ``ssh_config`` file contains a ``ProxyCommand``
directive that matches the specified ``ssh_address_or_host`` (or first
positional argument), ``SSHTunnelForwarder`` will create a
|paramiko.ProxyCommand|_ object where all SSH traffic will be passed through.

See the ``ssh_proxy`` argument for more details.


CONTRIBUTORS
============

- `Cameron Maske`_
- `Gustavo Machado`_
- `Colin Jermain`_
- `JM Fernández`_ - (big thanks!)
- `Lewis Thompson`_
- `Erik Rogers`_
- `Mart Sõmermaa`_
- `Chronial`_

CHANGELOG
=========

- v.0.0.7.2 (`JM Fernández`_)
    + Add ``compression`` (`JM Fernández`_)
    + Add ``__str__`` method (`JM Fernández`_)
- v.0.0.7.1 (`JM Fernández`_)
    + Add test functions (`JM Fernández`_)
    + Fix default username when not provided and ssh_config file is skipped (`JM Fernández`_)
    + Fix gateway IP unresolvable exception catching (`JM Fernández`_)
    + Minor fixes (`JM Fernández`_)
- v.0.0.7 (`JM Fernández`_)
    + Tunnels can now be stopped and started safely (`#41`_) (`JM Fernández`_)
    + Add timeout to SSH gateway and keep-alive messages (`#29`_) (`JM Fernández`_)
    + Allow sending a pkey directly (`#43`_) (`Chronial`_)
    + Add ``-V`` CLI option to show current version (`JM Fernández`_)
    + Add coverage (`JM Fernández`_)
    + Refactoring (`JM Fernández`_)

- v.0.0.6 (`Pahaz Blinov`_)
    + add ``-S`` CLI options for ssh private key password support (`Pahaz Blinov`_)

- v.0.0.5 (`Pahaz Blinov`_)
    + add ``ssh_proxy`` argument, as well as ``ssh_config(5)`` ``ProxyCommand`` support (`Lewis Thompson`_)
    + add some python 2.6 compatibility fixes (`Mart Sõmermaa`_)
    + ``paramiko.transport`` inherits handlers of loggers passed to ``SSHTunnelForwarder`` (`JM Fernández`_)
    + fix `#34`_, `#33`_, code style and docs (`JM Fernández`_)
    + add tests (`Pahaz Blinov`_)
    + add CI integration (`Pahaz Blinov`_)
    + normal packaging (`Pahaz Blinov`_)
    + disable check distenation socket connection by ``SSHTunnelForwarder.local_is_up`` (`Pahaz Blinov`_) [changed default behavior]
    + use daemon mode = False in all threads by default; detail_ (`Pahaz Blinov`_) [changed default behavior]

- v.0.0.4.4 (`Pahaz Blinov`_)
   + fix issue `#24`_ - hide ssh password in logs (`Pahaz Blinov`_)

- v.0.0.4.3 (`Pahaz Blinov`_)
    + fix default port issue `#19`_ (`Pahaz Blinov`_)

- v.0.0.4.2 (`Pahaz Blinov`_)
    + fix Thread.daemon mode for Python < 3.3 `#16`_, `#21`_ (`Lewis Thompson`_, `Erik Rogers`_)

- v.0.0.4.1 (`Pahaz Blinov`_)
    + fix CLI issues `#13`_ (`Pahaz Blinov`_)

- v.0.0.4 (`Pahaz Blinov`_)
    + daemon mode by default for all threads (`JM Fernández`_, `Pahaz Blinov`_) - *incompatible*
    + move ``make_ssh_forward_server`` to ``SSHTunnelForwarder.make_ssh_forward_server`` (`Pahaz Blinov`_, `JM Fernández`_) - *incompatible*
    + move ``make_ssh_forward_handler`` to ``SSHTunnelForwarder.make_ssh_forward_handler_class`` (`Pahaz Blinov`_, `JM Fernández`_) - *incompatible*
    + rename ``open`` to ``open_tunnel`` (`JM Fernández`_) - *incompatible*
    + add CLI interface (`JM Fernández`_)
    + support opening several tunnels at once (`JM Fernández`_)
    + improve stability and readability (`JM Fernández`_, `Pahaz Blinov`_)
    + improve logging (`JM Fernández`_, `Pahaz Blinov`_)
    + add ``raise_exception_if_any_forwarder_have_a_problem`` argument for opening several tunnels at once (`Pahaz Blinov`_)
    + add ``ssh_config_file`` argument support (`JM Fernández`_)
    + add Python 3 support (`JM Fernández`_, `Pahaz Blinov`_)

- v.0.0.3 (`Pahaz Blinov`_)
    + add ``threaded`` options (`Cameron Maske`_)
    + fix exception error message, correctly printing destination address (`Gustavo Machado`_)
    + fix pip install fails (`Colin Jermain`_, `Pahaz Blinov`_)

- v.0.0.1 (`Pahaz Blinov`_)
    + ``SSHTunnelForwarder`` class (`Pahaz Blinov`_)
    + ``open`` function (`Pahaz Blinov`_)

HELP
====

::

    usage: sshtunnel [-h] [-U SSH_USERNAME] [-p SSH_PORT] [-P SSH_PASSWORD] -R
                     IP:PORT [IP:PORT ...] [-L [IP:PORT [IP:PORT ...]]]
                     [-k SSH_HOST_KEY] [-K RSA_KEY_FILE]
                     [-S RSA_KEY_FILE_PASSWORD] [-t] [-v] [-V] [-x IP:PORT]
                     [-z]
                     ssh_address

    Pure python ssh tunnel utils

    positional arguments:
      ssh_address           SSH server IP address (GW for ssh tunnels)
                            set with "-- ssh_address" if immediately after -R or -L

    optional arguments:
      -h, --help            show this help message and exit
      -U SSH_USERNAME, --username SSH_USERNAME
                            SSH server account username
      -p SSH_PORT, --server_port SSH_PORT
                            SSH server TCP port (default: 22)
      -P SSH_PASSWORD, --password SSH_PASSWORD
                            SSH server account password
      -R IP:PORT [IP:PORT ...], --remote_bind_address IP:PORT [IP:PORT ...]
                            Remote bind address sequence: ip_1:port_1 ip_2:port_2 ... ip_n:port_n
                            Equivalent to ssh -Lxxxx:IP_ADDRESS:PORT
                            If omitted, default port is 22.
                            Example: -R 10.10.10.10: 10.10.10.10:5900
      -L [IP:PORT [IP:PORT ...]], --local_bind_address [IP:PORT [IP:PORT ...]]
                            Local bind address sequence: ip_1:port_1 ip_2:port_2 ... ip_n:port_n
                            Equivalent to ssh -LPORT:xxxxxxxxx:xxxx, being the local IP address optional.
                            By default it will listen in all interfaces (0.0.0.0) and choose a random port.
                            Example: -L :40000
      -k SSH_HOST_KEY, --ssh_host_key SSH_HOST_KEY
                            Gateway's host key
      -K RSA_KEY_FILE, --private_key_file RSA_KEY_FILE
                            RSA private key file
      -S RSA_KEY_FILE_PASSWORD, --private_key_file_password RSA_KEY_FILE_PASSWORD
                            RSA private key file password
      -t, --threaded        Allow concurrent connections to each tunnel
      -v, --verbosity       Increase output verbosity (default: ERROR)
      -V, --version         Show version number and quit
      -x, --proxy IP:PORT
                            IP and por for SSH proxy to destination
      -z, --compress        Request server for compression over SSH transport


.. _Pahaz Blinov: https://github.com/pahaz
.. _Cameron Maske: https://github.com/cameronmaske
.. _Gustavo Machado: https://github.com/gdmachado
.. _Colin Jermain: https://github.com/cjermain
.. _JM Fernández: https://github.com/fernandezcuesta
.. _Lewis Thompson: https://github.com/lewisthompson
.. _Erik Rogers: https://github.com/ewrogers
.. _Mart Sõmermaa: https://github.com/mrts
.. _Chronial: https://github.com/Chronial

.. _paramiko: http://www.paramiko.org/
.. |paramiko.ProxyCommand| replace:: ``paramiko.ProxyCommand``
.. _paramiko.ProxyCommand: http://paramiko-docs.readthedocs.org/en/latest/api/proxy.html

.. _#13: https://github.com/pahaz/sshtunnel/issues/13
.. _#16: https://github.com/pahaz/sshtunnel/issues/16
.. _#19: https://github.com/pahaz/sshtunnel/issues/19
.. _#21: https://github.com/pahaz/sshtunnel/issues/21
.. _#24: https://github.com/pahaz/sshtunnel/issues/24
.. _#29: https://github.com/pahaz/sshtunnel/issues/29
.. _#33: https://github.com/pahaz/sshtunnel/issues/33
.. _#34: https://github.com/pahaz/sshtunnel/issues/34
.. _#41: https://github.com/pahaz/sshtunnel/issues/41
.. _#43: https://github.com/pahaz/sshtunnel/issues/43
.. _detail: https://github.com/pahaz/sshtunnel/commit/64af238b799b0e0057c4f9b386cda247e0006da9#diff-76bc1662a114401c2954deb92b740081R127

.. |CircleCI| image:: https://circleci.com/gh/pahaz/sshtunnel.svg?style=svg
   :target: https://circleci.com/gh/pahaz/sshtunnel
.. |coveralls| image:: https://coveralls.io/repos/github/pahaz/sshtunnel/badge.svg?branch=master
   :target: https://coveralls.io/github/pahaz/sshtunnel?branch=master
.. |DwnMonth| image:: https://img.shields.io/pypi/dm/sshtunnel.svg
.. |DwnWeek| image:: https://img.shields.io/pypi/dw/sshtunnel.svg
.. |DwnDay| image:: https://img.shields.io/pypi/dd/sshtunnel.svg
.. |pyversions| image:: https://img.shields.io/pypi/pyversions/sshtunnel.svg
.. |version| image:: https://img.shields.io/pypi/v/sshtunnel.svg
.. |license| image::  https://img.shields.io/pypi/l/sshtunnel.svg
