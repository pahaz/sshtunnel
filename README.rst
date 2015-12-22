[![Circle CI](https://circleci.com/gh/pahaz/sshtunnel.svg?style=svg)](https://circleci.com/gh/pahaz/sshtunnel)

**Author**: **[Pahaz Blinov](https://github.com/pahaz)**

**Repo**: https://github.com/pahaz/sshtunnel/

Inspired by https://github.com/jmagnusson/bgtunnel but it doesn't work on Windows.  
See also: https://github.com/paramiko/paramiko/blob/master/demos/forward.py

Require `paramiko`.

Install
=======

::

    pip install sshtunnel

or :: 

    easy_install sshtunnel

SSH tunnels to remote server
============================

Useful when you need to connect to local port on remote server through ssh
tunnel. It works by opening a port forwarding ssh connection in the
background, using threads. The connection(s) are closed when explicitly
calling the `close` method of the returned SSHTunnelForwarder object.::

    ----------------------------------------------------------------------
    
                                |
    -------------+              |    +----------+               +---------
        LOCAL    |              |    |  REMOTE  |               | PRIVATE
        SERVER   | <== SSH ========> |  SERVER  | <== local ==> | SERVER
    -------------+              |    +----------+               +---------
                                |
                             FIREWALL
    
    ----------------------------------------------------------------------

Fig1: How to connect to PRIVATE SERVER throw SSH tunnel.


Ex 1
----

::

    from sshtunnel import SSHTunnelForwarder
    
    server = SSHTunnelForwarder(
        ('pahaz.urfuclub.ru', 22),
        ssh_username="pahaz",
        ssh_password="secret",
        remote_bind_address=('127.0.0.1', 5555))
    
    server.start()
    
    print(server.local_bind_port)
    # work with `SECRET SERVICE` throw `server.local_bind_port`.
    
    server.stop()

Ex 2
----

Example of a port forwarding for the Vagrant MySQL local port::

    from sshtunnel import SSHTunnelForwarder
    from time import sleep
    
    with SSHTunnelForwarder(
        ('localhost', 2222),
        ssh_username="vagrant",
        ssh_password="vagrant",
        remote_bind_address=('127.0.0.1', 3306)) as server:
    
        print(server.local_bind_port)
        while True:
            # press Ctrl-C for stopping
            sleep(1)
    
    print('FINISH!')

Or simple use CLI::

    python -m sshtunnel -U vagrant -P vagrant -L :3306 -R 127.0.0.1:3306 -p 2222 localhost

API/arguments
=============

`SSHTunnelForwarder` arguments
------------------------------

This is an incomplete list of arguments.  See `__init__()` method of `SSHTunnelForwarder` class in [sshtunnel.py](sshtunnel.py) for a full list.

`ssh_proxy = None`
------------------

Accepts a [paramiko.ProxyCommand](http://paramiko-docs.readthedocs.org/en/latest/api/proxy.html) object which all SSH traffic will be passed through.  See either the [paramiko.ProxyCommand documentation](http://paramiko-docs.readthedocs.org/en/latest/api/proxy.html) or `ProxyCommand` in `ssh_config(5)` for more information.

Note `ssh_proxy` overrides any `ProxyCommand` sourced from the user's `ssh_config`.

Note `ssh_proxy` is ignored if `ssh_proxy_enabled != True`.

`ssh_proxy_enabled = True`
--------------------------

If true (default) and the user's `ssh_config` file contains a `ProxyCommand` directive that matches the specified `ssh_address_or_host` (or first positional argument) `SSHTunnelForwarder` will create a [paramiko.ProxyCommand](http://paramiko-docs.readthedocs.org/en/latest/api/proxy.html) object which all SSH traffic will be passed through.  See the [ssh_proxy](#ssh_proxy) argument for more details.


CONTRIBUTORS
============

 - [Cameron Maske](https://github.com/cameronmaske)
 - [Gustavo Machado](https://github.com/gdmachado)
 - [Colin Jermain](https://github.com/cjermain)
 - [J.M. Fernández](https://github.com/fernandezcuesta) - (big thanks!)
 - [Lewis Thompson](https://github.com/lewisthompson)
 - [Erik Rogers](https://github.com/ewrogers)
 - [Mart Sõmermaa](https://github.com/mrts)

TODO
====

 - Write tests!
 
CHANGELOG
=========

## work in progres ##
 - new feature

## v.0.0.6 ##
 - add `-S` CLI options for ssh private key password support (pahaz)

## v.0.0.5 ##
 - add `ssh_proxy` argument, as well as `ssh_config(5)` `ProxyCommand` support (lewisthompson)
 - add some python 2.6 compatibility fixes (mrts)
 - `paramiko.transport` inherits handlers of loggers passed to `SSHTunnelForwarder` (fernandezcuesta)
 - fix #34, #33, code style and docs (fernandezcuesta)
 - add tests (pahaz)
 - add CI integration (pahaz)
 - normal packaging (pahaz)

## v.0.0.4.4 ##

 - fix issuse [#24](https://github.com/pahaz/sshtunnel/issues/24) - hide ssh password in logs (pahaz)

## v.0.0.4.3 ##

 - fix default port issuse [#19](https://github.com/pahaz/sshtunnel/issues/19) (pahaz)

## v.0.0.4.2 ##
 - fix Thread.daemon mode for Python < 3.3 [#16](https://github.com/pahaz/sshtunnel/issues/16), [#21](https://github.com/pahaz/sshtunnel/issues/21) (lewisthompson, ewrogers)

## v.0.0.4.1 ##
 - fix CLI issues/13 (pahaz)

## v.0.0.4 ##
 - daemon mode by default for all threads (fernandezcuesta, pahaz) - *incompatible*
 - move `make_ssh_forward_server` to `SSHTunnelForwarder.make_ssh_forward_server` (pahaz, fernandezcuesta) - *incompatible*
 - move `make_ssh_forward_handler` to `SSHTunnelForwarder.make_ssh_forward_handler_class` (pahaz, fernandezcuesta) - *incompatible*
 - rename `open` to `open_tunnel` (fernandezcuesta) - *incompatible*
 - add CLI interface (fernandezcuesta)
 - support opening several tunnels at once (fernandezcuesta)
 - improve stability and readability (fernandezcuesta, pahaz)
 - improve logging (fernandezcuesta, pahaz)
 - add `raise_exception_if_any_forwarder_have_a_problem` argument for opening several tunnels at once (pahaz)
 - add `ssh_config_file` argument support (fernandezcuesta)
 - add Python 3 support (fernandezcuesta, pahaz)

## v.0.0.3 ##
 - add `threaded` options (cameronmaske)
 - fix exception error message, correctly printing destination address (gdmachado)
 - fix pip install fails (cjermain, pahaz)

## v.0.0.1 ##
 - `SSHTunnelForwarder` class (pahaz)
 - `open` function (pahaz)

HELP
====

::

    usage: sshtunnel    [-h] [-U SSH_USERNAME] [-p SSH_PORT] [-P SSH_PASSWORD] -R
                        IP:PORT [IP:PORT ...] [-L [IP:PORT [IP:PORT ...]]]
                        [-k SSH_HOST_KEY] [-K RSA_KEY_FILE]
                        [-S RSA_KEY_FILE_PASSWORD] [-t] [-v]
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
      -v, --verbosity       Increase output verbosity (default: 40)

