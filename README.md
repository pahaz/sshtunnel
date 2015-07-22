**Author**: **[Pahaz Blinov](https://github.com/pahaz)**

**Repo**: https://github.com/pahaz/sshtunnel/

Inspired by https://github.com/jmagnusson/bgtunnel but it doesn't work on Windows.  
See also: https://github.com/paramiko/paramiko/blob/master/demos/forward.py

Require `paramiko`.

# Install #

    pip install sshtunnel

or

    easy_install sshtunnel

# SSH tunnels to remote server #

Useful when you need to connect to local port on remote server throw ssh
tunnel. It works by opening a port forwarding ssh connection in the
background, using threads. The connection(s) are closed when explicitly
calling the `close` method of the returned SSHTunnelForwarder object.

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


## Ex 1: ##

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

# Ex 2: ##

Example of a port forwarding for the Vagrant MySQL local port:
    
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

Or simple use CLI:

    python -m sshtunnel -U vagrant -P vagrant -L :3306 -R 127.0.0.1:3306 -p 2222 localhost


# CONTRIBUTORS #

 - [Cameron Maske](https://github.com/cameronmaske)
 - [Gustavo Machado](https://github.com/gdmachado)
 - [Colin Jermain](https://github.com/cjermain)
 - [J.M. Fernández](https://github.com/fernandezcuesta) - (big thanks!)
 - [Lewis Thompson](https://github.com/lewisthompson)
 - [Erik Rogers](https://github.com/ewrogers)

# TODO #

 - Write tests!
 
# CHANGELOG #

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

