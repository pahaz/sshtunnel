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

    import sshtunnel

    with sshtunnel.open_tunnel(
            (ssh_host, ssh_port),
            ssh_host_key=None,
            ssh_username=ssh_user,
            ssh_password=ssh_password,
            ssh_private_key=None,
            remote_bind_address=(REMOTE_HOST, REMOTE_PORT)) as server:

        def do_something(port):
            pass

        print("LOCAL PORT:", server.local_bind_port)

        do_something(server.local_bind_port)

## Ex 2: ##

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

# Ex 3: ##
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

# CONTRIBUTORS #

 - [Cameron Maske](https://github.com/cameronmaske)
 - [Gustavo Machado](https://github.com/gdmachado)
 - [Colin Jermain](https://github.com/cjermain)
 - [J.M. Fernández](https://github.com/fernandezcuesta) - (big thanks!)

# TODO #

 - Write tests!
 
# CHANGELOG #

## work in progress ##

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

## v.0.0.3 ##
 - add `threaded` options (cameronmaske)
 - fix exception error message, correctly printing destination address (gdmachado)
 - fix pip install fails (cjermain, pahaz)

## v.0.0.1 ##
 - `SSHTunnelForwarder` class (pahaz)
 - `open` function (pahaz)

