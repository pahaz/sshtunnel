**Author**: Pahaz Blinov  
**Repo**: https://github.com/pahaz/sshtunnel/


Inspired: https://github.com/jmagnusson/bgtunnel but it don`t work on windows.  
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
    -------------|              |    |----------|               |---------
        LOCAL    |              |    |  REMOTE  |               | PRIVATE
        SERVER   | <== SSH ========> |  SERVER  | <== local ==> | SERVER
    -------------|              |    |----------|               |---------
                                |
                             FIREWALL

    ----------------------------------------------------------------------

Fig1: How to connect to PRIVATE SERVER throw SSH tunnel.


## Ex 1: ##

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

## Ex 2: ##

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

# AUTHORS #

 - [Pahaz Blinov](https://github.com/pahaz)
 - [Cameron Maske](https://github.com/cameronmaske)
 - [Gustavo Machado](https://github.com/gdmachado)
 - [Colin Jermain](https://github.com/cjermain)

# CHANGELOG #

## work in progress ##

## v.0.0.2 ##
 - add `threaded` options (cameronmaske)
 - fix exception error message, correctly printing destination address (gdmachado)
 - fix pip install fails (cjermain, pahaz)

## v.0.0.1 ##
 - `SSHTunnelForwarder` class (pahaz)
 - `open` function (pahaz)

