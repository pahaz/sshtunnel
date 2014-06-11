*Author*: Pahaz Blinov.

Inspired: https://github.com/jmagnusson/bgtunnel but it don`t work on windows.
See also: https://github.com/paramiko/paramiko/blob/master/demos/forward.py

Require `paramiko`.

# sshtunnel - SSH tunnels to remote server. #

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

# CHANGELOG #

## v.0.0.1 ##
 - `SSHTunnelForwarder` class
 - `open` function

