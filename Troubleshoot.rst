Troubleshooting guidelines
==========================

In case of problems using ``sshtunnel`` and prior to logging an issue, please
consider following the next steps to debug where your problem may come from.

- Check if you're running the latest version (`PYPI`_ package may not be
  updated)
- Double-check connectivity to SSH gateway/bastion host using `paramiko`_

An example of an SSH connectivity test using `paramiko`_ authenticating with
username and password follows::

    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(IP_ADDRESS_OR_HOSTNAME,
                   username=USERNAME,
                   password=PASSWORD,
                   allow_agent=False,
                   look_for_keys=False
                   timeout=5.0)


While troubleshooting, implicitly set the local bind address and enable verbose
logging as follows::

    import sshtunnel

    sshtunnel.SSH_TIMEOUT = sshtunnel.TUNNEL_TIMEOUT = 5.0

    server = sshtunnel.open_tunnel(
        IP_ADDRESS_OR_HOSTNAME,
        ssh_username=USERNAME,
        ssh_password=PASSWORD,
        remote_bind_address=(REMOTE_BIND_IP, REMOTE_BIND_PORT),
        local_bind_address=('127.0.0.1', LOCAL_BIND_PORT),
        debug_level='TRACE',
    )

    server.start()
    print(server.local_bind_port)  # show assigned local port
    server.stop()

Check if you've permission to listen at ``LOCAL_BIND_PORT``::

    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', LOCAL_BIND_PORT))
    s.listen(1)
    s.close()


Additional notes
----------------

- In general, try to use wrapper (``open_tunnel()``)
- The context manager (``with`` statement) handles opening and closing of tunnels and underlying SSH transports
- Deprecated parameters/arguments may be deleted in future releases, thus it's recommended not to use them unless necessary



.. _PYPI: https://pypi.python.org/pypi/sshtunnel
.. _paramiko: http://www.paramiko.org/
