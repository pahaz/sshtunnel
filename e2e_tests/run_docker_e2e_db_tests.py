import select
import traceback
import sys
import os
import time
from sshtunnel import SSHTunnelForwarder
import sshtunnel
import logging
import threading
import paramiko

sshtunnel.DEFAULT_LOGLEVEL = 1
logging.basicConfig(
    format='%(asctime)s| %(levelname)-4.3s|%(threadName)10.9s/%(lineno)04d@%(module)-10.9s| %(message)s', level=1)

SSH_SERVER_ADDRESS = ('127.0.0.1', 2223)
SSH_SERVER_USERNAME = 'linuxserver'
SSH_PKEY = os.path.join(os.path.dirname(__file__), 'ssh-server-config', 'ssh_host_rsa_key')
SSH_SERVER_REMOTE_SIDE_ADDRESS_PG = ('10.5.0.5', 5432)
SSH_SERVER_REMOTE_SIDE_ADDRESS_MYSQL = ('10.5.0.6', 3306)
SSH_SERVER_REMOTE_SIDE_ADDRESS_MONGO = ('10.5.0.7', 27017)

PG_DATABASE_NAME = 'main'
PG_USERNAME = 'postgres'
PG_PASSWORD = 'postgres'
PG_QUERY = 'select version()'
PG_EXPECT = eval(
    """('PostgreSQL 13.0 (Debian 13.0-1.pgdg100+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 8.3.0-6) 8.3.0, 64-bit',)""")

MYSQL_DATABASE_NAME = 'main'
MYSQL_USERNAME = 'mysql'
MYSQL_PASSWORD = 'mysql'
MYSQL_QUERY = 'select version()'
MYSQL_EXPECT = (('8.0.22',),)

MONGO_DATABASE_NAME = 'main'
MONGO_USERNAME = 'mongo'
MONGO_PASSWORD = 'mongo'
MONGO_QUERY = lambda client, db: client.server_info()
MONGO_EXPECT = eval(
    """{'version': '3.6.21', 'gitVersion': '1cd2db51dce4b16f4bc97a75056269df0dc0bddb', 'modules': [], 'allocator': 'tcmalloc', 'javascriptEngine': 'mozjs', 'sysInfo': 'deprecated', 'versionArray': [3, 6, 21, 0], 'openssl': {'running': 'OpenSSL 1.0.2g  1 Mar 2016', 'compiled': 'OpenSSL 1.0.2g  1 Mar 2016'}, 'buildEnvironment': {'distmod': 'ubuntu1604', 'distarch': 'x86_64', 'cc': '/opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0', 'ccflags': '-fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp', 'cxx': '/opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0', 'cxxflags': '-Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14', 'linkflags': '-pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro', 'target_arch': 'x86_64', 'target_os': 'linux'}, 'bits': 64, 'debug': False, 'maxBsonObjectSize': 16777216, 'storageEngines': ['devnull', 'ephemeralForTest', 'mmapv1', 'wiredTiger'], 'ok': 1.0}""")


def run_postgres_query(port, query=PG_QUERY):
    import psycopg2

    ASYNC_OK = 1
    ASYNC_READ_TIMEOUT = 2
    ASYNC_WRITE_TIMEOUT = 3
    ASYNC_TIMEOUT = 0.2

    def wait(conn):
        while 1:
            state = conn.poll()
            if state == psycopg2.extensions.POLL_OK:
                break
            elif state == psycopg2.extensions.POLL_WRITE:
                select.select([], [conn.fileno()], [])
            elif state == psycopg2.extensions.POLL_READ:
                select.select([conn.fileno()], [], [])
            else:
                raise psycopg2.OperationalError(
                    "poll() returned %s from _wait function" % state)

    def wait_timeout(conn):
        while 1:
            state = conn.poll()
            if state == psycopg2.extensions.POLL_OK:
                return ASYNC_OK
            elif state == psycopg2.extensions.POLL_WRITE:
                # Wait for the given time and then check the return status
                # If three empty lists are returned then the time-out is
                # reached.
                timeout_status = select.select(
                    [], [conn.fileno()], [], ASYNC_TIMEOUT
                )
                if timeout_status == ([], [], []):
                    return ASYNC_WRITE_TIMEOUT
            elif state == psycopg2.extensions.POLL_READ:
                # Wait for the given time and then check the return status
                # If three empty lists are returned then the time-out is
                # reached.
                timeout_status = select.select(
                    [conn.fileno()], [], [], ASYNC_TIMEOUT
                )
                if timeout_status == ([], [], []):
                    return ASYNC_READ_TIMEOUT
            else:
                raise psycopg2.OperationalError(
                    "poll() returned %s from _wait_timeout function" % state
                )

    pg_conn = psycopg2.connect(
        host='127.0.0.1',
        hostaddr='127.0.0.1',
        port=port,
        database=PG_DATABASE_NAME,
        user=PG_USERNAME,
        password=PG_PASSWORD,
        sslmode='disable',
        async_=1
    )
    wait(pg_conn)
    cur = pg_conn.cursor()
    cur.execute(query)
    res = wait_timeout(cur.connection)
    while res != ASYNC_OK:
        res = wait_timeout(cur.connection)
    return cur.fetchone()


def run_mysql_query(port, query=MYSQL_QUERY):
    import pymysql
    conn = pymysql.connect(
        host='127.0.0.1',
        port=port,
        user=MYSQL_USERNAME,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE_NAME,
        connect_timeout=5,
        read_timeout=5)
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def run_mongo_query(port, query=MONGO_QUERY):
    import pymongo
    client = pymongo.MongoClient('127.0.0.1', port)
    db = client[MONGO_DATABASE_NAME]
    return query(client, db)


def create_tunnel():
    logging.info('Creating SSHTunnelForwarder... (sshtunnel v%s, paramiko v%s)',
                 sshtunnel.__version__, paramiko.__version__)
    tunnel = SSHTunnelForwarder(
        SSH_SERVER_ADDRESS,
        ssh_username=SSH_SERVER_USERNAME,
        ssh_pkey=SSH_PKEY,
        remote_bind_addresses=[
            SSH_SERVER_REMOTE_SIDE_ADDRESS_PG, SSH_SERVER_REMOTE_SIDE_ADDRESS_MYSQL,
            SSH_SERVER_REMOTE_SIDE_ADDRESS_MONGO,
        ],
    )
    return tunnel


def start(tunnel):
    try:
        logging.info('Trying to start ssh tunnel...')
        tunnel.start()
    except Exception as e:
        logging.exception('Tunnel start exception: %r', e)
        raise


def run_db_queries(tunnel):
    result1, result2, result3 = None, None, None

    try:
        logging.info('Trying to run PG query...')
        result1 = run_postgres_query(tunnel.local_bind_ports[0])
        logging.info('PG query: %r', result1)
    except Exception as e:
        logging.exception('PG query exception: %r', e)
        raise

    try:
        logging.info('Trying to run MYSQL query...')
        result2 = run_mysql_query(tunnel.local_bind_ports[1])
        logging.info('MYSQL query: %r', result2)
    except Exception as e:
        logging.exception('MYSQL query exception: %r', e)
        raise

    try:
        logging.info('Trying to run MONGO query...')
        result3 = run_mongo_query(tunnel.local_bind_ports[2])
        logging.info('MONGO query: %r', result3)
    except Exception as e:
        logging.exception('MONGO query exception: %r', e)
        raise

    return result1, result2, result3


def wait_and_check_or_restart_if_required(tunnel, i=1):
    logging.warning('Sleeping for %s second...', i)
    while i:
        time.sleep(1)
        if i % 10 == 0:
            logging.info('Running tunnel.check_tunnels... (i=%s)', i)
            tunnel.check_tunnels()
            logging.info('Check result: %r (i=%s)', tunnel.tunnel_is_up, i)
            if not tunnel.is_active:
                logging.warning('Tunnel is DOWN! restarting ...')
                tunnel.restart()
        i -= 1


def stop(tunnel, force=True):
    try:
        logging.info('Trying to stop resources...')
        tunnel.stop(force=force)
    except Exception as e:
        logging.exception('Tunnel stop exception: %r', e)
        raise


def show_threading_state_if_required():
    current_threads = list(threading.enumerate())
    if len(current_threads) > 1:
        logging.warning('[1] THREAD INFO')
        logging.info('Threads: %r', current_threads)
        logging.info('Threads.daemon: %r', [x.daemon for x in current_threads])

    if len(current_threads) > 1:
        logging.warning('[2] STACK INFO')
        code = ["\n\n*** STACKTRACE - START ***\n"]
        for threadId, stack in sys._current_frames().items():
            code.append("\n# ThreadID: %s" % threadId)
            for filename, lineno, name, line in traceback.extract_stack(stack):
                code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
                if line:
                    code.append("  %s" % (line.strip()))
        code.append("\n*** STACKTRACE - END ***\n\n")
        logging.info('\n'.join(code))


if __name__ == '__main__':
    logging.warning('RUN')
    tunnel = create_tunnel()
    start(tunnel)
    res = run_db_queries(tunnel)
    stop(tunnel)
    wait_and_check_or_restart_if_required(tunnel)
    show_threading_state_if_required()
    logging.warning('EOF')
    
    assert res == (PG_EXPECT, MYSQL_EXPECT, MONGO_EXPECT)
    
    # If Python 2.7 is dropped below makes debugging easier!
    # assert res[0] == PG_EXPECT, f"{res[0]=} {PG_EXPECT}"
    # assert res[1] == MYSQL_EXPECT, f"{res[1]=} {MYSQL_EXPECT}"
    # assert res[2] == MONGO_EXPECT, f"{res[2]=} {MONGO_EXPECT}"
    logging.info("Tests pass!")
