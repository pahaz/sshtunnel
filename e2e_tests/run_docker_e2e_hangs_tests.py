import logging
import sshtunnel
import os


if __name__ == '__main__':
    path = os.path.join(os.path.dirname(__file__), 'run_docker_e2e_db_tests.py')
    with open(path) as f:
        exec(f.read())
    logging.warning('RUN')
    tunnel = create_tunnel()
    start(tunnel)
    logging.warning('EOF')
