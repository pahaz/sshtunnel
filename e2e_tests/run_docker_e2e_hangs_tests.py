import logging

if __name__ == '__main__':
    from run_docker_e2e_db_tests import create_tunnel, start
    logging.warning('RUN')
    tunnel = create_tunnel()
    start(tunnel)
    logging.warning('EOF')
