import logging

if __name__ == '__main__':
    x = __import__('run_docker_e2e_db_tests')
    logging.warning('RUN')
    tunnel = x.create_tunnel()
    x.start(tunnel)
    logging.warning('EOF')
