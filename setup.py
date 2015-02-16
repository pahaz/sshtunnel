import re
from setuptools import setup

__author__ = 'pahaz'


def get_version(path):
    """
    Return version as listed in `__version__`.
    """
    with open(path, 'rb') as f:
        data = f.read()
        return eval(re.search(b"__version__[ ]*=[ ]*([^\r\n]+)", data).group(1))


appname = 'sshtunnel'
version = get_version(appname + '.py')

setup(
    name=appname,
    version=version,
    description="Initiate SSH tunnels",
    long_description=open('README.md').read(),
    py_modules=[appname],
    install_requires=['paramiko>=1.12.3'],
    author='Pahaz Blinov',
    author_email='pahaz.blinov@gmail.com',
    url='https://github.com/pahaz/sshtunnel',
    download_url='https://pypi.python.org/packages/source/s/sshtunnel/sshtunnel-' + version + '0.0.2.zip',
    keywords=['SSH', 'proxy', 'TCP forwarder'],
    license='MIT',
    platforms=['unix', 'macos', 'windows'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft',
        'Operating System :: Unix',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Security :: Cryptography',
    ],
)

# TODO: add entry_point