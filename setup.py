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
try:
   import pypandoc
   long_description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
   long_description = open('README.md').read()

setup(
    name=appname,
    version=version,
    description="Initiate SSH tunnels",
    long_description=long_description,
#    py_modules=[appname],
    package_dir={'sshtunnel': ''},
    packages=['sshtunnel'],
    install_requires=['paramiko>=1.15.2'],
    author='Pahaz Blinov',
    author_email='pahaz.blinov@gmail.com',
    url='https://github.com/pahaz/sshtunnel',
    download_url='https://pypi.python.org/packages/source/s/sshtunnel/sshtunnel-' + version + '.zip',
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
    entry_points={
        'console_scripts': [
            'sshtunnel=sshtunnel.sshtunnel:main',
        ]
    }
)
