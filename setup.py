from setuptools import setup

__version_info__ = (0, 0, 1)
__version__ = '.'.join(str(i) for i in __version_info__)
__author__ = 'pahaz'

appname = 'sshtunnel'

setup(
    name=appname,
    version=__version__,
    description="Initiate SSH tunnels",
    long_description=open('README.md').read(),
    py_modules=[appname],
    install_requires=['paramiko>=1.12.3'],
    author='Pahaz Blinov',
    author_email='pahaz.blinov@gmail.com',
    url='https://github.com/pahaz/sshtunnel',
    download_url='https://github.com/pahaz/sshtunnel/tarball/' + __version__,
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