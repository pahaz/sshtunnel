from setuptools import setup

__author__ = 'pahaz'

appname = 'sshtunnel'
app = __import__(appname)
version = app.__version__

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
    download_url='https://github.com/pahaz/sshtunnel/tarball/' + version,
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
        'Programming Language :: Python :: 2',
        'Programming Languate :: Python :: 3',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Security :: Cryptography',
    ],
)

# TODO: add entry_point