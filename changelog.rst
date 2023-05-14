CONTRIBUTORS
============

- `Cameron Maske`_
- `Gustavo Machado`_
- `Colin Jermain`_
- `JM Fernández`_ - (big thanks!)
- `Lewis Thompson`_
- `Erik Rogers`_
- `Mart Sõmermaa`_
- `Chronial`_
- `Dan Harbin`_
- `Ignacio Peluffo`_
- `Niels Zeilemaker`_
- `Georgy Rylov`_
- `Eddie Chiang`_
- `kkrasovskii`_
- `V0idk`_
- `Bruno Inec`_
- `alex3d`_

CHANGELOG
=========

- v.0.X.Y (`V0idk`_, `Bruno Inec`_, `alex3d`_)
    + Remove the potential deadlock that is associated with threading.Lock (`#231`_)
    + Remove the hidden modification of the logger in cases where a custom logger is used. (`#250`_)
    + Speed up the bulk transfer (`#247`_)

- v.0.4.0 (`Pahaz`_)
    + Change the daemon mod flag for all tunnel threads (is not fully backward compatible) to prevent unexpected hangs (`#219`_)
    + Add docker based end to end functinal tests for Mongo/Postgres/MySQL (`#219`_)
    + Add docker based end to end hangs tests (`#219`_)

- v.0.3.2 (`Pahaz`_, `JM Fernández`_)
    + Fix host key directory detection
    + Unify default ssh config folder to `~/.ssh`

- v.0.3.1 (`Pahaz`_)
    + Increase open connection timeout to 10 secods

- v.0.3.0 (`Pahaz`_)
    + Change default with context behavior to use `.stop(force=True)` on exit (is not fully backward compatible)
    + Remove useless `daemon_forward_servers = True` hack for hangs prevention (is not fully backward compatible)
    + Set transport keepalive to 5 second by default (disabled for version < 0.3.0)
    + Set default transport timeout to 0.1
    + Deprecate and remove `block_on_close` option
    + Fix "deadlocks" / "tunneling hangs" (`#173`_, `#201`_, `#162`_, `#211`_)

- v.0.2.2 (`Pahaz`_)
    + Add `.stop(force=True)` for force close active connections (`#201`_)

- v.0.2.1 (`Pahaz`_, `Eddie Chiang`_ and `kkrasovskii`_)
    + Fixes bug with orphan thread for a tunnel that is DOWN (`#170`_)

- v.0.2.0 (`Georgy Rylov`_)
    + Support IPv6 without proxy command. Use built-in paramiko create socket logic. The logic tries to use ipv6 socket family first, then ipv4 socket family.

- v.0.1.5 (`JM Fernández`_)
    + Introduce `block_on_close` attribute

- v.0.1.4 (`Niels Zeilemaker`_)
    + Allow loading pkeys from `~/.ssh`

- v.0.1.3 (`Ignacio Peluffo`_ and others)
    + ``pkey_file`` parameter updated to accept relative paths to user folder using ``~``
    + Several bugfixes

- v.0.1.2 (`JM Fernández`_)
    + Fix #77

- v.0.1.1 (`JM Fernández`_)
    + Fix #72

- v.0.1.0 (`JM Fernández`_)
    + Add `tunnel_bindings` property
    + Several bugfixes (#49, #56, #57, #59, #60, #62, #64, #66, ...)
      (`Pahaz`_, `JM Fernández`_)
    + Add TRACE logging level (`JM Fernández`_)
    + Code and tests refactoring (`JM Fernández`_)
    + Drop python3.2 support

- v.0.0.8 (`JM Fernández`_)
    + Merge `#31`_: Support Unix domain socket (local) forwarding (`Dan Harbin`_)
    + Simplify API (`JM Fernández`_)
    + Add sphinx-based documentation (`JM Fernández`_)
    + Add ``allow_agent`` (fixes `#36`_, `#46`_) (`JM Fernández`_)
    + Add ``compression`` (`JM Fernández`_)
    + Add ``__str__`` method (`JM Fernández`_)
    + Add test functions (`JM Fernández`_)
    + Fix default username when not provided and ssh_config file is skipped (`JM Fernández`_)
    + Fix gateway IP unresolvable exception catching (`JM Fernández`_)
    + Minor fixes (`JM Fernández`_)
    + Add AppVeyor support (`JM Fernández`_)

- v.0.0.7 (`JM Fernández`_)
    + Tunnels can now be stopped and started safely (`#41`_) (`JM Fernández`_)
    + Add timeout to SSH gateway and keep-alive messages (`#29`_) (`JM Fernández`_)
    + Allow sending a pkey directly (`#43`_) (`Chronial`_)
    + Add ``-V`` CLI option to show current version (`JM Fernández`_)
    + Add coverage (`JM Fernández`_)
    + Refactoring (`JM Fernández`_)

- v.0.0.6 (`Pahaz`_)
    + add ``-S`` CLI options for ssh private key password support (`Pahaz`_)

- v.0.0.5 (`Pahaz`_)
    + add ``ssh_proxy`` argument, as well as ``ssh_config(5)`` ``ProxyCommand`` support (`Lewis Thompson`_)
    + add some python 2.6 compatibility fixes (`Mart Sõmermaa`_)
    + ``paramiko.transport`` inherits handlers of loggers passed to ``SSHTunnelForwarder`` (`JM Fernández`_)
    + fix `#34`_, `#33`_, code style and docs (`JM Fernández`_)
    + add tests (`Pahaz`_)
    + add CI integration (`Pahaz`_)
    + normal packaging (`Pahaz`_)
    + disable check distenation socket connection by ``SSHTunnelForwarder.local_is_up`` (`Pahaz`_) [changed default behavior]
    + use daemon mode = False in all threads by default; detail_ (`Pahaz`_) [changed default behavior]

- v.0.0.4.4 (`Pahaz`_)
   + fix issue `#24`_ - hide ssh password in logs (`Pahaz`_)

- v.0.0.4.3 (`Pahaz`_)
    + fix default port issue `#19`_ (`Pahaz`_)

- v.0.0.4.2 (`Pahaz`_)
    + fix Thread.daemon mode for Python < 3.3 `#16`_, `#21`_ (`Lewis Thompson`_, `Erik Rogers`_)

- v.0.0.4.1 (`Pahaz`_)
    + fix CLI issues `#13`_ (`Pahaz`_)

- v.0.0.4 (`Pahaz`_)
    + daemon mode by default for all threads (`JM Fernández`_, `Pahaz`_) - *incompatible*
    + move ``make_ssh_forward_server`` to ``SSHTunnelForwarder.make_ssh_forward_server`` (`Pahaz`_, `JM Fernández`_) - *incompatible*
    + move ``make_ssh_forward_handler`` to ``SSHTunnelForwarder.make_ssh_forward_handler_class`` (`Pahaz`_, `JM Fernández`_) - *incompatible*
    + rename ``open`` to ``open_tunnel`` (`JM Fernández`_) - *incompatible*
    + add CLI interface (`JM Fernández`_)
    + support opening several tunnels at once (`JM Fernández`_)
    + improve stability and readability (`JM Fernández`_, `Pahaz`_)
    + improve logging (`JM Fernández`_, `Pahaz`_)
    + add ``raise_exception_if_any_forwarder_have_a_problem`` argument for opening several tunnels at once (`Pahaz`_)
    + add ``ssh_config_file`` argument support (`JM Fernández`_)
    + add Python 3 support (`JM Fernández`_, `Pahaz`_)

- v.0.0.3 (`Pahaz`_)
    + add ``threaded`` option (`Cameron Maske`_)
    + fix exception error message, correctly printing destination address (`Gustavo Machado`_)
    + fix ``pip install`` failure (`Colin Jermain`_, `Pahaz`_)

- v.0.0.1 (`Pahaz`_)
    + ``SSHTunnelForwarder`` class (`Pahaz`_)
    + ``open`` function (`Pahaz`_)


.. _Pahaz: https://github.com/pahaz
.. _Cameron Maske: https://github.com/cameronmaske
.. _Gustavo Machado: https://github.com/gdmachado
.. _Colin Jermain: https://github.com/cjermain
.. _JM Fernández: https://github.com/fernandezcuesta
.. _Lewis Thompson: https://github.com/lewisthompson
.. _Erik Rogers: https://github.com/ewrogers
.. _Mart Sõmermaa: https://github.com/mrts
.. _Chronial: https://github.com/Chronial
.. _Dan Harbin: https://github.com/RasterBurn
.. _Ignacio Peluffo: https://github.com/ipeluffo
.. _Niels Zeilemaker: https://github.com/NielsZeilemaker
.. _Georgy Rylov: https://github.com/g0djan
.. _Eddie Chiang: https://github.com/eddie-chiang
.. _kkrasovskii: https://github.com/kkrasovskii
.. _V0idk: https://github.com/V0idk
.. _Bruno Inec: https://github.com/sweenu
.. _alex3d: https://github.com/alex3d
.. _#13: https://github.com/pahaz/sshtunnel/issues/13
.. _#16: https://github.com/pahaz/sshtunnel/issues/16
.. _#19: https://github.com/pahaz/sshtunnel/issues/19
.. _#21: https://github.com/pahaz/sshtunnel/issues/21
.. _#24: https://github.com/pahaz/sshtunnel/issues/24
.. _#29: https://github.com/pahaz/sshtunnel/issues/29
.. _#31: https://github.com/pahaz/sshtunnel/issues/31
.. _#33: https://github.com/pahaz/sshtunnel/issues/33
.. _#34: https://github.com/pahaz/sshtunnel/issues/34
.. _#36: https://github.com/pahaz/sshtunnel/issues/36
.. _#41: https://github.com/pahaz/sshtunnel/issues/41
.. _#43: https://github.com/pahaz/sshtunnel/issues/43
.. _#46: https://github.com/pahaz/sshtunnel/issues/46
.. _#170: https://github.com/pahaz/sshtunnel/issues/170
.. _#201: https://github.com/pahaz/sshtunnel/issues/201
.. _#162: https://github.com/pahaz/sshtunnel/issues/162
.. _#173: https://github.com/pahaz/sshtunnel/issues/173
.. _#201: https://github.com/pahaz/sshtunnel/issues/201
.. _#211: https://github.com/pahaz/sshtunnel/issues/211
.. _#219: https://github.com/pahaz/sshtunnel/issues/219
.. _#231: https://github.com/pahaz/sshtunnel/issues/231
.. _#247: https://github.com/pahaz/sshtunnel/issues/247
.. _#250: https://github.com/pahaz/sshtunnel/issues/250
.. _detail: https://github.com/pahaz/sshtunnel/commit/64af238b799b0e0057c4f9b386cda247e0006da9#diff-76bc1662a114401c2954deb92b740081R127
