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

CHANGELOG
=========
- v.0.1.1 (`JM Fernández`_)
    + Fix #72
- v.0.1.0 (`JM Fernández`_)
    + Add `tunnel_bindings` property
    + Several bugfixes (#49, #56, #57, #59, #60, #62, #64, #66, ...)
      (`Pahaz Blinov`_, `JM Fernández`_)
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

- v.0.0.6 (`Pahaz Blinov`_)
    + add ``-S`` CLI options for ssh private key password support (`Pahaz Blinov`_)

- v.0.0.5 (`Pahaz Blinov`_)
    + add ``ssh_proxy`` argument, as well as ``ssh_config(5)`` ``ProxyCommand`` support (`Lewis Thompson`_)
    + add some python 2.6 compatibility fixes (`Mart Sõmermaa`_)
    + ``paramiko.transport`` inherits handlers of loggers passed to ``SSHTunnelForwarder`` (`JM Fernández`_)
    + fix `#34`_, `#33`_, code style and docs (`JM Fernández`_)
    + add tests (`Pahaz Blinov`_)
    + add CI integration (`Pahaz Blinov`_)
    + normal packaging (`Pahaz Blinov`_)
    + disable check distenation socket connection by ``SSHTunnelForwarder.local_is_up`` (`Pahaz Blinov`_) [changed default behavior]
    + use daemon mode = False in all threads by default; detail_ (`Pahaz Blinov`_) [changed default behavior]

- v.0.0.4.4 (`Pahaz Blinov`_)
   + fix issue `#24`_ - hide ssh password in logs (`Pahaz Blinov`_)

- v.0.0.4.3 (`Pahaz Blinov`_)
    + fix default port issue `#19`_ (`Pahaz Blinov`_)

- v.0.0.4.2 (`Pahaz Blinov`_)
    + fix Thread.daemon mode for Python < 3.3 `#16`_, `#21`_ (`Lewis Thompson`_, `Erik Rogers`_)

- v.0.0.4.1 (`Pahaz Blinov`_)
    + fix CLI issues `#13`_ (`Pahaz Blinov`_)

- v.0.0.4 (`Pahaz Blinov`_)
    + daemon mode by default for all threads (`JM Fernández`_, `Pahaz Blinov`_) - *incompatible*
    + move ``make_ssh_forward_server`` to ``SSHTunnelForwarder.make_ssh_forward_server`` (`Pahaz Blinov`_, `JM Fernández`_) - *incompatible*
    + move ``make_ssh_forward_handler`` to ``SSHTunnelForwarder.make_ssh_forward_handler_class`` (`Pahaz Blinov`_, `JM Fernández`_) - *incompatible*
    + rename ``open`` to ``open_tunnel`` (`JM Fernández`_) - *incompatible*
    + add CLI interface (`JM Fernández`_)
    + support opening several tunnels at once (`JM Fernández`_)
    + improve stability and readability (`JM Fernández`_, `Pahaz Blinov`_)
    + improve logging (`JM Fernández`_, `Pahaz Blinov`_)
    + add ``raise_exception_if_any_forwarder_have_a_problem`` argument for opening several tunnels at once (`Pahaz Blinov`_)
    + add ``ssh_config_file`` argument support (`JM Fernández`_)
    + add Python 3 support (`JM Fernández`_, `Pahaz Blinov`_)

- v.0.0.3 (`Pahaz Blinov`_)
    + add ``threaded`` option (`Cameron Maske`_)
    + fix exception error message, correctly printing destination address (`Gustavo Machado`_)
    + fix ``pip install`` failure (`Colin Jermain`_, `Pahaz Blinov`_)

- v.0.0.1 (`Pahaz Blinov`_)
    + ``SSHTunnelForwarder`` class (`Pahaz Blinov`_)
    + ``open`` function (`Pahaz Blinov`_)


.. _Cameron Maske: https://github.com/cameronmaske
.. _Gustavo Machado: https://github.com/gdmachado
.. _Colin Jermain: https://github.com/cjermain
.. _JM Fernández: https://github.com/fernandezcuesta
.. _Lewis Thompson: https://github.com/lewisthompson
.. _Erik Rogers: https://github.com/ewrogers
.. _Mart Sõmermaa: https://github.com/mrts
.. _Chronial: https://github.com/Chronial
.. _Dan Harbin: https://github.com/RasterBurn
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
.. _detail: https://github.com/pahaz/sshtunnel/commit/64af238b799b0e0057c4f9b386cda247e0006da9#diff-76bc1662a114401c2954deb92b740081R127