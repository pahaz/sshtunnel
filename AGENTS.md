# Notes for AI coding agents

## Environment setup

```bash
python -m pip install -e .
python -m pip install -r tests/requirements.txt flake8
```

The test suite also needs the OpenSSH client (`ssh`) on `PATH`:
`paramiko.ProxyCommand` starts its command as soon as it is created, so
`test_connect_via_proxy` and `test_read_ssh_config` fail with
`FileNotFoundError: 'ssh'` without it. Minimal containers often lack it;
install it instead of mocking it in the tests:

```bash
apt-get update && apt-get install -y openssh-client
```

## Checks to run before pushing

```bash
python -m pytest tests -n auto -W ignore::DeprecationWarning
flake8
```

## Commits, pull requests and comments

- Write everything on GitHub in English.
- Do not add any AI attribution: no "Generated with Claude Code" (or
  similar) lines, no `Co-Authored-By` trailers for AI tools, no session
  links, no robot emoji. Write plain maintainer-style text.
