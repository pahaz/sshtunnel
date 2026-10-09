#!/usr/bin/env bash
# Create the git tag and the GitHub Release for the version in sshtunnel.py.
# Runs at the end of the `deploy` job, after the upload to PyPI.
#
# The tag is `X.Y.Z` (no "v" prefix, as for the previous releases) and points to
# the commit that was built. Release notes are taken from the matching section
# of changelog.rst. Does nothing if the release already exists.
#
# Needs GITHUB_TOKEN in the CircleCI project environment variables
# (fine-grained token for this repo with "Contents: Read and write").
set -eu
cd "$(dirname "$0")/.."

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "GITHUB_TOKEN is not set: create the tag and the GitHub Release by hand" >&2
  exit 1
fi

python3 - <<'PY'
import json
import os
import re
import sys
import urllib.error
import urllib.request

env = os.environ.get
token = env("GITHUB_TOKEN")
repo = "{}/{}".format(env("CIRCLE_PROJECT_USERNAME"), env("CIRCLE_PROJECT_REPONAME"))
api = env("GITHUB_API_URL") or "https://api.github.com"
sha = env("CIRCLE_SHA1")

version = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", open("sshtunnel.py").read()).group(1)
tag = version


def call(method, path, data=None, ok_404=False):
    req = urllib.request.Request(
        api + path,
        method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        if e.code == 404 and ok_404:
            return None
        sys.exit("GitHub API {} {} failed: {} {}".format(method, path, e.code, e.read().decode()))


def release_notes():
    """Bullets of the `- v.X.Y.Z (...)` section of changelog.rst, as markdown."""
    lines = open("changelog.rst", encoding="utf-8").read().splitlines()
    head = re.compile(r"^- v\.{} ?\(".format(re.escape(version)))
    start = next((i for i, l in enumerate(lines) if head.match(l)), None)
    if start is None:
        return None
    notes = []
    for line in lines[start + 1:]:
        if line.startswith("- v."):
            break
        m = re.match(r"^\s+\+ (.*)$", line)
        if m:
            notes.append("- " + m.group(1))
    text = "\n".join(notes)
    # RST ``code`` -> markdown `code`
    text = re.sub(r"``([^`]+)``", r"`\1`", text)
    # `#123`_ -> link to the issue/PR
    text = re.sub(r"`#(\d+)`_", r"[#\1](https://github.com/{}/issues/\1)".format(repo), text)
    return text or None


if call("GET", "/repos/{}/releases/tags/{}".format(repo, tag), ok_404=True):
    print("Release {} already exists, nothing to do".format(tag))
    sys.exit(0)

notes = release_notes()
body = {
    "tag_name": tag,
    "target_commitish": sha,  # creates the tag on this commit if it does not exist
    "name": tag,
    "draft": False,
    "prerelease": False,
}
if notes:
    body["body"] = notes + "\n\nhttps://pypi.org/project/sshtunnel/{}/".format(version)
else:
    print("No section for v.{} in changelog.rst, generating the notes on GitHub".format(version))
    body["generate_release_notes"] = True

created = call("POST", "/repos/{}/releases".format(repo), body)
print("Created release {} ({}) on {}".format(tag, created["html_url"], sha[:7]))
PY
