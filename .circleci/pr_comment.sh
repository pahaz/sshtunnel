#!/usr/bin/env bash
# Post (or update) a summary of the current CircleCI job as a pull request
# comment. Never fails the build: any problem just prints a note and exits 0.
#
# Needs GITHUB_TOKEN in the CircleCI project environment variables
# (fine-grained token for this repo with "Pull requests: Read and write").
# The log is collected by the `logged` command from config.yml in /tmp/ci.log,
# failed steps are listed in /tmp/ci-failed.
set -u

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "GITHUB_TOKEN is not set, skipping the PR comment"
  exit 0
fi

python3 - <<'PY' || echo "Could not post the PR comment (ignored)"
import json
import os
import re
import urllib.request

env = os.environ.get
token = env("GITHUB_TOKEN")
repo = "{}/{}".format(env("CIRCLE_PROJECT_USERNAME"), env("CIRCLE_PROJECT_REPONAME"))
api = env("GITHUB_API_URL") or "https://api.github.com"
marker = "<!-- circleci-report:{} -->".format(env("CIRCLE_JOB"))


def call(method, path, data=None):
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
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return json.loads(body) if body else None


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# Pull request number: from the env var, or by looking up the branch.
pr = (env("CIRCLE_PULL_REQUEST") or "").rstrip("/").rsplit("/", 1)[-1]
if not pr.isdigit():
    owner = env("CIRCLE_PROJECT_USERNAME")
    prs = call("GET", "/repos/{}/pulls?state=open&head={}:{}".format(
        repo, owner, env("CIRCLE_BRANCH")))
    pr = str(prs[0]["number"]) if prs else ""
if not pr:
    print("No open pull request for this build, skipping the PR comment")
    raise SystemExit(0)

failed = [x for x in read("/tmp/ci-failed").splitlines() if x]
log = read("/tmp/ci.log")
# never publish secrets
for name, value in os.environ.items():
    if value and len(value) > 5 and re.search(r"TOKEN|PASSWORD|SECRET|KEY", name):
        log = log.replace(value, "***")
lines = log.splitlines()
tail = "\n".join(lines[-80:])
if len(tail) > 50000:
    tail = tail[-50000:]

job = "{} (Python {})".format(env("CIRCLE_JOB"), env("PYTHON_VERSION", "")).replace(" (Python )", "")
sha = (env("CIRCLE_SHA1") or "")[:7]
if failed:
    status = "❌ failed at: " + ", ".join("`{}`".format(x) for x in failed)
else:
    status = "✅ passed"
body = "{}\n### CircleCI `{}`: {}\n\nCommit `{}` · [build #{}]({})\n".format(
    marker, job, status, sha, env("CIRCLE_BUILD_NUM"), env("CIRCLE_BUILD_URL"))
if failed:
    body += "\n<details open><summary>Last lines of the log</summary>\n\n```\n{}\n```\n\n</details>\n".format(tail)

# Update the previous comment of this job, if any.
existing = None
page = 1
while True:
    comments = call("GET", "/repos/{}/issues/{}/comments?per_page=100&page={}".format(repo, pr, page))
    for c in comments:
        if marker in c["body"]:
            existing = c["id"]
    if len(comments) < 100:
        break
    page += 1

if existing:
    call("PATCH", "/repos/{}/issues/comments/{}".format(repo, existing), {"body": body})
else:
    call("POST", "/repos/{}/issues/{}/comments".format(repo, pr), {"body": body})
print("PR comment posted")
PY
exit 0
