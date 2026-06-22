#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from urllib.parse import urlparse


SEMVER_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
RELEASE_COMMIT = re.compile(r"^chore\(release\):\s+")


def run_git(*args):
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def parse_tag(tag):
    match = SEMVER_TAG.match(tag)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def get_repo_name():
    repo = os.environ.get("GITHUB_REPOSITORY")
    if repo:
        return repo

    remote = run_git("remote", "get-url", "origin")
    if remote.startswith("git@"):
        return remote.split(":", 1)[1].removesuffix(".git")

    parsed = urlparse(remote)
    return parsed.path.strip("/").removesuffix(".git")


def get_previous_tag(current_tag):
    current_version = parse_tag(current_tag)
    if current_version is None:
        raise SystemExit(f"{current_tag} is not a vX.Y.Z tag")

    tags = []
    for tag in run_git("tag", "--list", "v[0-9]*").splitlines():
        version = parse_tag(tag)
        if version is not None and version < current_version:
            tags.append((version, tag))

    if not tags:
        return None

    return sorted(tags)[-1][1]


def revision_exists(revision):
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", revision],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def get_commits(previous_tag, current_tag):
    target = current_tag if revision_exists(current_tag) else "HEAD"
    revision_range = f"{previous_tag}..{target}" if previous_tag else target
    output = run_git(
        "log",
        "--reverse",
        "--pretty=format:%h%x09%s",
        revision_range,
    )

    commits = []
    for line in output.splitlines():
        if not line:
            continue
        short_sha, subject = line.split("\t", 1)
        if RELEASE_COMMIT.match(subject):
            continue
        commits.append((short_sha, subject))
    return commits


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_release_notes.py vX.Y.Z")

    current_tag = sys.argv[1]
    previous_tag = get_previous_tag(current_tag)
    repo = get_repo_name()
    version = current_tag.removeprefix("v")
    commits = get_commits(previous_tag, current_tag)

    print("## What's Changed")
    print()
    if commits:
        for short_sha, subject in commits:
            print(f"- {subject} (`{short_sha}`)")
    else:
        print("- Maintenance release.")

    print()
    print("## Docker Images")
    print()
    print(f"- `ghcr.io/{repo}:{current_tag}`")
    print(f"- `ghcr.io/{repo}:latest`")

    if previous_tag:
        print()
        print("## Full Changelog")
        print()
        print(f"https://github.com/{repo}/compare/{previous_tag}...{current_tag}")


if __name__ == "__main__":
    main()
