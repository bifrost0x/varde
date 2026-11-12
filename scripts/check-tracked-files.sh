#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fails when the repository tracks a file of a kind that never belongs in
# it: private keys, environment files, databases, local state, working
# files of tools. .gitignore keeps them out of "git add"; this catches
# "git add -f" and a .gitignore that was edited.
#
# It also reads the commit messages of the history it is given: a link to
# a private working session of a coding assistant is not for a public
# repository.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

forbidden='(^|/)\.env($|\.)|\.(pem|key|p12|pfx|jks|kdbx|db|db-wal|db-shm|sqlite3|log|tmp|swp)$|(^|/)id_(rsa|ed25519|ecdsa)(\.pub)?$|_token$|(^|/)(secrets|dev-keys|\.superpowers|\.claude|\.idea|\.vscode|\.cache|published|work)/|(^|/)\.DS_Store$|(^|/)CLAUDE(\.local)?\.md$'
# Fixtures the tests need, and the example of an environment file.
allowed='^deploy/\.env\.example$|/testdata/'

bad="$(git ls-files | grep -E "${forbidden}" | grep -vE "${allowed}" || true)"
if [[ -n "${bad}" ]]; then
  echo "these tracked files must not be in the repository:" >&2
  echo "${bad}" >&2
  exit 1
fi

# A private key in any text file, wherever it is. The tests use a
# placeholder body ("AAAA"); a real key has a longer one.
if git grep -InE -A1 -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' -- . | grep -E -e '-[0-9]+-[A-Za-z0-9+/=]{40,}$' >/dev/null; then
  echo "a tracked file holds what looks like a private key" >&2
  exit 1
fi
# Commit messages (the whole history in CI, which checks out all of it).
if git log --format=%B | grep -nE 'claude\.ai/code/session|chatgpt\.com/(c|codex)/|session_[0-9A-Za-z]{16,}' >/dev/null; then
  echo "a commit message links a private working session:" >&2
  git log --format='%h %s' --grep='claude\.ai/code/session' --grep='chatgpt\.com/' --grep='session_[0-9A-Za-z]\{16,\}' >&2
  exit 1
fi
echo "tracked files and commit messages: ok ($(git ls-files | wc -l) files, $(git rev-list --count HEAD) commits)"
