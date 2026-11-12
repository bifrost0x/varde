#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Publishes a built data package: one commit that holds exactly feed/,
# the builder's store and its signature, pushed over the branch "data". The
# branch never grows: every build replaces it. Run from inside a checkout of
# the repository.
#
#   scripts/publish-data.sh <work-dir>
#
# <work-dir> holds feed/ (written by cmd/packagebuilder) and
# cache/builder.db (the builder's store, kept for the next build).
#
# The store is published compressed, as cache/builder.db.gz. It holds the
# full text of public advisories, and those quote example and leaked
# credentials in their proofs of concept; as plain text on a branch they
# raise a secret-scanning alert with every build. The signature stays the
# one over the uncompressed store.
# PUBLISH_REMOTE (default origin) and PUBLISH_BRANCH (default data) name
# the destination.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <work-dir>" >&2
  exit 2
fi
work="$(cd "$1" && pwd)"
remote="${PUBLISH_REMOTE:-origin}"
branch="${PUBLISH_BRANCH:-data}"

if [[ "${branch}" == "main" || "${branch}" == "master" ]]; then
  echo "refusing to publish over ${branch}" >&2
  exit 1
fi
for needed in feed/v1/manifest.json feed/v1/manifest.json.sig feed/v1/root.json feed/stats.json feed/stats.json.sig cache/builder.db cache/builder.db.sig; do
  if [[ ! -f "${work}/${needed}" ]]; then
    echo "${needed} is missing from ${work}: nothing published" >&2
    exit 1
  fi
done

index_file="$(mktemp)"
trap 'rm -f "${index_file}"' EXIT
rm -f "${index_file}" # git wants to create it itself
export GIT_INDEX_FILE="${index_file}"
export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-github-actions[bot]}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-${GIT_AUTHOR_NAME}}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-${GIT_AUTHOR_EMAIL}}"

# -n: no name and no timestamp, the same store gives the same file.
gzip -9 -n -c "${work}/cache/builder.db" > "${work}/cache/builder.db.gz"

# -f: the repository's .gitignore is about the source tree, not about this.
git --work-tree="${work}" add -f -- feed cache/builder.db.gz cache/builder.db.sig
tree="$(git write-tree)"
sequence="$(sed -n 's/^ *"sequence": *\([0-9][0-9]*\).*/\1/p' "${work}/feed/stats.json" | head -n 1)"
commit="$(git commit-tree "${tree}" -m "data: package ${sequence:-unknown}")"
git push --force "${remote}" "${commit}:refs/heads/${branch}"
echo "published package ${sequence:-unknown} as ${commit} on ${branch}"
