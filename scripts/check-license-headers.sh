#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Fails if a tracked or staged source file lacks an SPDX license identifier
# within its first five lines.
set -eu

cd "$(git rev-parse --show-toplevel)"

missing=0
for f in $(git ls-files --cached --others --exclude-standard \
	'*.go' '*.sh' '*.sql' '*.html' '*.css' '*.js' 'Makefile' 'Dockerfile'); do
	[ -f "$f" ] || continue
	case "$f" in
	testdata/* | */testdata/*) continue ;;
	# Vendored third-party files keep their own license (see NOTICE).
	*/vendor/*) continue ;;
	esac
	if ! head -n 5 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0'; then
		echo "missing SPDX header: $f"
		missing=1
	fi
done

if [ "$missing" -ne 0 ]; then
	echo "add '// SPDX-License-Identifier: Apache-2.0' (or the comment syntax of the file type)" >&2
	exit 1
fi
