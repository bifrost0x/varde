#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Renders PNG exports of the brand SVGs. Requires rsvg-convert (librsvg) and
# the Inter font (Debian: librsvg2-bin fonts-inter). Output is committed so
# the repository does not depend on these tools.
set -eu

cd "$(dirname "$0")/../assets/brand"

rsvg-convert -w 1280 -h 640 social-preview.svg -o social-preview.png
rsvg-convert -w 500 -h 500 avatar.svg -o avatar.png
rsvg-convert -w 512 -h 512 mark.svg -o mark-512.png
rsvg-convert -w 512 -h 512 badge.svg -o badge-512.png
rsvg-convert -w 180 -h 180 -b '#0E1318' badge.svg -o apple-touch-icon.png
rsvg-convert -w 32 -h 32 favicon.svg -o favicon-32.png
