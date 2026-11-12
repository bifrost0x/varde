# 0008 Precision-first matching

Status: Accepted

## Context
A false alarm costs more trust than a missed low-severity advisory. Identification and version
detection are frequently uncertain (floating tags, missing labels, forks).

## Decision
Only `exact` or `strong` identifications with a known, comparable version can produce `affected`
findings and notifications. Unknown or incomparable versions yield `unverified`; weak
identifications require user confirmation. Both states are shown explicitly in the UI, never
silently dropped.

## Alternatives
- Recall-first ("possibly affected" alerts): typical scanner behaviour; produces the noise this
  product exists to remove.

## Consequences
Some real issues surface only as `unverified` until the user pins a version label. The UI must make
that state and the fix (the label to add) obvious.
