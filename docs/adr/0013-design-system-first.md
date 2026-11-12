# 0013 Brand and design system before UI work

Status: Accepted

## Context
Visual quality matters for adoption. Retrofitting a design onto finished pages is
expensive and produces inconsistency.

## Decision
Logo, colour tokens, typography scale, icon sprite and core components are defined before the first
page; pages are built from the tokens and components only. Guiding concept: a
calm, dark interface where the ember accent appears only while a P1 finding exists. See
`docs/brand.md`.

## Alternatives
- A CSS framework (Pico, Bootstrap): faster start, generic look, extra dependency.

## Consequences
Pages use tokens only, no ad-hoc colours. Contrast of token pairs is verified by a test.
