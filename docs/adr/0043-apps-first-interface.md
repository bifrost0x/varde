# 0043 An interface that starts from apps

Status: Accepted (the front page, the app pages, the three areas and the wording are built; the
pages below them keep their content)

## Context
The interface was built from Varde's own objects: findings, priorities P1 to P3, attack paths,
background noise, coverage. Five areas with eleven pages, and the overview led with counts of
findings and the words of the policy. A person who runs a homelab asks something else: which of
my apps do I have to update, to what, and how. The answer was there, but two or three pages down
and in a vocabulary that had to be learned first.

## Decision
- **The front page lists apps.** One card per app that needs something (a container, an
  installed app, the packages of a system), one quiet row for each that does not. A card says
  why it matters in one line, names the one version to install and what it fixes, and carries
  the image line to copy.
- **States are what a person does.** Update now, update soon, with the next update, check
  yourself; nothing found, nothing known, not checked. They map to the policy's priorities
  (P1, P2, P3, unverified) and to what a workload was checked against. The priorities remain
  the names of the policy, the notifications and the API; the pages show them as a tooltip.
- **An app has a page.** What to do as numbered steps (the line of its Compose service, the
  commands), why (urgency, exposure, version and where it comes from, the newest release), and
  the flaws behind it as a list that leads to each finding's evidence. Nobody has to read the
  flaws to update.
- **Three areas.** Apps (the front page, all containers, machines, gaps), Updates (the to-do
  list with filters, attack paths, background noise, history), Setup (connections, agents,
  settings, advisory data). Every earlier page keeps its address.
- **Depth stays, one step down.** Findings, evidence, attack paths and the audit trail are
  unchanged in content; they are details of an app, not the entrance.
- **One interface.** No simple and expert mode: two interfaces drift apart and double the care.

## Alternatives
- Keeping the structure and reducing text: the findings would stay the main object. Rejected.
- A simple and an expert mode behind a switch. Rejected for the reason above.

## Consequences
- The update of a card is chosen for the whole app: the version that fixes every finding of
  its highest priority, with what a newer major version would fix beyond it said beside it.
- Pages below the front page still speak of findings; their wording follows where it is
  touched. The screenshots in `docs/screenshots` show the earlier overview until they are taken
  again on a real installation.
