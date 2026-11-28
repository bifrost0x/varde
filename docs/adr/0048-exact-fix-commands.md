# 0048 The exact way to apply a fix, never applied by Varde

Status: Accepted

## Context
Varde knows how each workload was deployed: the Compose labels name the project, the service,
the project directory and the files; Portainer keeps the files of its stacks in its own volume
(`/data/compose/<id>`); Unraid's Docker manager labels its containers; a container without such
labels was started with `docker run`; the packages of a host come with their package manager,
and a Proxmox LXC container with its node and VMID. The pages still said "Then run in <dir>"
with a command that ignored the project name and any second Compose file, offered a Compose
command for Portainer stacks whose files are not on the host, and named a generic `apt upgrade`
for a host.

## Decision
- **One way per workload, in the terms of what deployed it.** Compose: one command that runs
  from any directory (`cd` to the project directory, `-p` and `-f` where they differ from what
  Compose assumes there). Portainer: the stack and the clicks (Editor, Update the stack with
  re-pull); no command. Unraid: the Docker page's Edit or Force update. `docker run`: the pull of
  the new image and the instruction to recreate the container with its own options; Varde does
  not see all of them (environment, restart policy), so it writes no run command that could
  silently drop one. An image built on the host: the rebuild (ADR 0045 amendment). Host
  packages: the package manager's command for exactly the installed packages an update fixes,
  the kernel image packages when a kernel is among them, through `sudo`, and for an LXC container
  also through `pct exec` on its node.
- **Varde runs nothing.** It shows commands and clicks; it never calls Portainer, Docker, SSH or
  WebSSH to apply them, and stores no credential for that. It stays read-only (ADR 0006, ADR 0020).
- **WebSSH as the way to a shell.** With the address of the user's WebSSH set
  (`VARDE_WEBSSH_URL` or Settings), every command offers "Copy and open WebSSH": the command goes
  to the clipboard and WebSSH opens in a new tab, where the user connects and pastes; nothing
  runs until they press Enter. Without the address, one line under a command names WebSSH and
  where to set it.

## Alternatives
- Applying updates from Varde (Portainer API or webhooks, SSH, the Docker API): one click, but a
  Varde that writes to every host is the target ADR 0006 avoids. Rejected.
- A WebSSH link that opens a session to the host with the command filled in: needs a WebSSH
  feature (a connect link with a command shown for confirmation, never sent with a newline).
  Planned there; the clipboard works with every WebSSH today.
- A reconstructed `docker run` command: Varde does not see every option, and a command that
  drops the environment or the restart policy would change the container without saying so.

## Consequences
- Commands are built only from validated labels, paths and package names and are shell-quoted;
  an invalid name never reaches a command.
- A Portainer stack deployed from Git is updated in Git; the page's clicks fit stacks edited in
  Portainer's editor.
- The WebSSH link is plain navigation to an address the user set; the clipboard needs a secure
  context (HTTPS or localhost). Over plain HTTP the page selects the command instead.
