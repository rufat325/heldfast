# Moving the feed's collector off GitHub Actions

The collector is `.github/workflows/feed.yml`. This folder is the same work
as a program you run on your own machine: `run.py`, plus systemd timers in
`systemd/`. It exists so that if GitHub ever restricts or disables the
crawler, moving takes a day rather than leaving a gap in the record. Until
then it stays unused: nothing here is deployed, and the timers are not
enabled.

Everything below is free. Nothing here needs a payment method.

## Before anything: never two collectors at once

Two collectors writing to `rufat325/heldfast-feed` make conflicting commits,
and the record then disagrees with itself. **Disable the schedule in
`feed.yml` before enabling a single timer here**: on GitHub, Actions →
feed → ⋯ → Disable workflow. Do the reverse when moving back.

## Where to move it

- **Oracle Cloud Always Free.** An Arm VM, free with no end date. Since June
  2026 it has 2 Arm cores and 12 GB of RAM, down from 4 and 24; the cut was
  made without announcement, so check what the offer is when you sign up.
  Free Arm capacity is not guaranteed in every region, sign-up may ask for a
  card to verify your identity, and software built only for x86 may not run.
  Enough for the hosted readings; for npm measuring, give `measure` a smaller
  `--budget` (40 launches per shard is a start) and check the run finishes
  within a day. The image builds for Arm (checked on 27 September 2026 with
  `docker buildx build --platform linux/arm64`). Which watched servers fail
  to install or start on Arm has not been measured yet: do it on the Arm
  machine before switching, by running `measure` with a fresh state against
  the daily servers and comparing with a day of the Actions feed. Servers
  that ship x86-only native binaries are the ones to expect there.
- **A dedicated old computer.** Never your main machine: `measure` runs
  unreviewed npm packages, in a container, and a container is not a
  security boundary you should bet your own files on. No personal files or
  accounts on it, and ideally on a separate network, such as guest Wi-Fi.
  Power and internet outages leave gaps in the record, and the watchdog will
  say so.
- **Never a self-hosted GitHub Actions runner on this public repository.**
  Pull requests from strangers can end up running code on it.

## Setting a machine up

Debian or Ubuntu with systemd, Docker, git and Python 3.9 or later. Linux,
not Windows: the feed holds paths longer than Windows allows and two that
differ only in letter case, so a Windows checkout silently loses one and
would commit its deletion. `run.py` refuses to start there. On a Windows
computer, a dry run works under WSL (Ubuntu), which has a Linux file system
and uses Docker Desktop.

1. **Users.** One per credential, so no third-party code shares a user with
   the push credential:
   ```bash
   sudo groupadd heldfast
   for u in heldfast-measure heldfast-publish heldfast-anchor heldfast-mirror; do
     sudo useradd --system --create-home --gid heldfast "$u"
   done
   sudo usermod -aG docker heldfast-measure
   ```
   Membership of the `docker` group is equivalent to root on that machine.
   Prefer [rootless Docker](https://docs.docker.com/engine/security/rootless/)
   for `heldfast-measure` where you can; `run.py` passes the same
   `--cap-drop ALL`, `no-new-privileges`, memory, CPU and PID limits and
   `--user` either way.
2. **The code.** `sudo git clone https://github.com/rufat325/heldfast /opt/heldfast`,
   owned by root and readable by all. Everything runs the code from here, and
   nothing a measured server wrote is ever executed.
3. **The state.** `/var/lib/heldfast-feed`, group `heldfast`, mode `2770`.
   Clone the feed there as the publishing user:
   ```bash
   sudo install -d -o heldfast-publish -g heldfast -m 2770 /var/lib/heldfast-feed
   sudo -u heldfast-publish git clone https://github.com/rufat325/heldfast-feed /var/lib/heldfast-feed/feed
   ```
4. **The push credential**, readable by `heldfast-publish` alone: a
   fine-grained token for `rufat325/heldfast-feed` with Contents read and
   write (the `FEED_TOKEN` of the Actions setup, or a new one), stored with
   `git config credential.helper store` in that user's home, mode `0600`.
5. **The third-party clients**, each in its own virtual environment, from the
   hash-pinned files, owned by root:
   ```bash
   sudo python3 -m venv /opt/heldfast-venvs/ots
   sudo /opt/heldfast-venvs/ots/bin/pip install --require-hashes --only-binary :all: \
     -r /opt/heldfast/research/feed/anchor-requirements.txt
   sudo python3 -m venv /opt/heldfast-venvs/hf
   sudo /opt/heldfast-venvs/hf/bin/pip install --require-hashes --only-binary :all: \
     -r /opt/heldfast/research/feed/mirror-requirements.txt
   ```
   The OpenTimestamps client runs as `heldfast-anchor` and huggingface_hub as
   `heldfast-mirror`. Neither user can read the push credential.
6. **The Hugging Face token**: `/etc/heldfast-feed/hf.env` containing
   `HF_TOKEN=...`, owned by `heldfast-mirror`, mode `0600`.
7. **The image**: `sudo -u heldfast-measure docker build -f
   /opt/heldfast/research/feed/Dockerfile -t heldfast-feed /opt/heldfast`
   (on Arm: the same, or `docker buildx build --platform linux/arm64 --load`).
8. **Try it** before enabling anything:
   ```bash
   python3 /opt/heldfast/research/feed/server/run.py dry-run --npm 3 --hosted 5
   ```
   It clones the feed into a temporary folder, watches three npm servers and
   five hosted endpoints, measures them in the container, admits, renders,
   checkpoints and verifies, and pushes nothing. It must end with `dry run
   complete`.
9. **Switch over.** Disable `feed.yml`'s schedule on GitHub first. Then:
   ```bash
   sudo cp /opt/heldfast/research/feed/server/systemd/* /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now heldfast-feed-measure.timer heldfast-feed-busy.timer heldfast-feed-sync.timer
   ```

## What runs when

The timers are `feed.yml`'s schedule: daily at 06:23 UTC, the busy pass at
minute 43 of every fourth hour, the watchlist on Mondays at 05:03 UTC. Each
phase is its own service, run as its own user, and each starts the next only
if it succeeded (`OnSuccess=`):

| service | user | does | reads a credential |
|---|---|---|---|
| measure | heldfast-measure | one container per shard, on a throwaway clone | none |
| publish | heldfast-publish | admit, verify, fold, render, verify, commit, push, checkpoint | push |
| anchor | heldfast-anchor | OpenTimestamps: stamp, upgrade | none |
| record | heldfast-publish | admit the stamps, commit, push | push |
| archive | heldfast-mirror | pack what the mirror lacks | none |
| mirror | heldfast-mirror | upload to Hugging Face | Hugging Face |

Every phase holds `/var/lib/heldfast-feed/lock` through `flock`, so a busy
pass never starts inside a daily run, and the reverse.

Not carried over: the Sigstore witness. Keyless signing needs the identity
token only GitHub Actions issues; the Bitcoin anchor does not depend on it.
The watchdog keeps running from the feed repository wherever the collector is.

## Moving back

Disable the timers (`sudo systemctl disable --now heldfast-feed-*.timer`),
make sure no phase is running (`systemctl list-units 'heldfast-feed-*'`),
then enable `feed.yml` on GitHub again. The feed repository is the state:
either collector picks up from its last commit.
