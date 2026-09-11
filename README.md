# Rabi Local

Lets an agent work on **your own computer**, without opening anything on it.

Your machine dials out to the platform over HTTPS and holds that connection
open. Nothing listens for inbound connections, so NAT, home routers and
corporate firewalls are not in the way. Every command and every write is
approved by you first, and the agent can only reach one folder that you chose.

This repository is the Go implementation, plus the tray item that shows what it
is doing.

```
.                    the daemon: relay, tools, approvals, audit
cmd/menubar          the tray item (macOS menu bar, Windows system tray)
internal/            everything else, one package per concern
```

## Build

```bash
go build -o rabi .                  # the daemon
go build -o Rabi ./cmd/menubar      # the tray item
```

The daemon is pure Go and cross-compiles anywhere. The tray item is pure Go on
Windows and Linux, but on macOS it needs Cgo and Xcode Command Line Tools,
because the menu bar is Objective-C:

```bash
xcode-select --install
```

CI builds all of it. Grab the artifacts from the **build** workflow rather than
compiling by hand.

## The tray item

| Row | Shows | Click |
|---|---|---|
| Status | `Connected · 12m`, `Offline · <the daemon's own words>`, `Not running` | — |
| Machine | the name this computer is registered under | — |
| Folder | the one folder the agent may work in | opens the system folder picker |
| Sandbox | the container runtime and image | **the row is absent when there is none** |
| Toggle | `Pause` / `Start` | stops or starts the daemon |
| Open | the site this computer is paired with | opens a browser |

A single dot carries the state: green connected, amber connecting or retrying,
grey not running.

**The tray item is not the daemon.** It reads the same home directory and draws
it, so closing it does not take this computer offline.

```
~/.unieai/ava-local/machine.json   who this machine is, which folder, which sandbox
~/.unieai/ava-local/state.json     connection state, rewritten on every change
~/.unieai/ava-local/daemon.pid     is that process alive
```

Alive comes from the pid; connected comes from `state.json`. A daemon killed
with `SIGKILL` never gets to rewrite the state file, so it would sit at
`online` for ever — which is why the display always looks at the process first.

## Changing the folder

Writing `grantedRoot` into `machine.json` is not enough on its own: it is the
boundary the daemon loaded at startup, and every file tool checks paths against
it. Swapping it under a running daemon moves the fence in the middle of a turn.
So the tray item writes the file, stops the daemon and starts it again.

The browser does not need to be told. The daemon reports `grantedRoot` in its
`hello` on every connect, so the page shows the new one as soon as it is back.
Facts flow from the machine to the cloud, not the other way.

## Pausing

On a computer with start-at-login installed, killing the process is not enough:
launchd's `KeepAlive` and systemd's `Restart=always` bring it straight back, so
the user presses Pause, watches it stop, and then watches it light up again.
When a service is installed the toggle goes through that service instead.

## Tests

```bash
go test ./...
```

The redaction package is tested against a **differential corpus** shared with
the TypeScript implementation: both must produce the same output for the same
input, or the port does not mean anything. The corpus is generated over there
and copied into `internal/redact/testdata/`; the other side pins its hash, so
editing one without the other turns that build red.

Content and behaviour for the tray live in `internal/menubar/model.go` and
`actions.go`, which are portable and tested. The systray glue in `tray.go` only
draws. Put new decisions in the tested files.
