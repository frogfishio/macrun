# macrun

macrun is a macOS command-line tool for local development secrets.

It stores secret values in macOS Keychain, tracks non-secret metadata separately, and injects secrets into a child process only when you explicitly run a command.

If you want the convenience of environment variables without leaving plaintext `.env` files around your repo, this is the tool.

## Why Use It

Local secret handling tends to drift into one of a few bad patterns:

- large plaintext `.env` files copied between projects
- long-lived `export` commands in a shell session
- reusing the wrong project's credentials by accident
- handing every secret to every process whether it needs them or not

macrun is designed to tighten that up without trying to be a full secret platform.

It helps by:

- storing secret values in Keychain instead of repo files
- scoping secrets by project and profile
- importing from existing `.env` files when needed
- supporting selective injection with `--only` and `--prefix`
- keeping the main workflow centered on `macrun exec -- ...`

## What It Is Not

macrun is for local development on macOS. It is not a replacement for:

- Vault or another server-side secret manager
- CI/CD secret distribution
- production secret storage
- process sandboxing

If a process receives a secret, that process can still leak it. macrun reduces exposure before process start; it does not make an unsafe program safe.

## Install

From crates.io:

```bash
cargo install macrun
```

From this repository:

```bash
cargo install --path .
```

During development you can also run it directly:

```bash
cargo run -- doctor
```

To install the exact lockfile-resolved dependency set from a published release:

```bash
cargo install --locked macrun
```

## Quick Start

Initialize the current working tree:

```bash
macrun init --project my-app --profile dev
```

Import an existing `.env` file:

```bash
macrun import -f .env
```

List stored keys without printing values:

```bash
macrun list
```

Run a command with only the secrets it needs:

```bash
macrun exec --prefix APP_ -- cargo run
```

Or inject a specific subset:

```bash
macrun exec \
  --only APP_DATABASE_URL \
  --only APP_SESSION_SECRET \
  -- python3 server.py
```

## Mental Model

Each stored secret is identified by:

- project
- profile
- environment variable name

Example scope:

- project: `my-app`
- profile: `dev`
- key: `APP_DATABASE_URL`

When you run a command, macrun resolves the active project and profile, reads the selected values from Keychain, and injects them only into the child process you launched.

## Core Commands

Implemented today:

- `init`
- `set`
- `get`
- `import`
- `list`
- `exec`
- `env`
- `unset`
- `purge --yes`
- `doctor`
- `vault push`

Global flags:

- `--project NAME`
- `--profile NAME`
- `--json`

## Common Workflows

Set secrets manually:

```bash
macrun set APP_DATABASE_URL=postgres://localhost/appdb
macrun set APP_SESSION_SECRET=change-me API_TOKEN=replace-me
```

Read a specific value:

```bash
macrun get APP_DATABASE_URL
```

Import only a subset from a larger `.env` file:

```bash
macrun import -f .env --prefix APP_ --prefix API_
```

Inspect metadata:

```bash
macrun list --show-metadata
```

Print a machine-readable environment snapshot:

```bash
macrun env --format json --prefix APP_
```

Remove keys:

```bash
macrun unset APP_SESSION_SECRET API_TOKEN
```

## Project and Profile Resolution

macrun can resolve the active scope from a local config file named `.macrun.toml`.

Project resolution order:

1. explicit `--project`
2. `.macrun.toml` in the current directory or nearest ancestor
3. failure

Profile resolution order:

1. explicit `--profile`
2. `default_profile` from `.macrun.toml`
3. `dev`

That means a typical workflow is:

1. run `macrun init` once in a working tree
2. store or import secrets for that project
3. run local commands via `macrun exec`

## Storage Model

Secret values live in macOS Keychain.

The current Keychain layout uses:

- service: `macrun/<project>/<profile>`
- account: env var name

Non-secret metadata is stored in the app config directory so macrun can efficiently list entries and track source and update time.

## Vault Transit Support

macrun includes an optional Vault transit workflow.

`vault push` can:

1. read a secret from Keychain
2. encrypt it using Vault transit
3. optionally verify decrypt without printing plaintext

Example:

```bash
export VAULT_TOKEN=...

macrun vault push APP_CLIENT_SECRET \
  --vault-addr http://127.0.0.1:8200 \
  --vault-key app-secrets \
  --verify-decrypt
```

## Security Notes

macrun helps reduce:

- accidental commits of plaintext secret files
- broad shell-session contamination
- wrong-project and wrong-profile reuse
- oversharing secrets to processes that do not need them

It does not protect against:

- malware or a compromised user session
- root or admin compromise of the machine
- a child process that logs or forwards its environment
- terminal capture, clipboard leaks, or screen capture

## Documentation

- [USER_GUIDE.md](USER_GUIDE.md) for full usage and operational guidance
- [TODO.md](TODO.md) for implementation notes and future work

## Release Workflow

Typical release flow:

```bash
make bump
make dist
cargo publish
```

What those steps do:

- `make bump` increments [VERSION](VERSION)
- `make dist` increments [BUILD](BUILD), builds a release binary, and stages release artifacts in `dist/`
- `cargo publish` publishes the crate so users can install it with `cargo install macrun`

The staged distribution currently includes:

- `dist/bin/macrun`
- `dist/USER_GUIDE.md`
- `dist/README.md`
- `dist/LICENSE`

`BUILD` is intentionally included in the published crate source because the binary reads both [VERSION](VERSION) and [BUILD](BUILD) at compile time to produce the custom `--version` output.

## License

GPL-3.0-or-later

Copyright (c) Alexander R. Croft