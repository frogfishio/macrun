# macrun

macrun is a macOS command-line tool for local development secrets.

It stores secret values in macOS Keychain, tracks non-secret metadata separately, and injects secrets into a child process only when you explicitly run a command.

If you want the convenience of environment variables without leaving plaintext `.env` files around your repo, this is the tool.

It also works with sensible defaults, so common usage does not require setup first.

## Why Use It

Local secret handling tends to drift into one of a few bad patterns:

- large plaintext `.env` files copied between projects
- long-lived `export` commands in a shell session
- reusing the wrong project's credentials by accident
- handing every secret to every process whether it needs them or not

macrun is designed to tighten that up without trying to be a full secret platform.

It helps by:

- storing secret values in Keychain instead of repo files
- scoping secrets by project and env
- importing from existing `.env` files when needed
- keeping the main workflow centered on whole-scope `macrun exec -- ...`

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

Store a value in the default project and default env:

```bash
macrun set URL=https://somewhere
```

Store a value in a named env while keeping the default project:

```bash
macrun set --env staging URL=https://staging.example.com
```

Initialize the current working tree:

```bash
macrun init --project my-app --env dev
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
macrun exec -- cargo run
```

Run a command with one secret replaced by Vault Transit ciphertext:

```bash
macrun exec \
  --vault-encrypt APP_CLIENT_SECRET=APP_CLIENT_SECRET_CIPHERTEXT \
  --vault-addr http://127.0.0.1:8200 \
  --vault-key app-secrets \
  -- myapp
```

Print the full resolved environment for the active project/env:

```bash
macrun env --format json
```

## Mental Model

Each stored secret is identified by:

- project
- env
- environment variable name

Example scope:

- project: `my-app`
- env: `dev`
- key: `APP_DATABASE_URL`

When you run a command, macrun resolves the active project and env, reads every stored value for that scope from Keychain, and injects them into the child process you launched.

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
- `vault encrypt`
- `vault push`

Global flags:

- `--project NAME`
- `--env NAME`
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

Import a dotenv file into the active scope:

```bash
macrun import -f .env
```

Inspect metadata:

```bash
macrun list --show-metadata
```

Print a machine-readable environment snapshot:

```bash
macrun env --format json
```

Remove keys:

```bash
macrun unset APP_SESSION_SECRET API_TOKEN
```

## Project and Env Resolution

macrun can resolve the active scope from a local config file named `.macrun.toml`.

Project resolution order:

1. explicit `--project`
2. `.macrun.toml` in the current directory or nearest ancestor
3. internal default project scope

Env resolution order:

1. explicit `--env`
2. `default_env` from `.macrun.toml`
3. `dev`

That means a typical workflow is:

1. run `macrun init` once in a working tree
2. store or import secrets for that project
3. run local commands via `macrun exec`

If you do not initialize a working tree, `macrun` falls back to:

1. project: `(default)`
2. env: `dev`

So commands like `macrun set URL=https://somewhere` work immediately.

`(default)` is a display label for the fallback project scope, not a literal project name. If you run `macrun --project default ...`, the project name is exactly `default`.

## Storage Model

Secret values live in macOS Keychain.

The current Keychain layout uses:

- service: `macrun/<project>/<env>`
- account: env var name

Non-secret metadata is stored in the app config directory so macrun can efficiently list entries and track source and update time.

## Vault Bootstrap Transfer

macrun's Vault support exists for bootstrap transfer, not day-to-day runtime secret serving.

The useful cases are:

1. get Vault Transit ciphertext for an app that must store a key in its database
2. write one or more secrets into Vault KV so the app fetches them from Vault directly

### Transit ciphertext for app storage

`vault encrypt` reads a plaintext secret from Keychain, sends it to Vault Transit, and prints the ciphertext.

That ciphertext can then be stored in an application database or handed to an admin API. At runtime, the app asks Vault to decrypt it and keeps plaintext only in memory.

If the app is being bootstrapped directly from `macrun exec`, you can also replace a plaintext env var with Transit ciphertext in the child process:

```bash
macrun exec \
  --vault-encrypt APP_CLIENT_SECRET=APP_CLIENT_SECRET_CIPHERTEXT \
  --vault-addr http://127.0.0.1:8200 \
  --vault-key app-secrets \
  -- myapp
```

In that mode, macrun removes `APP_CLIENT_SECRET` from the child environment and injects `APP_CLIENT_SECRET_CIPHERTEXT` instead.

That removal is intentional. The bootstrap target process should receive ciphertext only, not both plaintext and ciphertext.

Example:

```bash
export VAULT_TOKEN=...

macrun vault encrypt APP_CLIENT_SECRET \
  --vault-addr http://127.0.0.1:8200 \
  --vault-key app-secrets \
  --verify-decrypt
```

### Vault KV as the source of truth

`vault push` reads one or more plaintext secrets from Keychain and writes them into Vault KV.

Example:

```bash
export VAULT_TOKEN=...

macrun vault push APP_CLIENT_SECRET API_TOKEN \
  --vault-addr http://127.0.0.1:8200 \
  --mount secret \
  --path apps/my-app/dev \
  --kv-version v2
```

## Security Notes

macrun helps reduce:

- accidental commits of plaintext secret files
- broad shell-session contamination
- wrong-project and wrong-env reuse
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