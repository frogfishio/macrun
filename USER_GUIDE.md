# macrun User Guide

This guide covers the day-to-day use of macrun as a local development secrets tool for macOS.

It focuses on the current CLI as implemented in this repository and avoids assumptions about any larger parent project.

## 1. Overview

macrun stores local development secrets in macOS Keychain and injects them into a child process only when you explicitly ask it to.

It is built around three ideas:

- keep secret values out of repo files by default
- scope secrets by project and profile
- inject only the keys a process actually needs

## 2. What macrun Is For

Good fit:

- local app development on macOS
- moving away from plaintext `.env` files
- separating secrets between projects
- separating secrets between profiles such as `dev` and `staging`
- selectively injecting keys into a process

Not a fit:

- production secret storage
- CI/CD secret handling
- cross-machine secret synchronization
- replacing Vault or another server-side secret manager
- defending against a malicious process once it has received a secret

## 3. Installation

Install from crates.io:

```bash
cargo install macrun
```

Install from this repository:

```bash
cargo install --path .
```

Or run during development without installing:

```bash
cargo run -- doctor
```

## 4. Command Summary

Current commands:

- `init`
- `set`
- `get`
- `import`
- `list`
- `exec`
- `env`
- `unset`
- `purge`
- `vault push`
- `doctor`

Global flags:

- `--project NAME`
- `--profile NAME`
- `--json`

## 5. Scope Resolution

Every secret belongs to a scope:

- project
- profile
- env var name

Example:

- project: `my-app`
- profile: `dev`
- key: `APP_DATABASE_URL`

macrun resolves scope this way.

Project resolution order:

1. explicit `--project`
2. local `.macrun.toml` in the current directory or nearest ancestor
3. failure

Profile resolution order:

1. explicit `--profile`
2. `default_profile` from `.macrun.toml`
3. `dev`

This is why `macrun init` is usually the first command you run in a project.

## 6. Initialize a Working Tree

Create `.macrun.toml` in the current directory:

```bash
macrun init --project my-app --profile dev
```

That file binds the working tree to a default scope.

If you need to overwrite an existing file:

```bash
macrun init --project my-app --profile dev --force
```

The generated config is a small TOML file with the project name and default profile.

## 7. Store Secrets

Store one value:

```bash
macrun set APP_DATABASE_URL=postgres://localhost/myapp
```

Store several at once:

```bash
macrun set APP_SESSION_SECRET=replace-me API_TOKEN=replace-me-too
```

Attach metadata for future listing:

```bash
macrun set APP_SESSION_SECRET=replace-me --source manual --note "created for local testing"
```

Rules for names:

- names must be valid environment variable names
- names may contain letters, digits, and `_`
- names may not start with a digit

## 8. Read and Remove Secrets

Read one value:

```bash
macrun get APP_DATABASE_URL
```

Remove one or more values:

```bash
macrun unset APP_DATABASE_URL
macrun unset APP_SESSION_SECRET API_TOKEN
```

`get` is best treated as an explicit inspection tool. For normal usage, `exec` is safer because it only hands secrets to the process you are launching.

## 9. Import From an Existing .env File

Import a file:

```bash
macrun import -f .env
```

Overwrite existing keys intentionally:

```bash
macrun import -f .env --replace
```

Import only selected prefixes:

```bash
macrun import -f .env --prefix APP_ --prefix API_
```

The importer currently accepts plain lines in these forms:

- `KEY=value`
- `export KEY=value`

It skips:

- blank lines
- comment lines starting with `#`

It does not attempt to behave like a full shell parser, so complex shell syntax should be cleaned up before import.

Suggested migration pattern:

1. import the existing `.env`
2. verify with `macrun list`
3. switch local commands to `macrun exec`
4. remove or stop relying on the plaintext file

## 10. List What Is Stored

List keys only:

```bash
macrun list
```

List only a subset by prefix:

```bash
macrun list --prefix APP_
```

Show metadata such as source and update time:

```bash
macrun list --show-metadata
```

By default, `list` does not print secret values.

## 11. Print a Machine-Readable Environment

Shell output:

```bash
macrun env --format shell --prefix APP_
```

JSON output:

```bash
macrun env --format json --only APP_DATABASE_URL
```

This command is most useful for inspection, scripting, and debugging.

The safer default for interactive work is still to use `exec` rather than exporting secrets into your parent shell.

## 12. Run Commands With Injected Secrets

This is the main workflow.

Inject all keys that share a prefix:

```bash
macrun exec --prefix APP_ -- cargo run
```

Inject an explicit set of keys:

```bash
macrun exec \
  --only APP_DATABASE_URL \
  --only APP_SESSION_SECRET \
  -- node server.js
```

Run a non-Rust command:

```bash
macrun exec --prefix APP_ -- python3 manage.py runserver
```

Behavior to expect:

- the selected keys are loaded from Keychain
- the child process inherits the normal parent environment plus the selected secret values
- macrun prints a short scope summary to stderr before launching
- the child process exit code is returned unchanged when possible

If no keys match your selection, `exec` fails rather than silently running with an empty secret set.

## 13. Use Multiple Profiles

Profiles let you keep separate local contexts inside one project.

Examples:

- `dev`
- `test`
- `staging`
- `customer-a`

Store different values under different profiles:

```bash
macrun --project my-app --profile dev set APP_DATABASE_URL=postgres://localhost/devdb
macrun --project my-app --profile staging set APP_DATABASE_URL=postgres://localhost/stagingdb
```

Run against a specific profile:

```bash
macrun --project my-app --profile staging exec --prefix APP_ -- cargo run
```

Profiles are useful when the variable names stay the same but the actual endpoints or credentials change.

## 14. Purge a Scope

Remove every indexed secret for the active project and profile:

```bash
macrun purge --yes
```

This is intentionally destructive. Without `--yes`, the command fails and asks for explicit confirmation by re-running it.

## 15. Check Local State

Run:

```bash
macrun doctor
```

`doctor` reports useful context such as:

- current working directory
- whether a local `.macrun.toml` was found
- the resolved project and profile, if any
- the local state directory
- the index path
- how many secrets are indexed overall and in the current scope

If you are unsure why a command cannot resolve a project or profile, start with `doctor`.

## 16. Storage Details

The current implementation stores secret values in macOS Keychain using:

- service: `macrun/<project>/<profile>`
- account: env var name

macrun also stores non-secret metadata in its local application config directory. That metadata powers commands such as `list`, `unset`, `purge`, and scoped selection.

## 17. Security Model

macrun helps reduce these common local-development failures:

- committing plaintext `.env` files
- leaving sensitive values in repo-local files
- contaminating a long-lived shell session with broad exports
- mixing up projects or profiles
- oversharing secrets to commands that do not need them

It does not protect you from:

- malware already running as your user
- root or admin compromise
- a child process that logs or forwards secrets
- terminal capture, clipboard leaks, or screen recording

The rule is simple: once a process receives a secret, that process is part of your trust boundary.

## 18. Vault Transit Workflow

macrun includes a Vault transit integration through `vault push`.

That workflow:

1. reads a plaintext secret from Keychain
2. encrypts it with Vault transit
3. can verify decrypt without printing plaintext

Vault authentication currently uses `VAULT_TOKEN` from the environment.

Example:

```bash
export VAULT_TOKEN=...

macrun vault push APP_CLIENT_SECRET \
  --vault-addr http://127.0.0.1:8200 \
  --transit-path transit \
  --vault-key app-secrets \
  --verify-decrypt
```

## 19. Vault Over an SSH Tunnel

macrun does not create or manage SSH tunnels itself.

If your Vault endpoint is reachable only through a bastion or private network, open the tunnel separately and point `--vault-addr` at the local forwarded port.

Example:

```bash
ssh -L 18200:vault.internal:8200 user@bastion
```

Then in another shell:

```bash
export VAULT_TOKEN=...

macrun vault push APP_CLIENT_SECRET \
  --vault-addr http://127.0.0.1:18200 \
  --vault-key app-secrets \
```

If the remote Vault endpoint expects HTTPS with a certificate valid only for its original hostname, forwarding to `127.0.0.1` may cause hostname validation failures. That is a transport configuration issue rather than a macrun-specific behavior.

## 20. Recommended Usage Patterns

Good patterns:

- initialize each working tree once with `macrun init`
- keep local secrets in Keychain instead of repo files
- use profiles to separate materially different contexts
- inject only the keys a command needs
- use `doctor` when scope resolution is unclear

Patterns to avoid:

- exporting your entire secret set into a long-lived shell session
- keeping large plaintext `.env` files around after import
- sharing one profile across unrelated environments

## 21. Troubleshooting

`no project resolved`

- run `macrun doctor`
- check whether `.macrun.toml` exists in the current directory or an ancestor
- pass `--project` explicitly if needed

`requested secret(s) not found`

- verify the key names with `macrun list`
- check whether you selected the wrong profile
- confirm your `--only` or `--prefix` filters match stored keys

`import` fails on a line in `.env`

- simplify the source file to plain `KEY=value` lines
- remove shell constructs the importer does not understand
- retry with a smaller file if needed

`VAULT_TOKEN is required`

- export `VAULT_TOKEN` before using `macrun vault push`

`purge` refuses to run

- re-run with `--yes` if you really intend to destroy the current scope