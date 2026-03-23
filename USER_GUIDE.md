# macrun User Guide

This guide covers the day-to-day use of macrun as a local development secrets tool for macOS.

It focuses on the current CLI as implemented in this repository and avoids assumptions about any larger parent project.

## 1. Overview

macrun stores local development secrets in macOS Keychain and injects them into a child process only when you explicitly ask it to.

It is built around three ideas:

- keep secret values out of repo files by default
- scope secrets by project and env
- keep each project/env scope internally coherent

It also has usable fallback defaults, so basic commands can work without a setup step.

## 2. What macrun Is For

Good fit:

- local app development on macOS
- moving away from plaintext `.env` files
- separating secrets between projects
- separating secrets between envs such as `dev` and `staging`
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
- `vault encrypt`
- `vault push`
- `doctor`

Global flags:

- `--project NAME`
- `--env NAME`
- `--json`

## 5. Scope Resolution

Every secret belongs to a scope:

- project
- env
- env var name

Example:

- project: `my-app`
- env: `dev`
- key: `APP_DATABASE_URL`

macrun resolves scope this way.

Project resolution order:

1. explicit `--project`
2. local `.macrun.toml` in the current directory or nearest ancestor
3. internal default project scope

Env resolution order:

1. explicit `--env`
2. `default_env` from `.macrun.toml`
3. `dev`

If no explicit flag or local config is present, the fallback scope is:

1. project: `(default)`
2. env: `dev`

This means `macrun set URL=https://somewhere` works even before you run `init`.

`(default)` is just how macrun displays the fallback project scope. It is not a reserved user-facing project name, so `macrun --project default ...` still means the literal project `default`.

## 6. Initialize a Working Tree

Create `.macrun.toml` in the current directory:

```bash
macrun init --project my-app --env dev
```

That file binds the working tree to a default scope.

If you need to overwrite an existing file:

```bash
macrun init --project my-app --env dev --force
```

The generated config is a small TOML file with the project name and default env.

`init` is optional. It is useful when you want the current working tree to resolve to a non-default project or env automatically.

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

Show metadata such as source and update time:

```bash
macrun list --show-metadata
```

By default, `list` does not print secret values.

## 11. Print a Machine-Readable Environment

Shell output:

```bash
macrun env --format shell
```

JSON output:

```bash
macrun env --format json
```

This command is most useful for inspection, scripting, and debugging.

The safer default for interactive work is still to use `exec` rather than exporting secrets into your parent shell.

## 12. Run Commands With Injected Secrets

This is the main workflow.

Inject the entire active scope:

```bash
macrun exec -- cargo run
```

Run a non-Rust command:

```bash
macrun exec -- python3 manage.py runserver
```

Bootstrap an app with Vault Transit ciphertext instead of plaintext for one key:

```bash
macrun exec \
  --vault-encrypt APP_CLIENT_SECRET=APP_CLIENT_SECRET_CIPHERTEXT \
  --vault-addr http://127.0.0.1:8200 \
  --vault-key app-secrets \
  -- myapp
```

Behavior to expect:

- every key in the current scope is loaded from Keychain
- the child process inherits the normal parent environment plus every secret value in that scope
- macrun prints a short scope summary to stderr before launching
- the child process exit code is returned unchanged when possible

When `--vault-encrypt` is used:

- macrun reads the named plaintext secret from Keychain
- encrypts it with Vault Transit before launching the child process
- removes the plaintext source variable from the child environment
- injects the ciphertext under the destination variable name

`SRC=DST` means:

- `SRC` is the secret name in macrun Keychain storage
- `DST` is the env var name the child process receives

If you pass only `SRC`, macrun replaces that same env var with ciphertext.

This is intentional bootstrap behavior: the child process should not receive both the plaintext source variable and the ciphertext replacement unless you explicitly model that as two separate stored secrets.

If the scope has no stored keys, `exec` fails rather than silently running with an empty secret set.

## 13. Use Multiple Envs

Envs let you keep separate local contexts inside one project.

Examples:

- `dev`
- `test`
- `staging`
- `customer-a`

Store different values under different envs:

```bash
macrun --project my-app --env dev set APP_DATABASE_URL=postgres://localhost/devdb
macrun --project my-app --env staging set APP_DATABASE_URL=postgres://localhost/stagingdb
```

Run against a specific env:

```bash
macrun --project my-app --env staging exec -- cargo run
```

Envs are useful when the variable names stay the same but the actual endpoints or credentials change.

## 14. Purge a Scope

Remove every indexed secret for the active project and env:

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
- the resolved project and env, if any
- the local state directory
- the index path
- how many secrets are indexed overall and in the current scope

If you are unsure why a command cannot resolve a project or env, start with `doctor`.

## 16. Storage Details

The current implementation stores secret values in macOS Keychain using:

- service: `macrun/<project>/<env>`
- account: env var name

macrun also stores non-secret metadata in its local application config directory. That metadata powers commands such as `list`, `unset`, `purge`, and scoped selection.

## 17. macOS Keychain Access Prompts After Rebuilds

If macOS keeps asking for Keychain access every time you rebuild `macrun`, the usual cause is that the binary is not being signed with a stable identity.

On macOS, Keychain access decisions are tied to the code identity of the calling binary. A rebuilt unsigned or ad-hoc binary can be treated as a new caller, which causes repeated approval prompts.

Recommended development workflow:

1. build and sign the debug binary with a stable identity every time
3. approve access once for that identity

Examples:

```bash
make build-signed
```

```bash
make codesign-debug
```

For release builds:

```bash
make dist
```

The default signing mode is ad-hoc signing with the identifier `io.frogfish.macrun`. Override it with `CODESIGN_IDENTITY=...` and `SIGN_NAME=...` if your local policy needs a different identity.

## 18. Security Model

macrun helps reduce these common local-development failures:

- committing plaintext `.env` files
- leaving sensitive values in repo-local files
- contaminating a long-lived shell session with broad exports
- mixing up projects or envs
- oversharing secrets to commands that do not need them

It does not protect you from:

- malware already running as your user
- root or admin compromise
- a child process that logs or forwards secrets
- terminal capture, clipboard leaks, or screen recording

The rule is simple: once a process receives a secret, that process is part of your trust boundary.

## 19. Vault Bootstrap Transfer

macrun's Vault support is for bootstrap transfer: moving a high-value secret out of local Keychain and into its real system boundary without first dropping it into a plaintext file.

There are two separate patterns.

### Transit ciphertext for application databases

Use `vault encrypt` when an app must keep a key in its own database.

That workflow:

1. reads a plaintext secret from Keychain
2. encrypts it with Vault Transit
3. prints the ciphertext so it can be stored downstream
4. can verify decrypt without printing plaintext

The app then stores the ciphertext and asks Vault Transit to decrypt it when needed, usually caching the plaintext only in memory.

If you are bootstrapping the app directly with `macrun exec`, the same pattern can be used without an intermediate copy step:

```bash
macrun exec \
  --vault-encrypt APP_CLIENT_SECRET=APP_CLIENT_SECRET_CIPHERTEXT \
  --vault-addr http://127.0.0.1:8200 \
  --vault-key app-secrets \
  -- myapp
```

Vault authentication currently uses `VAULT_TOKEN` from the environment.

Example:

```bash
export VAULT_TOKEN=...

macrun vault encrypt APP_CLIENT_SECRET \
  --vault-addr http://127.0.0.1:8200 \
  --transit-path transit \
  --vault-key app-secrets \
  --verify-decrypt
```

### Vault KV as shared secret storage

Use `vault push` when Vault itself should store the secrets and the app will fetch them from Vault directly.

That workflow:

1. reads one or more plaintext secrets from Keychain
2. writes them into Vault KV at a chosen mount and path
3. leaves Vault as the source of truth for the app-side read path

Example:

```bash
export VAULT_TOKEN=...

macrun vault push APP_CLIENT_SECRET API_TOKEN \
  --vault-addr http://127.0.0.1:8200 \
  --mount secret \
  --path apps/my-app/dev \
  --kv-version v2
```

## 20. Vault Over an SSH Tunnel

macrun does not create or manage SSH tunnels itself.

If your Vault endpoint is reachable only through a bastion or private network, open the tunnel separately and point `--vault-addr` at the local forwarded port.

Example:

```bash
ssh -L 18200:vault.internal:8200 user@bastion
```

Then in another shell:

```bash
export VAULT_TOKEN=...

macrun vault encrypt APP_CLIENT_SECRET \
  --vault-addr http://127.0.0.1:18200 \
  --vault-key app-secrets \
```

If the remote Vault endpoint expects HTTPS with a certificate valid only for its original hostname, forwarding to `127.0.0.1` may cause hostname validation failures. That is a transport configuration issue rather than a macrun-specific behavior.

## 21. Recommended Usage Patterns

Good patterns:

- initialize each working tree once with `macrun init`
- keep local secrets in Keychain instead of repo files
- use envs to separate materially different contexts
- keep each env self-contained so a command can consume the whole scope
- use `doctor` when scope resolution is unclear

Patterns to avoid:

- exporting your entire secret set into a long-lived shell session
- keeping large plaintext `.env` files around after import
- sharing one env across unrelated environments

## 22. Troubleshooting

`no project resolved`

- run `macrun doctor`
- check whether `.macrun.toml` exists in the current directory or an ancestor
- pass `--project` explicitly if needed

`exec` says there are no secrets in the current scope

- verify the scope with `macrun doctor`
- check the stored names with `macrun list`
- confirm you are using the intended project and env

`import` fails on a line in `.env`

- simplify the source file to plain `KEY=value` lines
- remove shell constructs the importer does not understand
- retry with a smaller file if needed

`VAULT_TOKEN is required`

- export `VAULT_TOKEN` before using `macrun vault encrypt` or `macrun vault push`

macOS asks for Keychain access after every rebuild

- sign the binary with a stable code-signing identity
- use `make build-signed`
- if you already created secrets with an older caller identity, approve once again for the newly signed binary

`purge` refuses to run

- re-run with `--yes` if you really intend to destroy the current scope