## Vault Transit Workflow

- [ ] Define the long-term purpose of `macrun vault push`
	- should it remain a local encrypt-and-report command
	- should it write ciphertext to a generic file or stdout target
	- should downstream persistence live outside macrun entirely
- [ ] Implement Vault Transit key creation and policy setup
- [ ] Add macrun support for Vault authentication and transit encryption
- [ ] Implement `macrun vault push` with this first-pass CLI contract:
	- `macrun vault push <ENV_KEY> --vault-addr <URL> --transit-path <PATH> --vault-key <KEY>`
	- Example: `macrun vault push APP_CLIENT_SECRET --vault-addr https://vault.example.com --transit-path transit --vault-key app-secrets`
	- Read plaintext from Keychain only
	- Encrypt via Vault transit only
	- Print ciphertext metadata, never plaintext
	- Add `--verify-decrypt` only for explicit round-trip checks during setup
- [ ] Ensure no plaintext secrets are written to disk/logs
- [ ] Add auditing guidance for local encrypt/decrypt operations
- [ ] Add tests for round-trip encryption/decryption and access control

## First Vertical Slice

- [ ] Add a `vault` command group in macrun CLI
- [ ] Add a minimal Vault client module for transit `encrypt`
- [ ] Support Vault auth via `VAULT_TOKEN` first; defer AppRole and other flows
- [ ] Return structured output for: env key, vault key, ciphertext length, key version
- [ ] Add tests that assert plaintext is not emitted in stdout/stderr
- [ ] Add tests for missing Vault token, missing Keychain entry, and non-2xx Vault responses
