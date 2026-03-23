## Vault Transit Master Key & Encrypted Secret Workflow

- [ ] Define the first k2mx encrypted secret record shape:
	- `id`: durable secret record id
	- `provider`: provider slug such as `office365`
	- `name`: human label such as `primary`
	- `ciphertext`: Vault transit ciphertext blob
	- `vault_key`: transit key name such as `k2mx-provider-creds`
	- `key_version`: optional transit key version if tracked explicitly
	- `metadata`: JSON metadata for tenant, mailbox, notes, or rotation context
	- `created_at` / `updated_at`: audit timestamps
	- `disabled_at`: optional soft-disable timestamp
- [ ] Implement Vault Transit key creation and policy setup
- [ ] Add macrun support for Vault authentication and transit encryption
- [ ] Implement `macrun vault push` with this first-pass CLI contract:
	- `macrun vault push <ENV_KEY> --vault-addr <URL> --transit-path <PATH> --vault-key <KEY> --provider <PROVIDER> --name <NAME>`
	- Example: `macrun vault push OFFICE365_PASSWORD --vault-addr https://vault.example.com --transit-path transit --vault-key k2mx-provider-creds --provider office365 --name primary`
	- Read plaintext from Keychain only
	- Encrypt via Vault transit only
	- Print ciphertext metadata or remote record id, never plaintext
	- Add `--dry-run` to stop after successful encryption without storing in k2mx
	- Add `--verify-decrypt` only for explicit round-trip checks during setup
- [ ] Update k2mx to decrypt secrets via Vault Transit (in-memory only)
- [ ] Add in-memory caching for decrypted secrets in k2mx
- [ ] Ensure no plaintext secrets are written to disk/logs
- [ ] Add auditing for all encrypt/decrypt operations (Vault + k2mx)
- [ ] Document bootstrap flow for enrolling new provider credentials
- [ ] Add tests for round-trip encryption/decryption and access control

## First Vertical Slice

- [ ] Add a `vault` command group in macrun CLI
- [ ] Add a minimal Vault client module for transit `encrypt`
- [ ] Support Vault auth via `VAULT_TOKEN` first; defer AppRole and other flows
- [ ] Implement `macrun vault push --dry-run` before any k2mx persistence work
- [ ] Return structured output for: env key, provider, name, vault key, ciphertext length, key version
- [ ] Add tests that assert plaintext is not emitted in stdout/stderr
- [ ] Add tests for missing Vault token, missing Keychain entry, and non-2xx Vault responses

## k2mx Integration After Dry Run

- [ ] Add a write path to store ciphertext records in k2mx after dry-run flow is stable
- [ ] Keep decrypt separate from write so encrypt-and-store can ship before runtime unwrap
- [ ] Add a runtime decrypt helper in k2mx that only returns plaintext in memory
- [ ] Cache decrypted provider credentials in process memory with explicit expiry or invalidation
- [ ] Add a rotation path: re-encrypt with a new transit key or key version without exposing plaintext outside Vault
