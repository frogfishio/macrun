# Product Direction

macrun should be quiet, obvious, and boring.

## Everyday interface

- `macrun set [PROJECT [ENVIRONMENT]] SECRET`
- `macrun run [PROJECT [ENVIRONMENT]] -- COMMAND`
- `macrun list [PROJECT [ENVIRONMENT]]`
- `macrun unset [PROJECT [ENVIRONMENT]] SECRET`

New features should not add concepts to this interface unless ordinary usage clearly requires them.

## Next

- Add black-box tests around Keychain-backed `set`, `run`, `list`, and `unset` using an isolated test service.
- Test stdin and environment-variable ingestion without exposing values in output.
- Add an Ansible example and test it locally.
- Validate the Terraform ephemeral-variable example against supported Terraform versions.
- Decide on a deprecation window for the hidden legacy commands.

## Parked

Vault transfer, encrypted archives, metadata, and local project configuration remain in the code for compatibility. They are intentionally outside the everyday product until their purpose is clearer.
