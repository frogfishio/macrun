# macrun

macrun keeps secrets in macOS Keychain and gives them to commands when they run.

## Quick start

Save a secret:

```console
$ macrun set myapp production API_TOKEN
API_TOKEN:
```

Type the value at the prompt and press Return. Your typing is hidden. Only put the secret **name** in the command:

```bash
# Yes: macrun asks for the value safely
macrun set myapp production API_TOKEN

# No: API_TOKEN=aaa is treated as a name, not a value
macrun set myapp production API_TOKEN=aaa
```

Run your app with the saved secrets:

```bash
macrun run myapp production -- npm start
```

The command receives `API_TOKEN` in its environment. macrun prints nothing of its own.

## Install

```bash
cargo install macrun
```

Upgrade an older installation:

```bash
cargo install macrun --locked --force
macrun --version
```

Or install this checkout:

```bash
cargo install --path .
```

## The one pattern

A secret can belong to the machine, a project, or a project environment:

| Command shape | Where the secret belongs |
| --- | --- |
| `macrun set SECRET` | this machine |
| `macrun set PROJECT SECRET` | that project |
| `macrun set PROJECT ENVIRONMENT SECRET` | that project environment |

For example:

```bash
macrun set API_TOKEN                       # this machine
macrun set myapp API_TOKEN                 # myapp
macrun set myapp staging API_TOKEN         # myapp / staging
macrun set myapp production DATABASE_URL   # myapp / production
```

Use the same words with `list`, `run`, and `unset`.

## List secret names

`list` shows secret names for one exact scope. It never prints their values:

```bash
macrun list                 # names stored for this machine
macrun list myapp           # names stored for myapp
macrun list myapp staging   # names stored for myapp / staging
```

Suppose you saved these:

```bash
macrun set myapp staging API_TOKEN
macrun set myapp staging DATABASE_URL
macrun set myapp production API_TOKEN
```

Then:

```console
$ macrun list myapp staging
API_TOKEN
DATABASE_URL

$ macrun list myapp production
API_TOKEN
```

`macrun list myapp` does not combine every environment. It only lists secrets stored directly for `myapp`. If a scope is empty, `list` prints nothing.

## Run a command

Choose the same scope, then put the command after `--`:

```bash
macrun run -- some-command
macrun run myapp -- some-command
macrun run myapp staging -- some-command
```

Only secrets from that exact scope are added to the command.

## Unset a secret

Use `unset` exactly like the shell counterpart to `set`:

```bash
macrun unset API_TOKEN
macrun unset myapp API_TOKEN
macrun unset myapp staging API_TOKEN
```

Unsetting a secret that is already absent is harmless. Successful `set` and `unset` commands are quiet.

## Automation

Read a value from standard input:

```bash
printf '%s' "$API_TOKEN" | macrun set myapp staging API_TOKEN --stdin
```

Or read it from an environment variable:

```bash
macrun set myapp staging API_TOKEN --from-env API_TOKEN
```

Prefer these forms in setup scripts, Terraform, and Ansible so the value is not placed in the command itself.

### Capture a bootstrap key from Ansible

Ansible can initialize software on a server, keep the returned key in memory, and send it directly to macrun on the developer Mac:

```text
server stdout → Ansible memory → macrun stdin → macOS Keychain
```

No plaintext file is needed:

```yaml
- name: Bootstrap the application key
  no_log: true
  block:
    - name: Obtain the pending bootstrap key
      ansible.builtin.command:
        argv:
          - /opt/myapp/bin/myapp
          - init
          - --print-bootstrap-key
      register: myapp_bootstrap

    - name: Refuse an empty key
      ansible.builtin.assert:
        that:
          - myapp_bootstrap.stdout | length > 0
        quiet: true

    - name: Store the key on the developer Mac
      ansible.builtin.command:
        argv:
          - macrun
          - set
          - myapp
          - production
          - MASTER_KEY
          - --stdin
        stdin: "{{ myapp_bootstrap.stdout }}"
        stdin_add_newline: false
      delegate_to: localhost
      throttle: 1

    - name: Acknowledge safe receipt
      ansible.builtin.command:
        argv:
          - /opt/myapp/bin/myapp
          - acknowledge-bootstrap-key
```

This assumes Ansible is being run from the developer Mac. `delegate_to: localhost` means the Ansible controller; in AWX or CI it refers to that runner, not a developer's computer.

The application should keep returning the same pending key until `acknowledge-bootstrap-key` succeeds. That makes retries safe if Keychain is locked or the local storage task fails. `macrun set` overwrites the same entry, so repeating the transfer is harmless.

For this handoff to remain safe:

- apply `no_log: true` to every task that can see the key
- do not run the playbook with `ANSIBLE_DEBUG` enabled
- have the application print only the key to stdout and diagnostics to stderr
- ensure the developer's login Keychain is unlocked

Ansible stores registered task results in memory for the current playbook run. Its command module supports stdin, and delegation runs the macrun step on the controller. See the Ansible documentation for [registered variables](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_variables.html), [command stdin](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/command_module.html), [delegation](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_delegation.html), and [`no_log`](https://docs.ansible.com/projects/ansible/latest/reference_appendices/faq.html).

## What macrun does

- Stores values in macOS Keychain.
- Keeps projects and environments separate.
- Adds the selected secrets to one child command.
- Prints nothing when `set` and `unset` succeed.

macrun is for local development on macOS. It is not a production secret manager and cannot prevent a program from leaking a secret after receiving it.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
