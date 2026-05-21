# Contributing to VPS Hardening Suite

Thank you for your interest. This project targets production VPS operators who need a reliable, auditable hardening baseline — contributions are held to that standard.

---

## Before You Open a PR

- Run `bash -n <file>` on every modified shell script — no syntax errors
- Test the affected module on a fresh Ubuntu 22.04 or Debian 12 VM before submitting
- Keep modules idempotent: the installer must be safe to re-run
- All ports, service names, and state keys must flow through `lib/common.sh` constants
- New modules must expose exactly one `run_<id>()` function and call `mark_module_complete "<id>"` on success

## Reporting Bugs

Use the **Bug Report** issue template. Include:
- The exact error output (copy from `/var/log/vps-hardening/install.log`)
- Output of `cat /var/lib/vps-hardening/state.json`
- OS version (`lsb_release -a`)

## Proposing Changes

Open a **Feature Request** issue before starting significant work. This project prioritizes security correctness over feature breadth — new attack surface needs justification.

## Code Style

- `set -euo pipefail` at the top of every script
- Guard against double-sourcing with `[[ -n "${_MODULE_NAME_LOADED:-}" ]] && return 0`
- Use `log_info` / `log_success` / `log_warning` / `log_error` from `lib/common.sh` — no bare `echo` for status messages
- Prefer `command_exists` / `package_installed` / `service_running` over raw `which` / `dpkg` calls
- Quote all variables: `"$var"` not `$var`
- No hardcoded ports — add a constant to `lib/common.sh` and reference it

## Security Disclosures

Do not open a public issue for security vulnerabilities. Contact **[@fellcrack](https://github.com/fellcrack)** directly via GitHub.
