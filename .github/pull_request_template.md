## Summary

<!-- What does this PR do and why? Link related issue if applicable: Closes #N -->

## Type of change

- [ ] Bug fix
- [ ] New module
- [ ] Existing module improvement
- [ ] Documentation
- [ ] Other:

## Testing

- [ ] Tested on Ubuntu 22.04 LTS
- [ ] Tested on Debian 12
- [ ] `bash -n` passes on all modified scripts
- [ ] Installer is idempotent (safe to re-run with `--force`)
- [ ] No new ports hardcoded — constants added to `lib/common.sh`

## Checklist

- [ ] `set -euo pipefail` present in new scripts
- [ ] New module exposes `run_<id>()` and calls `mark_module_complete`
- [ ] All ports/service names use `lib/common.sh` constants
- [ ] `.env.example` updated if new env variables were added
- [ ] CHANGELOG.md updated under `[Unreleased]`
