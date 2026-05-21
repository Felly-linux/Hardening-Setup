---
name: Bug Report
about: Something broke during or after installation
labels: bug
---

## What happened

<!-- Describe the problem clearly and concisely. -->

## Steps to reproduce

1. 
2. 
3. 

## Expected behavior

<!-- What should have happened instead? -->

## Error output

<!-- Paste the relevant lines from the log or terminal. -->

```
# cat /var/log/vps-hardening/install.log | tail -50
```

## Environment

- **OS**: <!-- e.g. Ubuntu 22.04 LTS -->
- **Install mode**: <!-- basic / intermediate / hardcore / custom -->
- **Module that failed**: <!-- e.g. crowdsec -->
- **State file**:

```json
# cat /var/lib/vps-hardening/state.json
```

## Additional context

<!-- Screenshots, iptables output, docker ps, etc. -->
