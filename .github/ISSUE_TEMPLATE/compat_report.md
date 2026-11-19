---
name: Compatibility report
about: Behavior that differs from stock CUPS - wire responses, config parsing, file formats, exit codes
title: "[compat] "
labels: compatibility
assignees: ''
---

**yindle version / commit**
<!-- output of `cupsd --version` (or `cupsd -v`), or the release tag / commit SHA -->

**Stock CUPS behavior** (version, distro):
<!-- what stock cupsd does -->

**yindle behavior**:

**How to reproduce** (config, client command, ipptool file, or packet capture):

**Client affected** (`lp`, GNOME print dialog, macOS, a specific driver/backend):

If the divergence is already listed in
[`docs/deviations.md`](https://github.com/vindeckyy/yindle/blob/main/docs/deviations.md),
note it — fixes may still be wanted.
