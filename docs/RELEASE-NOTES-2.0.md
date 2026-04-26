# HyperSwitch 2.0 Release Notes

## HyperSwitch 2.0.0

HyperSwitch 2.0 is the first full productized release of the utility: a cleaner, safer, and more supportable Windows troubleshooting console for Hyper-V, VBS, DSE, and related platform checks.

## Highlights

- Safer operator workflow with clearer Basic and Advanced mode boundaries
- Faster, cleaner status refresh with reduced duplicate probing
- Modularized internal structure for boot helpers, queries, features, platform checks, mitigations, runtime metadata, UI helpers, and updater logic
- Recovery Center with grouped restore sets, raw artifact access, restore command copying, and direct import support for HyperSwitch backup artifacts
- Activity Center with persistent operator history and remembered mode selection
- Support bundle export with summaries, recovery notes, debug output, update state, recent artifacts, and activity history
- GitHub release updater with release detection, ZIP download, digest verification, and in-place relaunch flow
- Single release ZIP distribution with the main executable at the top level and support materials organized into subfolders

## Release Package

The `2.0.0` release ships as one ZIP bundle that includes:

- `HyperSwitch.exe`
- `debug/HyperSwitchDBG.exe`
- `docs/`
- `assets/`
- `source/`

## Notes

- Run HyperSwitch as Administrator.
- Many write operations still apply on the next restart.
- The utility remains intentionally conservative: it focuses on a small set of supported write paths and keeps the broader security surface read-only for clarity.

## Thank You

Thanks to everyone testing, reporting edge cases, and helping shape the 2.0 release.
