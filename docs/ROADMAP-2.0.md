# HyperSwitch Version 2.0 Roadmap

## Status

HyperSwitch `2.0.0` is now released.

The roadmap below captures the direction and workstreams that shaped the 2.0 launch. It remains useful as product history and as context for future updates beyond the 2.0 line.

## Vision

HyperSwitch 2.0 is the evolution of HyperSwitch from a useful single-purpose troubleshooting utility into a more polished, trustworthy, and maintainable Windows virtualization control center.

The goal is not to make the tool "do everything." The goal is to make it feel safer, clearer, faster, and more professional for the people who rely on it when they are already troubleshooting a difficult machine.

## Product Goals

### 1. Trustworthy by Default

- Keep safe defaults for one-off troubleshooting.
- Make reboot implications, firmware boundaries, and unsupported states obvious.
- Improve backup, rollback, and auditability before any boot-setting change.

### 2. Faster and Clearer Status Reporting

- Reduce repeated system probing and avoid redundant refresh work.
- Make the status model easier to understand at a glance.
- Separate runtime state, configured state, and hardware capability more cleanly.

### 3. More Professional Operator Experience

- Introduce cleaner product metadata, versioning, and documentation.
- Improve release packaging, diagnostics, and support handoff materials.
- Present the app as a cohesive desktop utility rather than a large script bundle.

### 4. Stronger Internal Architecture

- Break the monolithic application into focused modules over time.
- Separate UI concerns from system-query logic and mutation logic.
- Create a path for tests around parsing, status calculation, and safety guards.

## Scope For 2.0

HyperSwitch 2.0 should target the following outcome:

- A more modular codebase with clear product metadata and internal boundaries.
- A safer and more explainable UI for Hyper-V, VBS, DSE, HVCI, Secure Boot, Credential Guard, DMA protection, and CPU virtualization checks.
- Better diagnostics and release artifacts for users, testers, and maintainers.
- Improved maintainability so future platform features can be added without growing one giant file forever.

## Roadmap Phases

### Phase 1: Foundation

- Centralize product metadata and version handling.
- Add roadmap and architecture-facing documentation.
- Continue reducing redundant refresh and probe work.
- Improve release contents so docs and support materials ship with builds.

### Phase 2: Internal Restructure

- Split the current monolithic script into modules such as:
  - product metadata and paths
  - system queries
  - boot configuration helpers
  - safety and backup services
  - UI components and dialogs
- Introduce a stable application entry layer that is easier to package and test.

### Phase 3: UX and Safety Upgrade

- Improve state labels and operator guidance.
- Add clearer explanations for blocked changes and unsupported machine states.
- Make read-only versus writable controls more obvious.
- Improve help, first-run guidance, and advanced mode explanations.

### Phase 4: Diagnostics and Supportability

- Expand structured debug reporting.
- Add build/version details to reports and support artifacts.
- Improve packaging of docs, rollback guidance, and release notes.
- Create a clearer issue-reporting flow for testers.

### Phase 5: Launch Readiness

- Finalize 2.0 release notes and support docs.
- Validate build and packaging flow end-to-end.
- Review naming, product copy, and trust signals across the UI and releases.
- Tag and publish HyperSwitch 2.0 with a stable release bundle.

## Workstreams

### Architecture

- Move from a single large script toward maintainable modules.
- Reduce coupling between UI rendering and system inspection.
- Create seams for future automated verification.

### Safety

- Strengthen guardrails around reboot-sensitive changes.
- Improve backup visibility and restore confidence.
- Preserve the tool's current safety posture unless a new behavior is explicitly justified.

### User Experience

- Make the app feel more intentional and less like a debug console.
- Improve copy, state labeling, and operator confidence.
- Keep the tool fast enough to feel responsive during repeated troubleshooting.

### Release Engineering

- Ship cleaner bundles with better docs.
- Keep versioning, metadata, and packaged outputs aligned.
- Make release artifacts easier to understand for end users.

## Non-Goals

- Turning HyperSwitch into a general-purpose system tweaker.
- Expanding risky write operations without matching safety and rollback support.
- Replacing BIOS or firmware configuration paths that Windows cannot safely control.

## Definition of Done For 2.0

HyperSwitch 2.0 is ready when:

- the product has a clearly documented architecture direction,
- the release bundle feels professional and self-explanatory,
- the codebase is materially less monolithic,
- diagnostics are stronger than the 1.x line,
- and the user experience is clearer without losing the current safety-first approach.

## Immediate Next Steps

Work has already started on the 2.0 foundation track with:

- centralized product metadata and version surfacing,
- roadmap documentation in the repo,
- and release packaging that can ship roadmap/support documents alongside the executable.
