# Release preparation notes

Prepared on 2026-09-25 from the authors' public [ponyyuhan/secureclaw](https://github.com/ponyyuhan/secureclaw) runtime at commit `11e95bcdcf0943fc459060e3239af3948c0adf82`. The target repository was empty when inspected. This release uses a clean initial history rather than importing unrelated local project history.

## Included changes

- Documented installation, local validation, paper-to-code correspondence, simulated sinks, and the distinction from benchmark experiments.
- Copied four existing portable test modules from the authors' research workspace at base commit `ab56ad47ff541cbb5a9dda6a1b37261927d3992b`; these modules were unchanged in that workspace.
- Fixed three demo-filesystem containment checks. String-prefix comparison previously admitted sibling directories whose names started with the allowed directory name; resolved path containment now rejects them. Four regression tests cover rejected sibling paths and valid in-root operations.
- Restricted Docker host-port mappings to loopback. The development policy keys are public examples, so publishing their services on every host network interface was inappropriate for the default local demonstration.
- Restored ignore rules for local environment files, state, logs, generated data, and build outputs; excluded them from Docker build contexts.
- Removed generated benchmark workspace files, generated policy databases, and OpenClaw runtime state. The databases are rebuilt by `scripts/dev_up.sh`.
- Replaced general-purpose OpenClaw workspace templates with a concise demonstration instruction file, retaining privacy, approval, and gateway-use constraints. The gateway skill and adapters remain.
- Updated the macOS capsule launcher to execute the selected Python by absolute path and allow read access to its base Python installation, which virtual environments keep outside `sys.prefix`. No general process or network permission was added.
- Removed optional client examples that disabled client approval and sandbox protections. No runtime authentication, proof verification, filesystem confinement, or other enforcement mechanism was removed.

## Validation on the prepared release

- Python 3.14 on macOS: 38 portable unit tests passed.
- Fresh local stack with isolated ports and state: all 50 runtime validation checks passed.
- Built-in benign and malicious demonstrations: exited successfully.
- macOS capsule with CPython 3.11.4 (Anaconda): all 7 existing mediation-contract assertions passed, including denied host-file access, arbitrary shell execution, public network access, and loopback bypass; mediated gateway access succeeded.
- Homebrew Python 3.14 virtual environment: capsule interpreter launch remained blocked by the OS sandbox. No passing capsule claim is made for that installation.
- No hosted model, provider credentials, or external side-effect backend was used.

The optional Node client adapters, Rust server, Docker build, and Linux capsule are not covered by these results. Runtime requirements remain the upstream package constraints; the checked Python environment and direct package versions are listed below for this validation.

| Package | Checked version |
| --- | --- |
| Python | 3.14 |
| FastAPI | 0.141.1 |
| Uvicorn | 0.54.0 |
| Pydantic | 2.13.5 |
| Requests | 2.34.2 |
| PyYAML | 6.0.3 |

## Dependencies and reuse

The project does not vendor installed Python, Node, or Rust dependencies. Python dependencies are listed in `requirements.txt`; optional Node and Rust dependencies retain their manifests and lockfiles. Their own license terms apply.

The sensitive-field vocabulary referenced by `common/output_sanitizer.py` follows the [AgentLeak project](https://github.com/Privatris/AgentLeak), specifically its `agentleak/detection/presidio_detector.py` taxonomy. The original comment's local `third_party/` path describes the research workspace; that external benchmark is not bundled here.

The original repository contained no project license. The authors selected the MIT License for the SecureClaw source in this release. This does not change third-party licenses.
