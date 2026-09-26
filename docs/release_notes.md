# Release preparation notes

## 2026-09-26 — Repository review and documentation

- Removed a legacy authorization fallback from the simulated message and fetch endpoints. Signed lookup results did not bind the destination or body of an execution request and cannot substitute for the existing request-bound COMMIT proofs. Requests without both COMMIT proofs are now rejected. The normal gateway flow already supplies these proofs; explicit research bypass settings are unchanged.
- Preserved the invoking Python interpreter for direct CLI subprocesses. The MCP launcher now finds the repository virtual environment without shell activation and supports an explicit `SECURECLAW_PYTHON` override.
- Declared the `jsonschema` dependency used by capsule verification and excluded fetched dependencies, experiment virtual environments, and generated run outputs from Docker build contexts.
- Reorganized the README and added setup, configuration, integration, and contribution guides, with original cartoon PNG illustrations. Added a GitHub Actions workflow for offline tests on Linux/macOS and local runtime checks on Linux.
- Local validation after these fixes: **97 offline tests passed** with Python 3.11 and the optional AgentDojo dependency; a fresh Python 3.14.6 environment passed **50 runtime checks**, both built-in agent demos, and real MCP initialization without an activated shell. No hosted-model call was made. These checks do not rerun the paper's benchmarks or establish compatibility for the optional external clients, Rust server, Docker image, or OS capsule on new platforms.

## Original preparation

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

## Method-source disclosure update

Added the existing AgentDojo/ASB method executor and AgentLeak field-classification, masking, registration, contextual-classification, and channel-mediation adapters. Extraction retains the relevant original method bodies; integration changes and upstream license notices are documented alongside each adapter. Experiment outputs, model traces, datasets, historical repair scripts, and batch orchestration remain excluded.

The full offline suite passed **55 tests** with Python 3.11 and AgentDojo 0.1.35, including 17 new adapter checks. These checks did not invoke a hosted model or external action. No existing core-runtime mechanism or safety fix was changed in this update. Original release validation above records the earlier runtime/service and capsule checks; those were not rerun for this source-only addition.

## Evaluation-source completion

The release now also includes the original primary benchmark runners and scorers, baseline integrations, additional experiment entry points, and mechanism-evaluation scripts. The experiment guide supplies dependency revisions, integration patches, third-party attribution, environment settings, and commands. The patches were applied against their recorded upstream revisions and checked to reconstruct the local source.

The complete offline suite still passes 55 tests. CLI/import and inventory checks cover the AgentDojo 97 benign/629 attacked cases, ASB 2,000 cases, and AgentLeak 500 benign/496 attacked cases. Small hosted-model checks exercise the disclosed runner paths; they are not a repeat of all paper experiments. Their generated outputs remain local, as do all historical experiment results and traces.

The accommodation runner's existing protocol-document dependency is supplied at `rebuttal/EXPERIMENT_PROTOCOL.md`. This is a public protocol description for the disclosed source; the original private development plan and review correspondence are not bundled. Core runtime enforcement and existing tests are unchanged by these packaging additions.

## Implementation verification repairs

Expanded own-method checks identified and repaired per-read reference collisions, overwritten task records, incomplete sensitive-value registration, missing attack delivery in the topology adapter, and incomplete channel observation during ablations. Evaluation errors are reported separately from scored outcomes, field-diagnostic selection works without historical result files, and the confirmation test now exercises a genuinely confirmation-required action. Existing authorization, replay, confinement and confirmation protections remain enabled. See [implementation checks](../experiments/implementation_checks.md) for entry points and scope. No upstream benchmark data or scoring rule was changed.

## Evaluation packaging scope

The standalone four-configuration Boundary/Handles experiment driver and its command example have been removed from the current release tree. Core runtime mechanisms, regression tests, and the other documented evaluation entry points are unchanged. Experiment outputs remain outside the repository.
