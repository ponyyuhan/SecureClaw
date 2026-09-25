# SecureClaw method adapters

These directories contain the existing method implementation used by the authors' benchmark integrations, separated from datasets, outputs, model traces, repair scripts, and batch experiment orchestration. The core gateway, policy services, executor, and storage mechanisms remain at the repository root.

- [AgentDojo and ASB](agentdojo/README.md): schema-aware summaries, reference aliases, policy checks, and tool-call mediation. ASB reuses this implementation.
- [AgentLeak](agentleak/README.md): field classification and masking, protected-value registration, contextual classification, and channel mediation.

Use each adapter's dependency and configuration instructions. Local tests use synthetic inputs and do not launch paid inference or benchmark experiments. Source attribution and extraction changes are recorded alongside the code. Upstream licenses are retained.

The full experiment entry points and dependency setup are documented in [the experiment guide](../experiments/README.md). Historical output files are not required inputs to those runs.
