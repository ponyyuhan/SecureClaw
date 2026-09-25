# Source and license notices

The disclosed adapter was extracted from the SecureClaw working copy of
[IPIGuard](https://github.com/Greysahy/ipiguard), whose vendored AgentDojo code
derives from [AgentDojo](https://github.com/ethz-spylab/agentdojo). The local
IPIGuard checkout is based on commit
`4e686ed2f62c135cb12564a4466daa95f3ace878`; the SecureClaw method modifications
are local changes, so that commit does not identify the complete disclosed
adapter.

- `tool_execution.py`: selected helper functions and classes from
  `agentdojo/src/agentdojo/agent_pipeline/tool_execution.py`. The extraction adds this package's documentation header,
  removes unused imports, adjusts the repository-root path, and uses a local
  whitelist import. The release also fixes cross-read reference reuse: a public
  read namespace preserves earlier bindings while each read's alias counter
  starts afresh. Regression tests cover reference resolution across reads,
  independence from earlier secret counts, and state cleanup at a new task.
  SecureClaw modifications are distributed under the root
  MIT license. Original third-party license notices remain applicable.
- `tool_white_list.py`: copied unchanged from
  `agentdojo/src/agentdojo/default_suites/v1/tools/tool_white_list.py`.
- `LICENSE_AGENTDOJO`: original MIT license, copyright 2024 Edoardo Debenedetti,
  Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian
  Tramèr.
- `LICENSE_IPIGUARD`: retained Apache License 2.0 from the enclosing IPIGuard
  repository. No repository-level NOTICE file was present in the local source.

The new package documentation and offline release tests are covered by the
repository's MIT license. Third-party terms are not replaced by that license.
