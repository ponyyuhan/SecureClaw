# Third-party benchmark and baseline sources

The project MIT license applies to our original code. It does not replace the
licenses of the benchmarks and baselines. `upstream_sources.json` records their
source URLs, revisions, and our modified Python files. The patches preserve the
local evaluation integrations; generated databases, traces, and result files are
not part of these patches.

| Dependency | Upstream terms included here | Use |
| --- | --- | --- |
| IPIGuard | Apache License 2.0 | Native evaluation runner and construct/traverse baseline |
| AgentDojo bundled with IPIGuard | MIT | Tasks, environments, attack generation, and utility/security scoring |
| ASB | MIT | Attack/task inputs and native no-defense runner |
| AgentLeak | MIT | Scenario generation, channel leakage detection, and strict utility scoring |
| Faramesh | Upstream `LICENSE` and `NOTICE` | Unmodified action-authorization baseline |
| DRIFT ASB fork | MIT license found in `ASB_DRIFT/` | ASB baseline integration |
| Official AgentDojo | MIT | DRIFT, Progent, and CaMeL benchmark interfaces |
| CaMeL | Apache License 2.0 | Additional AgentDojo comparison |
| Progent bundled AgentDojo | MIT | Additional AgentDojo comparison |

The recorded DRIFT repository has no repository-wide license file. Its source is
retrieved directly from the original repository; this release does not relicense
DRIFT or distribute a full copy of it. The DRIFT patch records the local changes
needed by the common evaluation harness. Refer to the original authors for terms
covering files outside its separately licensed ASB subtree.

The recorded Progent checkout likewise contains a license for its bundled
AgentDojo rather than a top-level license covering all Progent files. It is
retrieved unchanged from the original repository and is not relicensed here.

Original license texts are in `licenses/`. Fetching dependencies also obtains
the original repositories and their notices. If redistributing those sources,
retain their corresponding licenses and attribution.
