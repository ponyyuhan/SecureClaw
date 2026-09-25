# Adapted baseline scope

Both baseline runners select AgentDojo `v1.1.2` tasks and scorers from shared
revision `462c88ddf596cb745882702f9999c8aeb5fe467f`: 629 attacked and 97 benign
rows. A pilot selects 100 attacked and 20 benign rows.

Progent uses revision `9befb41cbf992b49dbf035cbd3d53eb953d3b351`. Its own AgentDojo
fork contains 589 attacked rows; two travel injection tasks are absent. The
adapter executes the official SecAgent core and per-suite tool wrappers against
the shared current task/scorer inventory. The attack-construction suite remains
unwrapped so policies from another evaluated task cannot alter benchmark ground
truth. Generated policy is the runner's formal comparison mode. Manual policy
and policy-update options are separate configurations. This is an adapted
comparison, not an assertion that an untouched upstream fork has the same
inventory or results.

CaMeL uses revision `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`, its original
privileged-LLM/interpreter pipeline, replay pipeline, and per-suite security-policy
engines, with the suite selector set to `v1.1.2` instead of the artifact CLI's
`v1.2`. The shared AgentDojo package precedes its bundled dependency. Stage 1
generates traces; stage 2 replays those traces with policies without another
model request. The included local interpreter patch replaces equality-based
list removal of the iterable dependency with removal by object identity. This
fixes recursive equality overflow on deep task objects; it is disclosed rather
than describing the full local checkout as untouched.

The runner safeguards check upstream revisions, selected rows, source/config
consistency, and resumption state. These are preserved from the research source.
New output directories do not contain historical decisions or outcomes.

See [the experiment README](../README.md) for dependency setup and commands.
