# Contributing to SecureClaw

Focused bug reports, documentation improvements, and implementation fixes are welcome.

## Report a problem

Open a [GitHub issue](https://github.com/ponyyuhan/SecureClaw_repo/issues) with the command you ran, the expected and actual behavior, and your OS and Python version. A small example using synthetic inputs is especially useful. Remove credentials, real protected values, and private model transcripts before posting logs.

For a vulnerability involving real data or deployed credentials, contact the authors using the contact information in the [paper](https://openreview.net/forum?id=0omFi3ZiBf) instead of posting sensitive details publicly.

## Work on a change

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r method_adapters/agentdojo/requirements.txt
python -m unittest discover -s tests -v
```

For changes to runtime requests, policy checks, or executor behavior, also run the [local integration checks](docs/quickstart.md#validate-and-try-the-demo). Test security-relevant behavior with a concrete allowed case and the corresponding rejected case.

Keep changes focused, describe the problem they solve, and include a regression test when fixing a behavioral bug. Documentation-only changes do not need new tests.

## Pull requests

Explain what changed and how you verified it. Preserve existing authorization, replay, authentication, and confinement checks. Update the relevant guide if commands or supported behavior change.

Do not commit API keys, generated results, model transcripts, datasets fetched into `third_party/`, or local runtime state. Existing ignore rules cover the standard output directories. Third-party source and integration patches must retain their attribution and licenses.
