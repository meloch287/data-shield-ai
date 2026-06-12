# Contributing to Data Shield AI

Thanks for helping make AI workflows privacy-safe.

## Principles

1. **Zero runtime dependencies.** The core must run on pure Python stdlib.
   Anything heavier (ML, etc.) goes behind an optional `extras` group and a lazy
   plugin that degrades gracefully when absent.
2. **Precision matters.** Prefer a checksum/validator over a broad regex. A new
   detector should not increase false positives on ordinary text.
3. **Local only.** No detector may make a network call.

## Development setup

```bash
git clone git@github.com:meloch287/data-shield-ai.git && cd data-shield-ai
python3 -m venv .venv-dev && .venv-dev/bin/pip install -e ".[dev]"
```

## Before opening a PR

```bash
python3 -m unittest discover -s tests -t .     # all tests must pass
.venv-dev/bin/ruff check datashield tests      # lint
.venv-dev/bin/mypy datashield                  # types
.venv-dev/bin/coverage run -m unittest discover -s tests -t . && .venv-dev/bin/coverage report
python3 tools/benchmark.py                      # no perf regression
```

## Adding a detector

1. Add it to the right module under `datashield/detectors/` (`regex_intl`, `ru`,
   `extra`, `secrets`, `addresses`, `names`).
2. Wire it into `datashield/detectors/registry.py`.
3. Add a validator to `validators.py` if the format has a checksum.
4. Add **positive and negative** tests (guard against false positives).
5. Update the detector catalog in the README.

## Commit messages

English, imperative mood, e.g. `feat: add German Steuer-ID detector`.
