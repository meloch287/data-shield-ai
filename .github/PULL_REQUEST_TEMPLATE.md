<!-- Keep the core dependency-free and precision-first. -->

## What & why

## Checklist

- [ ] `python3 -m unittest discover -s tests -t .` passes
- [ ] `ruff check` and `mypy datashield` clean
- [ ] New detector has positive **and** negative tests
- [ ] No new runtime dependency in the core (heavy deps go behind an extra + lazy plugin)
- [ ] No network calls; originals never written to disk
- [ ] README detector catalog / docs updated if behavior changed
