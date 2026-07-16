# Contributing to Marty UI

Thank you for helping improve Marty. Keep pull requests focused, explain the
user-visible effect, and include tests for behavior changes.

## Development checks

Run these checks before opening a pull request:

```bash
python scripts/check_oss_boundary.py
python -m pytest tests packages/tests services/gateway/tests
cd ui
npm install
npm test
npm run build
```

Some integration suites require Docker or coordinated Marty repositories. The
pull request should identify any checks that could not be run locally.

## Public/private boundary

This repository must build without private dependencies. Payment providers,
subscriptions, commercial prices, checkout UI, payment credentials, and
commercial release inputs belong in a separately distributed commerce
extension. Changes that intentionally add an extension point should provide a
working public no-op implementation and a boundary test.

Never commit credentials, production data, private repository snapshots, or
generated build output.

## Pull requests

- Link the issue or explain the motivation.
- Describe testing and deployment impact.
- Update documentation when configuration or public APIs change.
- Accept the repository's license terms for your contribution.
