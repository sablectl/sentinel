# Contributing

Contributions should preserve Sentinel's defensive scope, local-first operation and secure defaults. Do not submit real authentication logs, tokens, database files, production configuration or private project instructions.

## Development setup

- Use Node.js 24 LTS or later.
- Install the locked development dependencies with `npm ci`.
- Run `npm run verify` before opening a change.
- Add deterministic tests for parser, rule, store, API or export behavior changes.
- Keep runtime dependencies within the Node.js standard library unless a documented security or maintenance case justifies otherwise.

## Pull requests

Describe the behavior changed, security impact and verification performed. Keep changes focused, document parser limitations and avoid claims that an indicator confirms compromise. Do not include sensitive logs or secrets in fixtures.
