# Development and testing

## Requirements

Use Node.js 24 LTS or later. Sentinel's runtime code uses Node.js built-ins, including `node:sqlite`; TypeScript, ESLint, Prettier and Vitest are development dependencies.

## Commands

```sh
npm ci
npm run check
npm run lint
npm run format:check
npm test
npm run test:integration
npm run build
npm run verify
```

Unit tests cover parsers, rules, correlation, query validation, export escaping, configuration and security helpers. Integration tests use temporary directories and databases for ingestion checkpoints, migrations, alert lifecycle, HTTP security, exports and service startup. No test uses production logs or databases.

## Dashboard

The browser application is plain TypeScript in `src/web/`. `npm run build:web` type-checks it and copies the HTML/CSS shell into `dist/web`; compiled modules retain their relative paths. Views are separate modules, share typed API and DOM helpers, and do not render event-derived strings as HTML.

## Performance

Build before running `npm run bench`. The default synthetic corpus contains 1,000 records; pass an integer from 1 to 10,000 to vary its size:

```sh
npm run bench -- 1000
```

The script uses a temporary SQLite database and synthetic NDJSON records, prints machine-readable measurements and removes its temporary files. See [performance](performance.md) for the recorded baseline and interpretation.
