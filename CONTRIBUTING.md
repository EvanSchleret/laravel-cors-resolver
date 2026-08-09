# Contributing

## Setup

```bash
composer install
```

## Checks

```bash
composer test
composer format
composer analyse
composer validate
```

Keep the package independent of Eloquent and database schemas. Add or update tests for behavior changes, preserve support for Laravel 12 and 13, and avoid modifying Laravel's global CORS configuration.

Use conventional commits where practical. Changes that affect the public API or security behavior must include a changelog entry.
