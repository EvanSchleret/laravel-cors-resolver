# Security Policy

## Supported versions

Security fixes are currently provided for the Laravel 12 and Laravel 13 compatibility lines.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues. Use [GitHub's private vulnerability reporting](https://github.com/EvanSchleret/laravel-cors-resolver/security/advisories/new), or email evan@schleret.ch with:

- a description of the vulnerability;
- affected versions;
- reproduction steps or a minimal proof of concept;
- the impact you believe it has.

The maintainers will acknowledge reports as soon as practical and coordinate a fix and disclosure timeline. Do not include production secrets or personal data in a report.

## Security expectations

CORS controls browser access to responses. It does not authenticate requests, protect server-to-server traffic, or replace authorization. Applications must keep authentication, authorization, CSRF protection, validation, and rate limiting in place.

When policies are tenant-specific, configure `cache.tenant_parameter` and invalidate the tenant whenever its CORS configuration changes. Use resolver invalidation when changing resolver-wide policy logic. Cache namespaces and versions must be changed when the key contract changes. Never enable credentials with a wildcard origin.
