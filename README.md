# Laravel CORS Resolver

Dynamic, request-aware CORS policies for Laravel applications.

Status: active development.

`evanschleret/laravel-cors-resolver` is designed for multi-tenant and multi-site applications where the allowed origins, methods, and headers depend on the current request. It supports the Laravel 12 and 13 major versions that are currently within Laravel's official support window.

The package does not modify `config('cors')` and does not depend on `fruitcake/laravel-cors`, `spatie/laravel-cors`, or another abandoned CORS package.

## Installation

```bash
composer require evanschleret/laravel-cors-resolver
php artisan vendor:publish --tag=cors-resolver-config
```

Laravel package discovery registers the service provider and the `cors.resolve` middleware alias.

Use this middleware instead of Laravel's `Illuminate\Http\Middleware\HandleCors` for the paths handled by this package. Do not run both middleware for the same request.

## Other packages by Evan Schleret

- [lara-mjml](https://github.com/EvanSchleret/lara-mjml) — Blade-based MJML email templating for Laravel.
- [laravel-typebridge](https://github.com/EvanSchleret/laravel-typebridge) — deterministic TypeScript types from Laravel resources.
- [laravel-ebics](https://github.com/EvanSchleret/laravel-ebics) — EBICS integration for Laravel applications.
- [laravel-user-presence](https://github.com/EvanSchleret/laravel-user-presence) — track whether users are online, offline, or idle.
- [NotificationCompass](https://github.com/EvanSchleret/NotificationCompass) — context-aware notification preferences for Laravel applications.

## Configuration

```php
return [
    'paths' => ['api/*'],
    'resolver' => App\Cors\SiteCorsResolver::class,
    'failure_mode' => 'deny',
    'resolver_exception_mode' => 'deny',
    'failure_response' => null,
    'observability' => [
        'enabled' => true,
    ],
    'cache' => [
        'enabled' => true,
        'store' => null,
        'ttl' => 300,
        'namespace' => 'laravel-cors-resolver',
        'version' => 'v1',
        'tenant_parameter' => null,
        'lock' => [
            'enabled' => true,
            'ttl' => 10,
            'wait' => 5,
        ],
    ],
];
```

`deny` returns `403` for an invalid or unresolved preflight and omits CORS headers from actual responses. `passthrough` lets an invalid preflight reach the application without adding CORS headers. Both modes fail closed from the browser's point of view.

Configuration is validated while the service provider registers. Invalid paths, resolver declarations, failure modes, cache settings, namespaces, versions, and lock durations fail startup with a `CorsConfigurationException` instead of being silently coerced.

Resolver exceptions use `resolver_exception_mode`. The default `deny` mode returns `503 Service Unavailable`, adds only the appropriate `Vary` headers, does not invoke the application, and does not expose the exception. `throw` rethrows the original exception to Laravel's exception handler. Cache failures are not treated as resolver failures and are allowed to propagate.

Failure responses can be customized with a class implementing `CorsFailureResponse` or with a closure accepting `(Request $request, CorsFailure $failure)` and returning a Symfony `Response`. The package always adds the required `Vary` headers after the custom response. If the custom responder throws, the package falls back to the default fail-closed response.

The package dispatches three events when observability is enabled:

- `CorsRequestDenied` for rejected actual requests and preflights, with a reason such as `origin_not_allowed`, `method_not_allowed`, or `headers_not_allowed`.
- `CorsResolverFailed` when a resolver throws, including the original exception and the configured handling mode.
- `CorsPolicyCacheMissed` when an enabled policy cache has no matching policy.

Register listeners with Laravel's event system. Set `observability.enabled` to `false` when the application does not need these events. Event listener failures are isolated from the CORS response.

Caching is disabled by default. Enable it only when the resolver's result is stable for the request fingerprint and invalidate entries when external tenant configuration changes. `namespace` and `version` isolate this package's keys from other applications and provide a simple cache migration mechanism. Set `tenant_parameter` to a route parameter name when policies are tenant-specific, for example `tenant` or `account`.

When caching is enabled, supported Laravel lock stores protect cache misses from concurrent recomputation. `lock.ttl` must exceed the expected resolver duration, and `lock.wait` controls how long another request waits for the lock. If the store does not support locks or the lock times out, the resolver runs normally and the request is not failed because caching is only an optimization. Set `lock.enabled` to `false` to disable this protection.

## A simple resolver

```php
namespace App\Cors;

use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use Illuminate\Http\Request;

final class SiteCorsResolver implements CorsResolver
{
    public function resolve(Request $request): CorsPolicy
    {
        $site = $request->route('site');

        if ($site === null) {
            return CorsPolicy::deny();
        }

        return CorsPolicy::make()
            ->allowOrigins($site->cors_origins)
            ->allowMethods(['POST', 'OPTIONS'])
            ->allowHeaders(['Content-Type', 'Accept'])
            ->exposeHeaders(['X-Request-Id'])
            ->maxAge(300)
            ->allowCredentials(false);
    }
}
```

The package does not type the route value as an Eloquent model. The example works with Eloquent route model binding, but the same resolver can use a DTO, an API response, a configuration service, or a tenant registry.

## Closure and route parameter resolvers

```php
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\RouteParameterCorsResolver;

$closureResolver = new ClosureCorsResolver(
    fn (Request $request): CorsPolicy => CorsPolicy::make()
        ->allowOrigins(['https://app.example.com'])
);

$siteResolver = new RouteParameterCorsResolver(
    'site',
    fn ($site, Request $request): CorsPolicy => CorsPolicy::make()
        ->allowOrigins($site->cors_origins)
);
```

A closure can also be set directly as `cors-resolver.resolver`. A resolver configured as a class should implement `CorsResolver` and be resolvable by Laravel's container.

## Middleware registration

### Laravel 12 and 13

For a global resolver, remove `HandleCors` from the global stack and add the package middleware in `bootstrap/app.php`:

```php
use EvanSchleret\LaravelCorsResolver\Http\Middleware\ResolveCors;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(ResolveCors::class);
    })
    ->create();
```

### Route middleware

```php
Route::middleware('cors.resolve')->group(function (): void {
    Route::post('/api/resources/{resource}', StoreResource::class);
});
```

Route middleware is useful when the resolver needs route model binding. Ensure the route accepts `OPTIONS` before authentication middleware if your application uses route-scoped preflight handling. Global registration is usually preferable for automatic preflight handling.

Laravel 12 and 13 applications configure middleware in `bootstrap/app.php`. The package does not change the application file automatically.

## Security model

- Origins are compared as normalized, exact HTTP origins. Trailing slashes are removed, schemes and hosts are lowercased, and default ports are normalized.
- Wildcards are explicit. `*` and `https://*.example.com` are supported. A subdomain wildcard matches exactly one DNS label, and no origin wildcard, method wildcard, or header wildcard can be combined with credentials.
- Credentials always return the requesting origin, never `*`.
- Private Network Access is opt-in per policy with `->allowPrivateNetwork()`. An allowed PNA preflight must include `Access-Control-Request-Private-Network: true` and receives `Access-Control-Allow-Private-Network: true`.
- Unknown origins receive no CORS headers. Invalid preflights are denied by default.
- `Vary: Origin` is added to actual CORS responses. Preflight responses also vary by `Access-Control-Request-Method`, `Access-Control-Request-Headers`, and `Access-Control-Request-Private-Network`.
- CORS is not authentication or authorization. Continue to use Laravel authentication, authorization, CSRF protection, rate limiting, and input validation.
- Preflight resolution must not require an authenticated user. Resolve from the route, host, origin, public tenant identifier, or another value available before authentication.
- A resolver must return `CorsPolicy::deny()` when there is no applicable policy.

## Cache safety

The cache key includes the resolver class, configured paths, method, scheme and host, path, query parameters, all request headers, and a hash of the request body. This prevents a cached result for one tenant or origin from being reused for a different request context. Header and body values are hashed into the key and are not stored as cache metadata.

Invalidate a known context explicitly after changing external CORS configuration:

```php
$context = CorsResolverContext::fromRequest(
    $request,
    SiteCorsResolver::class,
    config('cors-resolver.paths', [])
);

app(CorsPolicyCache::class)->forget($context);
app(CorsPolicyCache::class)->invalidateContext($context);
```

Invalidate every cached policy for a resolver or tenant when its CORS configuration changes:

```php
app(CorsPolicyCache::class)->invalidateResolver(SiteCorsResolver::class);
app(CorsPolicyCache::class)->invalidateTenant((string) $tenant->getRouteKey());
app(CorsPolicyCache::class)->invalidateTenant(
    (string) $tenant->getRouteKey(),
    SiteCorsResolver::class,
);
```

Resolver and tenant invalidation uses persistent generation keys, so it works with cache stores that do not support tags. Existing policy entries become unreachable immediately and expire normally according to their configured TTL.

Do not cache policies that depend on mutable state not represented by the request fingerprint unless your application invalidates the entry when that state changes.

`forget` and `invalidateContext` invalidate one known request context. `invalidateResolver` invalidates all contexts for a resolver, while `invalidateTenant` invalidates all contexts for a tenant, optionally limited to one resolver. These methods are safe for application-level configuration change handlers and do not require cache tags.

## Known limitations

- A closure placed directly in the configuration cannot be serialized by Laravel's `config:cache`; register a closure resolver from a service provider when configuration caching is required.
- A route resolver that needs bound models must run after route binding. For automatic preflight handling, prefer a global middleware resolver that uses values available from the request path and host, or expose an `OPTIONS` route before route-scoped authentication.
- Fatal process errors that happen before Laravel creates a Symfony response cannot receive response headers. Normal Laravel exception responses are handled like every other response by the middleware.
- The package intentionally does not ship a database migration or a concrete Eloquent model. Applications own tenant storage and can use `RouteParameterCorsResolver` or their own `CorsResolver` implementation.

## Compatibility

| Laravel | PHP | Testbench |
| --- | --- | --- |
| 12 | 8.3–8.5 | 10 |
| 13 | 8.3–8.5 | 11 |

The package requires PHP 8.3 or newer. Laravel 13 officially supports PHP 8.3 through 8.5.

See Laravel's [Laravel 12 support policy](https://laravel.com/docs/12.x/releases#support-policy) and [Laravel 13 release notes](https://laravel.com/docs/13.x/releases) for the framework's current support window.

## Development

```bash
composer install
composer test
composer test:coverage
composer format
composer analyse
composer validate
composer audit --locked
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

The MIT License. See [LICENSE](LICENSE).
