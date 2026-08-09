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
    'cache' => [
        'enabled' => true,
        'store' => null,
        'ttl' => 300,
    ],
];
```

`deny` returns `403` for an invalid or unresolved preflight and omits CORS headers from actual responses. `passthrough` lets an invalid preflight reach the application without adding CORS headers. Both modes fail closed from the browser's point of view.

Caching is disabled by default. Enable it only when the resolver's result is stable for the request fingerprint and invalidate entries when external tenant configuration changes.

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
- Wildcards are explicit. `*` and `https://*.example.com` are supported, but no origin wildcard, method wildcard, or header wildcard can be combined with credentials.
- Credentials always return the requesting origin, never `*`.
- Unknown origins receive no CORS headers. Invalid preflights are denied by default.
- `Vary: Origin` is added to actual CORS responses. Preflight responses also vary by `Access-Control-Request-Method` and `Access-Control-Request-Headers`.
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
```

Do not cache policies that depend on mutable state not represented by the request fingerprint unless your application invalidates the entry when that state changes.

## Known limitations

- A closure placed directly in the configuration cannot be serialized by Laravel's `config:cache`; register a closure resolver from a service provider when configuration caching is required.
- A route resolver that needs bound models must run after route binding. For automatic preflight handling, prefer a global middleware resolver that uses values available from the request path and host, or expose an `OPTIONS` route before route-scoped authentication.
- Fatal process errors that happen before Laravel creates a Symfony response cannot receive response headers. Normal Laravel exception responses are handled like every other response by the middleware.
- The package intentionally does not ship a database migration or a concrete Eloquent model. Applications own tenant storage and can use `RouteParameterCorsResolver` or their own `CorsResolver` implementation.

## Compatibility

| Laravel | PHP | Testbench |
| --- | --- | --- |
| 12 | 8.2–8.5 | 10 |
| 13 | 8.3–8.5 | 11 |

Laravel 13 requires PHP 8.3. The package advertises PHP 8.2+ so it remains installable on Laravel 12 with PHP 8.2 and on Laravel 13 with PHP 8.3+.

See Laravel's [Laravel 12 support policy](https://laravel.com/docs/12.x/releases#support-policy) and [Laravel 13 release notes](https://laravel.com/docs/13.x/releases) for the framework's current support window.

## Development

```bash
composer install
composer test
composer format
composer analyse
composer validate
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

The MIT License. See [LICENSE](LICENSE).
