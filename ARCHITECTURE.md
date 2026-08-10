# Architecture

## Responsibilities

- `CorsPolicy` is an immutable value object. It normalizes configuration, validates wildcard and credential combinations, and performs strict origin, method, and header checks.
- `CorsResolver` is the only required extension point. It receives the current `Illuminate\Http\Request` and returns a `CorsPolicy`.
- `ResolveCors` owns path matching, preflight handling, response header emission, and failure behavior. It has no request state on its object instance, which makes it safe for Octane and long-lived workers.
- `CorsResolverContext` creates a deterministic, hashed request context for namespaced and versioned cache keys, including an optional tenant scope.
- `CorsPolicyCache` is an optional adapter around Laravel's cache repository. It never mutates configuration and exposes explicit invalidation by context, key, resolver, or tenant through persistent generations.
- `ClosureCorsResolver` and `RouteParameterCorsResolver` cover common adapters without requiring Eloquent or a database dependency.
- `LaravelCorsResolverServiceProvider` merges and publishes configuration, resolves the configured resolver, configures the optional cache, and registers the `cors.resolve` alias.

## Request flow

1. Ignore requests without an `Origin` header or outside configured paths.
2. Build a request context and resolve a policy, optionally through the cache.
3. For `OPTIONS`, validate the requested origin, method, and headers. Return `204` with CORS headers or fail closed.
4. For actual requests, call the application and add CORS headers only when origin and method are allowed.
5. Never retain the policy, origin, route, or response on the middleware instance.

## Laravel integration

Laravel's native `HandleCors` remains the framework's CORS integration. This package deliberately does not subclass it because its internal service and dependency graph vary between framework generations. Applications should replace it for the affected paths rather than stacking both middleware.

Laravel 12 and 13 applications configure the global stack and aliases in `bootstrap/app.php`. Route middleware remains available in every supported version.

## Compatibility decisions

The core depends on Laravel HTTP contracts and Symfony's stable response abstraction. It does not import Eloquent, database models, Fruitcake, or internal Laravel middleware classes. Laravel 13 support is constrained by Laravel's own PHP 8.3 requirement; the package's PHP constraint remains `^8.2` for Laravel 12.
