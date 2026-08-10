<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Providers;

use Closure;
use EvanSchleret\LaravelCorsResolver\Cache\CorsPolicyCache;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use EvanSchleret\LaravelCorsResolver\Http\Middleware\ResolveCors;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\NullCorsResolver;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use InvalidArgumentException;

final class LaravelCorsResolverServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/cors-resolver.php', 'cors-resolver');

        $this->app->singleton(CorsResolver::class, function (Application $app): CorsResolver {
            $configured = $app->make('config')->get('cors-resolver.resolver');

            if ($configured instanceof CorsResolver) {
                return $configured;
            }

            if ($configured instanceof Closure) {
                return new ClosureCorsResolver($configured);
            }

            if ($configured === null) {
                return new NullCorsResolver;
            }

            if (! is_string($configured) || ! is_a($configured, CorsResolver::class, true)) {
                throw new InvalidArgumentException('cors-resolver.resolver must be a CorsResolver class, closure, or null.');
            }

            $resolver = $app->make($configured);

            return $resolver;
        });

        $this->app->singleton(CorsPolicyCache::class, function (Application $app): CorsPolicyCache {
            $configuration = $app->make('config')->get('cors-resolver.cache', []);

            if (! is_array($configuration) || ! (bool) ($configuration['enabled'] ?? false)) {
                return new CorsPolicyCache(null, 0);
            }

            $ttl = max(1, (int) ($configuration['ttl'] ?? 300));
            $storeName = $configuration['store'] ?? null;
            $namespace = (string) ($configuration['namespace'] ?? 'laravel-cors-resolver');
            $version = $configuration['version'] ?? 'v1';
            $store = $storeName === null
                ? $app->make('cache.store')
                : $app->make('cache')->store($storeName);

            if (! $store instanceof Repository) {
                throw new InvalidArgumentException('The configured CORS cache store must implement the cache repository contract.');
            }

            return new CorsPolicyCache($store, $ttl, $namespace, $version);
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../../config/cors-resolver.php' => config_path('cors-resolver.php'),
        ], 'cors-resolver-config');

        if ($this->app->bound('router')) {
            $this->app->make('router')->aliasMiddleware('cors.resolve', ResolveCors::class);
        }
    }
}
