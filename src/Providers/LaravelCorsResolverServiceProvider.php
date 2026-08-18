<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Providers;

use Closure;
use EvanSchleret\LaravelCorsResolver\Cache\CorsPolicyCache;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;
use EvanSchleret\LaravelCorsResolver\Http\Middleware\ResolveCors;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\NullCorsResolver;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use ReflectionClass;

final class LaravelCorsResolverServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/cors-resolver.php', 'cors-resolver');
        $configuration = $this->app->make('config')->get('cors-resolver', []);

        if (! is_array($configuration)) {
            throw new CorsConfigurationException('cors-resolver must be an array.');
        }

        $this->validateConfiguration($configuration);

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
                throw new CorsConfigurationException('cors-resolver.resolver must be a CorsResolver class, closure, or null.');
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
            $lockConfiguration = $configuration['lock'] ?? [];
            $lockEnabled = is_array($lockConfiguration) && (bool) ($lockConfiguration['enabled'] ?? true);
            $lockSeconds = $lockEnabled ? max(1, (int) ($lockConfiguration['ttl'] ?? 10)) : 0;
            $lockWaitSeconds = $lockEnabled ? max(0, (int) ($lockConfiguration['wait'] ?? 5)) : 0;
            $observability = $app->make('config')->get('cors-resolver.observability', []);
            $eventsEnabled = is_array($observability) && ($observability['enabled'] ?? true) === true;
            $events = $app->bound('events') ? $app->make('events') : null;
            $events = $events instanceof Dispatcher ? $events : null;
            $store = $storeName === null
                ? $app->make('cache.store')
                : $app->make('cache')->store($storeName);

            if (! $store instanceof Repository) {
                throw new CorsConfigurationException('The configured CORS cache store must implement the cache repository contract.');
            }

            return new CorsPolicyCache($store, $ttl, $namespace, $version, $lockSeconds, $lockWaitSeconds, $events, $eventsEnabled);
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

    /** @param array<string, mixed> $configuration */
    private function validateConfiguration(array $configuration): void
    {
        $paths = $configuration['paths'] ?? [];

        if (! is_array($paths)) {
            throw new CorsConfigurationException('cors-resolver.paths must be a list of strings.');
        }

        $this->validatePaths($paths);
        $this->validateResolver($configuration['resolver'] ?? null);
        $this->validateMode($configuration['failure_mode'] ?? 'deny', 'failure_mode', ['deny', 'passthrough']);
        $this->validateMode($configuration['resolver_exception_mode'] ?? 'deny', 'resolver_exception_mode', ['deny', 'throw']);

        $observability = $configuration['observability'] ?? [];

        if (! is_array($observability)) {
            throw new CorsConfigurationException('cors-resolver.observability must be an array.');
        }

        $this->booleanValue($observability['enabled'] ?? true, 'cors-resolver.observability.enabled');

        $cache = $configuration['cache'] ?? [];

        if (! is_array($cache)) {
            throw new CorsConfigurationException('cors-resolver.cache must be an array.');
        }

        $this->validateCache($cache);
    }

    /** @param array<int, mixed> $paths */
    private function validatePaths(array $paths): void
    {
        if (! array_is_list($paths)) {
            throw new CorsConfigurationException('cors-resolver.paths must be a list of strings.');
        }

        foreach ($paths as $path) {
            if (! is_string($path) || trim($path) === '') {
                throw new CorsConfigurationException('cors-resolver.paths must contain only non-empty strings.');
            }
        }
    }

    private function validateResolver(mixed $resolver): void
    {
        if ($resolver instanceof CorsResolver || $resolver instanceof Closure || $resolver === null) {
            return;
        }

        if (! is_string($resolver) || ! class_exists($resolver) || ! is_a($resolver, CorsResolver::class, true) || ! (new ReflectionClass($resolver))->isInstantiable()) {
            throw new CorsConfigurationException('cors-resolver.resolver must be a CorsResolver class, closure, or null.');
        }
    }

    /** @param list<string> $allowed */
    private function validateMode(mixed $mode, string $key, array $allowed): void
    {
        if (! is_string($mode) || ! in_array($mode, $allowed, true)) {
            throw new CorsConfigurationException(sprintf('cors-resolver.%s must be one of: %s.', $key, implode(', ', $allowed)));
        }
    }

    /** @param array<string, mixed> $cache */
    private function validateCache(array $cache): void
    {
        $enabled = $this->booleanValue($cache['enabled'] ?? false, 'cors-resolver.cache.enabled');
        $store = $cache['store'] ?? null;

        if ($store !== null && (! is_string($store) || trim($store) === '')) {
            throw new CorsConfigurationException('cors-resolver.cache.store must be null or a non-empty string.');
        }

        $ttl = $cache['ttl'] ?? 300;

        if (! is_int($ttl) || $ttl < 0 || ($enabled && $ttl === 0)) {
            throw new CorsConfigurationException('cors-resolver.cache.ttl must be a positive integer when caching is enabled.');
        }

        $namespace = $cache['namespace'] ?? 'laravel-cors-resolver';

        if (! is_string($namespace) || preg_match('/^[A-Za-z0-9._-]+$/', $namespace) !== 1) {
            throw new CorsConfigurationException('cors-resolver.cache.namespace contains invalid characters.');
        }

        $version = $cache['version'] ?? 'v1';

        if ((! is_string($version) && ! is_int($version)) || preg_match('/^[A-Za-z0-9._-]+$/', (string) $version) !== 1) {
            throw new CorsConfigurationException('cors-resolver.cache.version contains invalid characters.');
        }

        $tenantParameter = $cache['tenant_parameter'] ?? null;

        if ($tenantParameter !== null && (! is_string($tenantParameter) || trim($tenantParameter) === '')) {
            throw new CorsConfigurationException('cors-resolver.cache.tenant_parameter must be null or a non-empty string.');
        }

        $lock = $cache['lock'] ?? [];

        if (! is_array($lock)) {
            throw new CorsConfigurationException('cors-resolver.cache.lock must be an array.');
        }

        $lockEnabled = $this->booleanValue($lock['enabled'] ?? true, 'cors-resolver.cache.lock.enabled');
        $lockTtl = $lock['ttl'] ?? 10;
        $lockWait = $lock['wait'] ?? 5;

        if (! is_int($lockTtl) || $lockTtl < 0 || ($lockEnabled && $lockTtl === 0)) {
            throw new CorsConfigurationException('cors-resolver.cache.lock.ttl must be a positive integer when locking is enabled.');
        }

        if (! is_int($lockWait) || $lockWait < 0) {
            throw new CorsConfigurationException('cors-resolver.cache.lock.wait must be a non-negative integer.');
        }
    }

    private function booleanValue(mixed $value, string $key): bool
    {
        if (! is_bool($value)) {
            throw new CorsConfigurationException($key.' must be a boolean.');
        }

        return $value;
    }
}
