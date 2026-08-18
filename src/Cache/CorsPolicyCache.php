<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Cache;

use Closure;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use EvanSchleret\LaravelCorsResolver\Events\CorsPolicyCacheMissed;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use InvalidArgumentException;
use Throwable;

final class CorsPolicyCache
{
    public function __construct(
        private readonly ?Repository $store,
        private readonly int $ttl,
        private readonly string $namespace = 'laravel-cors-resolver',
        string|int $version = 'v1',
        private readonly int $lockSeconds = 10,
        private readonly int $lockWaitSeconds = 5,
        private readonly ?Dispatcher $events = null,
        private readonly bool $eventsEnabled = true,
    ) {
        if ($namespace === '' || preg_match('/^[A-Za-z0-9._-]+$/', $namespace) !== 1) {
            throw new InvalidArgumentException('The CORS cache namespace must contain only letters, numbers, dots, underscores, or hyphens.');
        }

        if ((string) $version === '' || preg_match('/^[A-Za-z0-9._-]+$/', (string) $version) !== 1) {
            throw new InvalidArgumentException('The CORS cache version must contain only letters, numbers, dots, underscores, or hyphens.');
        }

        if ($lockSeconds < 0 || $lockWaitSeconds < 0) {
            throw new InvalidArgumentException('The CORS cache lock durations cannot be negative.');
        }

        $this->version = (string) $version;
    }

    private readonly string $version;

    public function remember(CorsResolverContext $context, Closure $resolver): CorsPolicy
    {
        if ($this->store === null || $this->ttl === 0) {
            return $resolver();
        }

        $key = $this->effectiveKey($context);
        $cached = $this->store->get($key);

        if ($cached instanceof CorsPolicy) {
            return $cached;
        }

        $this->dispatch(new CorsPolicyCacheMissed($context, $key));

        $lock = $this->lock($key);

        if ($lock === null) {
            return $this->resolveAndStore($key, $resolver);
        }

        try {
            return $lock->block($this->lockWaitSeconds, function () use ($key, $resolver): CorsPolicy {
                $cached = $this->store->get($key);

                if ($cached instanceof CorsPolicy) {
                    return $cached;
                }

                return $this->resolveAndStore($key, $resolver);
            });
        } catch (LockTimeoutException) {
            return $this->resolveAndStore($key, $resolver);
        }
    }

    public function forget(CorsResolverContext $context): bool
    {
        return $this->store?->forget($this->effectiveKey($context)) ?? false;
    }

    public function invalidateContext(CorsResolverContext $context): bool
    {
        return $this->forget($context);
    }

    public function forgetByKey(string $key): bool
    {
        return $this->store?->forget($key) ?? false;
    }

    public function invalidateResolver(string $resolverKey): bool
    {
        return $this->invalidate('resolver', $resolverKey);
    }

    public function invalidateTenant(string $tenantKey, ?string $resolverKey = null): bool
    {
        if ($resolverKey === null) {
            return $this->invalidate('tenant', $tenantKey);
        }

        return $this->invalidate('tenant-resolver', $tenantKey."\0".$resolverKey);
    }

    public function enabled(): bool
    {
        return $this->store !== null && $this->ttl > 0;
    }

    private function effectiveKey(CorsResolverContext $context): string
    {
        $generations = [$this->generation('resolver', $context->resolverKey())];

        if ($context->tenantKey() !== null) {
            $generations[] = $this->generation('tenant', $context->tenantKey());
            $generations[] = $this->generation('tenant-resolver', $context->tenantKey()."\0".$context->resolverKey());
        }

        return $context->cacheKey($this->namespace, $this->version).':'.implode(':', $generations);
    }

    private function invalidate(string $scope, string $value): bool
    {
        if ($this->store === null) {
            return false;
        }

        return $this->store->forever($this->generationKey($scope, $value), bin2hex(random_bytes(16)));
    }

    private function generation(string $scope, string $value): string
    {
        $generation = $this->store?->get($this->generationKey($scope, $value));

        return is_scalar($generation) ? (string) $generation : '0';
    }

    private function generationKey(string $scope, string $value): string
    {
        return $this->namespace.':'.$this->version.':generation:'.$scope.':'.hash('sha256', $value);
    }

    private function lock(string $key): ?Lock
    {
        if ($this->store === null || $this->lockSeconds === 0) {
            return null;
        }

        $store = $this->store->getStore();

        if (! $store instanceof LockProvider) {
            return null;
        }

        return $store->lock($this->namespace.':'.$this->version.':lock:'.hash('sha256', $key), $this->lockSeconds);
    }

    private function resolveAndStore(string $key, Closure $resolver): CorsPolicy
    {
        $policy = $resolver();
        $this->store?->put($key, $policy, $this->ttl);

        return $policy;
    }

    private function dispatch(object $event): void
    {
        if (! $this->eventsEnabled || $this->events === null) {
            return;
        }

        try {
            $this->events->dispatch($event);
        } catch (Throwable) {
        }
    }
}
