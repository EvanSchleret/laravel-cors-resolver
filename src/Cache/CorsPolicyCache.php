<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Cache;

use Closure;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use Illuminate\Contracts\Cache\Repository;
use InvalidArgumentException;

final class CorsPolicyCache
{
    public function __construct(
        private readonly ?Repository $store,
        private readonly int $ttl,
        private readonly string $namespace = 'laravel-cors-resolver',
        string|int $version = 'v1',
    ) {
        if ($namespace === '' || preg_match('/^[A-Za-z0-9._-]+$/', $namespace) !== 1) {
            throw new InvalidArgumentException('The CORS cache namespace must contain only letters, numbers, dots, underscores, or hyphens.');
        }

        if ((string) $version === '' || preg_match('/^[A-Za-z0-9._-]+$/', (string) $version) !== 1) {
            throw new InvalidArgumentException('The CORS cache version must contain only letters, numbers, dots, underscores, or hyphens.');
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

        $policy = $resolver();
        $this->store->put($key, $policy, $this->ttl);

        return $policy;
    }

    public function forget(CorsResolverContext $context): bool
    {
        return $this->store?->forget($this->effectiveKey($context)) ?? false;
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
}
