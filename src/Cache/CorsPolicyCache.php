<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Cache;

use Closure;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use Illuminate\Contracts\Cache\Repository;

final class CorsPolicyCache
{
    public function __construct(
        private readonly ?Repository $store,
        private readonly int $ttl,
    ) {}

    public function remember(CorsResolverContext $context, Closure $resolver): CorsPolicy
    {
        if ($this->store === null || $this->ttl === 0) {
            return $resolver();
        }

        $cached = $this->store->get($context->cacheKey());

        if ($cached instanceof CorsPolicy) {
            return $cached;
        }

        $policy = $resolver();
        $this->store->put($context->cacheKey(), $policy, $this->ttl);

        return $policy;
    }

    public function forget(CorsResolverContext $context): bool
    {
        return $this->store?->forget($context->cacheKey()) ?? false;
    }

    public function forgetByKey(string $key): bool
    {
        return $this->store?->forget($key) ?? false;
    }

    public function enabled(): bool
    {
        return $this->store !== null && $this->ttl > 0;
    }
}
