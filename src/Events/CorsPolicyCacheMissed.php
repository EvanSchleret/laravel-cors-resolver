<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Events;

use EvanSchleret\LaravelCorsResolver\CorsResolverContext;

final class CorsPolicyCacheMissed
{
    public function __construct(
        public readonly CorsResolverContext $context,
        public readonly string $key,
    ) {}
}
