<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver;

use Throwable;

final readonly class CorsFailure
{
    public function __construct(
        public string $reason,
        public int $status,
        public bool $preflight,
        public ?Throwable $exception = null,
    ) {}
}
