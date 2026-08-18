<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Events;

use Illuminate\Http\Request;

final class CorsRequestDenied
{
    public function __construct(
        public readonly Request $request,
        public readonly string $origin,
        public readonly string $reason,
        public readonly bool $preflight,
        public readonly ?string $requestedMethod = null,
    ) {}
}
