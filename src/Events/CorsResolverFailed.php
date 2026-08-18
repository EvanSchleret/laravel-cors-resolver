<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Events;

use Illuminate\Http\Request;
use Throwable;

final class CorsResolverFailed
{
    public function __construct(
        public readonly Request $request,
        public readonly Throwable $exception,
        public readonly string $mode,
    ) {}
}
