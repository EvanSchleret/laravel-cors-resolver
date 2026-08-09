<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver;

use Illuminate\Http\Request;

interface CorsResolver
{
    public function resolve(Request $request): CorsPolicy;
}
