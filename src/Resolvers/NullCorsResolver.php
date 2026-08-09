<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Resolvers;

use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use Illuminate\Http\Request;

final class NullCorsResolver implements CorsResolver
{
    public function resolve(Request $request): CorsPolicy
    {
        return CorsPolicy::deny();
    }
}
