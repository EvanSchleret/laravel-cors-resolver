<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Resolvers;

use Closure;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use Illuminate\Http\Request;

final class ClosureCorsResolver implements CorsResolver
{
    public function __construct(private readonly Closure $resolver) {}

    public function resolve(Request $request): CorsPolicy
    {
        $policy = ($this->resolver)($request);

        if (! $policy instanceof CorsPolicy) {
            throw new \UnexpectedValueException('A CORS resolver closure must return a CorsPolicy instance.');
        }

        return $policy;
    }
}
