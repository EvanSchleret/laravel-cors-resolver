<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Resolvers;

use Closure;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use Illuminate\Http\Request;

final class RouteParameterCorsResolver implements CorsResolver
{
    public function __construct(
        private readonly string $parameter,
        private readonly Closure $resolver,
    ) {}

    public function resolve(Request $request): CorsPolicy
    {
        $parameter = $request->route($this->parameter);
        $policy = ($this->resolver)($parameter, $request);

        if (! $policy instanceof CorsPolicy) {
            throw new \UnexpectedValueException('A route parameter CORS resolver must return a CorsPolicy instance.');
        }

        return $policy;
    }
}
