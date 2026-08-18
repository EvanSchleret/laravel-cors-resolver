<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Responses;

use Closure;
use EvanSchleret\LaravelCorsResolver\CorsFailure;
use EvanSchleret\LaravelCorsResolver\CorsFailureResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class ClosureCorsFailureResponse implements CorsFailureResponse
{
    public function __construct(private readonly Closure $resolver) {}

    public function respond(Request $request, CorsFailure $failure): Response
    {
        $response = ($this->resolver)($request, $failure);

        if (! $response instanceof Response) {
            throw new \UnexpectedValueException('A CORS failure response closure must return a Response instance.');
        }

        return $response;
    }
}
