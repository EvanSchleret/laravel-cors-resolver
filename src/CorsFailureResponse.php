<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface CorsFailureResponse
{
    public function respond(Request $request, CorsFailure $failure): Response;
}
