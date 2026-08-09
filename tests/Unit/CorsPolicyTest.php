<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\CorsPolicy;

it('returns a deny policy with no allowed origins', function (): void {
    expect(CorsPolicy::deny()->allowedOrigins())->toBe([])
        ->and(CorsPolicy::deny()->allowsOrigin('https://example.com'))->toBeFalse();
});

it('normalizes methods and headers', function (): void {
    $policy = CorsPolicy::make()
        ->allowMethods(['post', 'OPTIONS'])
        ->allowHeaders(['Content-Type', 'X-Request-ID']);

    expect($policy->allowedMethods())->toBe(['POST', 'OPTIONS'])
        ->and($policy->allowedHeaders())->toBe(['content-type', 'x-request-id'])
        ->and($policy->allowsHeaders(['Content-Type']))->toBeTrue();
});
