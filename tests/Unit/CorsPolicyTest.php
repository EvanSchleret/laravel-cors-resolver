<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;
use EvanSchleret\LaravelCorsResolver\Support\OriginNormalizer;

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

it('normalizes valid local, IP, and IPv6 origins', function (): void {
    expect(OriginNormalizer::normalize('HTTP://localhost/'))->toBe('http://localhost')
        ->and(OriginNormalizer::normalize('https://127.0.0.1:443/'))->toBe('https://127.0.0.1')
        ->and(OriginNormalizer::normalize('http://[0:0:0:0:0:0:0:1]/'))->toBe('http://[::1]');
});

it('rejects malformed and ambiguous origins', function (): void {
    $origins = [
        ' https://example.com',
        'https://example.com ',
        'https://example..com',
        'https://-example.com',
        'https://example-.com',
        'https://exa_mple.com',
        'https://例子.测试',
        'ftp://example.com',
        'https://example.com/path',
        'https://example.com?tenant=1',
        'https://user@example.com',
        'https://example.com:65536',
        'null',
    ];

    foreach ($origins as $origin) {
        expect(fn (): string => OriginNormalizer::normalize($origin))
            ->toThrow(CorsConfigurationException::class);
    }
});

it('matches only one wildcard subdomain label', function (): void {
    expect(OriginNormalizer::matches('https://*.example.com', 'https://tenant.example.com'))->toBeTrue()
        ->and(OriginNormalizer::matches('https://*.example.com', 'https://nested.tenant.example.com'))->toBeFalse()
        ->and(OriginNormalizer::matches('https://*.example.com', 'https://example.com.evil.test'))->toBeFalse();
});
