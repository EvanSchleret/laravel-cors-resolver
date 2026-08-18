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

it('supports the complete policy builder API', function (): void {
    $policy = CorsPolicy::make()
        ->allowOrigins('https://example.com')
        ->allowMethods(['get', 'GET', '*'])
        ->allowHeaders(['Content-Type', 'Content-Type', '*'])
        ->exposeHeaders('X-Request-ID')
        ->maxAge(600);

    expect($policy->allowedOrigins())->toBe(['https://example.com'])
        ->and($policy->allowedMethods())->toBe(['GET', '*'])
        ->and($policy->allowedHeaders())->toBe(['content-type', '*'])
        ->and($policy->exposedHeaders())->toBe(['x-request-id'])
        ->and($policy->maxAgeValue())->toBe(600)
        ->and($policy->allowsMethod('PATCH'))->toBeTrue()
        ->and($policy->allowsHeaders(['X-Other-Header']))->toBeTrue()
        ->and($policy->allowsAllOrigins())->toBeFalse()
        ->and($policy->toArray())->toBe([
            'allowed_origins' => ['https://example.com'],
            'allowed_methods' => ['GET', '*'],
            'allowed_headers' => ['content-type', '*'],
            'exposed_headers' => ['x-request-id'],
            'max_age' => 600,
            'allow_credentials' => false,
        ]);
});

it('supports wildcard origins without credentials', function (): void {
    $policy = CorsPolicy::make()->allowOrigins('*');

    expect($policy->allowsAllOrigins())->toBeTrue()
        ->and($policy->allowsOrigin('https://any.example'))->toBeTrue()
        ->and($policy->allowsCredentials())->toBeFalse();
});

it('rejects invalid policy tokens and max ages', function (): void {
    expect(fn (): CorsPolicy => CorsPolicy::make()->allowMethods('Invalid Method'))
        ->toThrow(CorsConfigurationException::class)
        ->and(fn (): CorsPolicy => CorsPolicy::make()->allowHeaders(''))
        ->toThrow(CorsConfigurationException::class)
        ->and(fn (): CorsPolicy => CorsPolicy::make()->maxAge(-1))
        ->toThrow(CorsConfigurationException::class)
        ->and(fn (): CorsPolicy => CorsPolicy::make()->allowMethods(['*'])->allowCredentials())
        ->toThrow(CorsConfigurationException::class)
        ->and(fn (): CorsPolicy => CorsPolicy::make()->allowHeaders(['*'])->allowCredentials())
        ->toThrow(CorsConfigurationException::class);
});

it('rejects headers that are not allowed by a concrete policy', function (): void {
    $policy = CorsPolicy::make()->allowHeaders(['Content-Type']);

    expect($policy->allowsHeaders(['Content-Type']))->toBeTrue()
        ->and($policy->allowsHeaders(['Authorization']))->toBeFalse()
        ->and($policy->allowsMethod('DELETE'))->toBeTrue();
});
