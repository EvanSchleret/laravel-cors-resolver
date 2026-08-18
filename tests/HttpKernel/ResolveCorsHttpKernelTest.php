<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use Illuminate\Http\Request;
use Tests\HttpKernelTestCase;

uses(HttpKernelTestCase::class)->in(__DIR__);

function configureHttpKernelCorsResolver(): void
{
    test()->setHttpKernelCorsResolver(new ClosureCorsResolver(
        static fn (Request $request): CorsPolicy => CorsPolicy::make()
            ->allowOrigins(['https://example.com'])
            ->allowMethods(['GET', 'POST', 'OPTIONS'])
            ->allowHeaders(['Content-Type', 'X-Request-ID'])
            ->exposeHeaders(['X-Request-ID'])
    ));
}

it('adds CORS headers to a route response through the HTTP kernel', function (): void {
    configureHttpKernelCorsResolver();

    $response = $this->withHeaders([
        'Origin' => 'https://example.com',
    ])->get('/api/resource');

    $response->assertOk()
        ->assertJson(['handled' => true])
        ->assertHeader('Access-Control-Allow-Origin', 'https://example.com')
        ->assertHeader('Access-Control-Expose-Headers', 'x-request-id')
        ->assertHeader('Vary', 'Origin');
});

it('handles an allowed preflight through the HTTP kernel', function (): void {
    configureHttpKernelCorsResolver();

    $response = $this->withHeaders([
        'Origin' => 'https://example.com',
        'Access-Control-Request-Method' => 'POST',
        'Access-Control-Request-Headers' => 'Content-Type',
    ])->options('/api/resource');

    $response->assertNoContent()
        ->assertHeader('Access-Control-Allow-Origin', 'https://example.com')
        ->assertHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        ->assertHeader('Access-Control-Allow-Headers', 'content-type, x-request-id')
        ->assertHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network');
});

it('denies an unknown origin through the HTTP kernel', function (): void {
    configureHttpKernelCorsResolver();

    $response = $this->withHeaders([
        'Origin' => 'https://unknown.example',
        'Access-Control-Request-Method' => 'POST',
    ])->options('/api/resource');

    $response->assertForbidden()
        ->assertHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network')
        ->assertHeaderMissing('Access-Control-Allow-Origin');
});
