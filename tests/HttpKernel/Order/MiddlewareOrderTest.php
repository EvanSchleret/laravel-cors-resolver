<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Tests\HttpKernelTestCase;

uses(HttpKernelTestCase::class)->in(__DIR__);

function configureMiddlewareOrderCorsResolver(?callable $callback = null): void
{
    test()->setHttpKernelCorsResolver(new ClosureCorsResolver(
        static function (Request $request) use ($callback): CorsPolicy {
            if ($callback !== null) {
                $callback($request);
            }

            return CorsPolicy::make()
                ->allowOrigins(['https://example.com'])
                ->allowMethods(['GET', 'OPTIONS'])
                ->allowHeaders(['Content-Type']);
        }
    ));
}

it('runs route bindings before a route-scoped CORS resolver', function (): void {
    configureMiddlewareOrderCorsResolver();

    $response = $this->withHeaders([
        'Origin' => 'https://example.com',
    ])->get('/api/bound-resources/example');

    $response->assertOk()
        ->assertJson(['resource' => 'bound-example'])
        ->assertHeader('Access-Control-Allow-Origin', 'https://example.com');
});

it('handles an anonymous preflight before the auth middleware', function (): void {
    $authenticatedDuringResolution = true;

    configureMiddlewareOrderCorsResolver(function (Request $request) use (&$authenticatedDuringResolution): void {
        $authenticatedDuringResolution = $request->user() !== null;
    });

    $response = $this->withHeaders([
        'Origin' => 'https://example.com',
        'Access-Control-Request-Method' => 'GET',
    ])->options('/api/private-resource');

    $response->assertNoContent()
        ->assertHeader('Access-Control-Allow-Origin', 'https://example.com');

    expect($authenticatedDuringResolution)->toBeFalse();
});

it('runs auth after CORS for an authenticated actual request', function (): void {
    configureMiddlewareOrderCorsResolver();
    $this->actingAs(new GenericUser(['id' => 1]));

    $response = $this->withHeaders([
        'Origin' => 'https://example.com',
    ])->get('/api/private-resource');

    $response->assertOk()
        ->assertJson(['private' => true])
        ->assertHeader('Access-Control-Allow-Origin', 'https://example.com');
});

it('lets the native HandleCors middleware short-circuit before routing', function (): void {
    $resolved = false;

    test()->setHttpKernelCorsResolver(new ClosureCorsResolver(
        static function (Request $request) use (&$resolved): CorsPolicy {
            $resolved = true;

            return CorsPolicy::make()->allowOrigins(['https://example.com']);
        }
    ));
    test()->setNativeCorsConfiguration([
        'paths' => ['api/*'],
        'allowed_methods' => ['GET', 'OPTIONS'],
        'allowed_origins' => ['https://example.com'],
        'allowed_origins_patterns' => [],
        'allowed_headers' => ['Content-Type'],
        'exposed_headers' => [],
        'max_age' => 0,
        'supports_credentials' => false,
    ]);

    $response = $this->withHeaders([
        'Origin' => 'https://example.com',
        'Access-Control-Request-Method' => 'GET',
    ])->options('/api/not-defined');

    $response->assertNoContent()
        ->assertHeader('Access-Control-Allow-Origin', 'https://example.com');

    expect($resolved)->toBeFalse();
});
