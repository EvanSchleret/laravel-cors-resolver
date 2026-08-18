<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\Cache\CorsPolicyCache;
use EvanSchleret\LaravelCorsResolver\CorsFailure;
use EvanSchleret\LaravelCorsResolver\CorsFailureResponse;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;
use EvanSchleret\LaravelCorsResolver\Providers\LaravelCorsResolverServiceProvider;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\NullCorsResolver;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

it('validates the resolver configuration during provider registration', function (): void {
    $this->app['config']->set('cors-resolver.resolver_exception_mode', 'invalid');

    expect(fn () => (new LaravelCorsResolverServiceProvider($this->app))->register())
        ->toThrow(CorsConfigurationException::class, 'resolver_exception_mode');
});

it('rejects malformed paths during provider registration', function (): void {
    $this->app['config']->set('cors-resolver.paths', 'api/*');

    expect(fn () => (new LaravelCorsResolverServiceProvider($this->app))->register())
        ->toThrow(CorsConfigurationException::class, 'paths must be a list');
});

it('rejects invalid cache lock configuration during provider registration', function (): void {
    $this->app['config']->set('cors-resolver.cache.lock.ttl', 0);

    expect(fn () => (new LaravelCorsResolverServiceProvider($this->app))->register())
        ->toThrow(CorsConfigurationException::class, 'cache.lock.ttl');
});

it('rejects resolver classes that do not implement the contract during provider registration', function (): void {
    $this->app['config']->set('cors-resolver.resolver', stdClass::class);

    expect(fn () => (new LaravelCorsResolverServiceProvider($this->app))->register())
        ->toThrow(CorsConfigurationException::class, 'resolver must be a CorsResolver');
});

it('registers the default resolver and disabled cache bindings', function (): void {
    $provider = new LaravelCorsResolverServiceProvider($this->app);
    $provider->register();

    expect($this->app->make(CorsResolver::class))->toBeInstanceOf(NullCorsResolver::class)
        ->and($this->app->make(CorsPolicyCache::class)->enabled())->toBeFalse();
});

it('registers a closure resolver binding', function (): void {
    $this->app['config']->set('cors-resolver.resolver', static fn (Request $request): CorsPolicy => CorsPolicy::deny());

    (new LaravelCorsResolverServiceProvider($this->app))->register();

    expect($this->app->make(CorsResolver::class))->toBeInstanceOf(ClosureCorsResolver::class);
});

it('registers an existing resolver instance', function (): void {
    $resolver = new ProviderTestCorsResolver;
    $this->app['config']->set('cors-resolver.resolver', $resolver);

    (new LaravelCorsResolverServiceProvider($this->app))->register();

    expect($this->app->make(CorsResolver::class))->toBe($resolver);
});

it('resolves a configured resolver class from the container', function (): void {
    $this->app['config']->set('cors-resolver.resolver', ProviderTestCorsResolver::class);

    (new LaravelCorsResolverServiceProvider($this->app))->register();

    expect($this->app->make(CorsResolver::class))->toBeInstanceOf(ProviderTestCorsResolver::class);
});

it('resolves a configured failure response class from the container', function (): void {
    $this->app['config']->set('cors-resolver.failure_response', ProviderTestFailureResponse::class);

    (new LaravelCorsResolverServiceProvider($this->app))->register();

    expect($this->app->make(CorsFailureResponse::class))->toBeInstanceOf(ProviderTestFailureResponse::class);
});

it('adapts a configured failure response closure', function (): void {
    $this->app['config']->set(
        'cors-resolver.failure_response',
        static fn (Request $request, CorsFailure $failure): Response => new Response('', $failure->status),
    );

    (new LaravelCorsResolverServiceProvider($this->app))->register();

    $response = $this->app->make(CorsFailureResponse::class)->respond(
        Request::create('/api/resource'),
        new CorsFailure('test', 418, true),
    );

    expect($response->getStatusCode())->toBe(418);
});

it('registers an enabled cache with its configured options', function (): void {
    $this->app['config']->set('cors-resolver.cache', [
        'enabled' => true,
        'store' => 'array',
        'ttl' => 60,
        'namespace' => 'provider-test',
        'version' => 'v2',
        'tenant_parameter' => 'tenant',
        'lock' => [
            'enabled' => false,
            'ttl' => 0,
            'wait' => 0,
        ],
    ]);
    $this->app['config']->set('cors-resolver.observability.enabled', false);

    (new LaravelCorsResolverServiceProvider($this->app))->register();

    expect($this->app->make(CorsPolicyCache::class)->enabled())->toBeTrue();
});

it('rejects invalid configuration values during provider registration', function (string $key, mixed $value, string $message): void {
    $this->app['config']->set($key, $value);

    expect(fn () => (new LaravelCorsResolverServiceProvider($this->app))->register())
        ->toThrow(CorsConfigurationException::class, $message);
})->with([
    ['cors-resolver.paths.0', '', 'paths must contain only non-empty strings'],
    ['cors-resolver.failure_mode', 'invalid', 'failure_mode'],
    ['cors-resolver.failure_response', stdClass::class, 'failure_response'],
    ['cors-resolver.observability', 'invalid', 'observability must be an array'],
    ['cors-resolver.observability.enabled', 'yes', 'observability.enabled'],
    ['cors-resolver.cache', 'invalid', 'cache must be an array'],
    ['cors-resolver.cache.enabled', 'yes', 'cache.enabled'],
    ['cors-resolver.cache.store', '', 'cache.store'],
    ['cors-resolver.cache.ttl', -1, 'cache.ttl'],
    ['cors-resolver.cache.namespace', 'invalid/value', 'cache.namespace'],
    ['cors-resolver.cache.version', 'invalid/value', 'cache.version'],
    ['cors-resolver.cache.tenant_parameter', '', 'cache.tenant_parameter'],
    ['cors-resolver.cache.lock', 'invalid', 'cache.lock must be an array'],
    ['cors-resolver.cache.lock.enabled', 'yes', 'cache.lock.enabled'],
    ['cors-resolver.cache.lock.wait', -1, 'cache.lock.wait'],
]);

it('rejects a zero cache ttl when caching is enabled', function (): void {
    $this->app['config']->set('cors-resolver.cache.enabled', true);
    $this->app['config']->set('cors-resolver.cache.ttl', 0);

    expect(fn () => (new LaravelCorsResolverServiceProvider($this->app))->register())
        ->toThrow(CorsConfigurationException::class, 'cache.ttl');
});

final class ProviderTestCorsResolver implements CorsResolver
{
    public function resolve(Request $request): CorsPolicy
    {
        return CorsPolicy::deny();
    }
}

final class ProviderTestFailureResponse implements CorsFailureResponse
{
    public function respond(Request $request, CorsFailure $failure): Response
    {
        return new Response('', $failure->status);
    }
}
