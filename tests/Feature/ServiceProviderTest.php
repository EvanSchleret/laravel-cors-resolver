<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;
use EvanSchleret\LaravelCorsResolver\Providers\LaravelCorsResolverServiceProvider;

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
