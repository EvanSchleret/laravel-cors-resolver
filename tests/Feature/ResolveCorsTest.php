<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\Cache\CorsPolicyCache;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use EvanSchleret\LaravelCorsResolver\Events\CorsPolicyCacheMissed;
use EvanSchleret\LaravelCorsResolver\Events\CorsRequestDenied;
use EvanSchleret\LaravelCorsResolver\Events\CorsResolverFailed;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\RouteParameterCorsResolver;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

it('adds headers to an allowed actual request', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()
            ->allowOrigins(['https://example.com'])
            ->allowMethods(['POST'])
            ->exposeHeaders(['X-Request-Id'])
    ));

    $response = $middleware->handle(makeRequest('POST', 'https://example.com'), nextResponse(headers: ['Vary' => 'Accept-Encoding']));

    expect($response->getStatusCode())->toBe(200)
        ->and($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://example.com')
        ->and($response->headers->get('Access-Control-Expose-Headers'))->toBe('x-request-id')
        ->and($response->headers->get('Vary'))->toBe('Accept-Encoding, Origin');
});

it('does not add headers for an unknown origin', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()->allowOrigins(['https://example.com'])
    ));

    $response = $middleware->handle(makeRequest('GET', 'https://unknown.example'), nextResponse());

    expect($response->getStatusCode())->toBe(200)
        ->and($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse()
        ->and($response->headers->get('Vary'))->toBe('Origin');
});

it('handles an allowed preflight', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()
            ->allowOrigins(['https://example.com'])
            ->allowMethods(['POST', 'OPTIONS'])
            ->allowHeaders(['Content-Type', 'Accept'])
            ->maxAge(300)
    ));

    $response = $middleware->handle(
        makeRequest('OPTIONS', 'https://example.com', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'Content-Type',
        ]),
        nextResponse()
    );

    expect($response->getStatusCode())->toBe(204)
        ->and($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://example.com')
        ->and($response->headers->get('Access-Control-Allow-Methods'))->toBe('POST, OPTIONS')
        ->and($response->headers->get('Access-Control-Allow-Headers'))->toBe('content-type, accept')
        ->and($response->headers->get('Access-Control-Max-Age'))->toBe('300')
        ->and($response->headers->get('Vary'))->toBe('Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
});

it('resolves methods and headers dynamically from the request', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()
            ->allowOrigins([$request->headers->get('Origin')])
            ->allowMethods([$request->headers->get('Access-Control-Request-Method', 'GET')])
            ->allowHeaders([$request->headers->get('Access-Control-Request-Headers', 'X-Request-ID')])
    ));

    $response = $middleware->handle(
        makeRequest('OPTIONS', 'https://tenant.example', [
            'Access-Control-Request-Method' => 'PATCH',
            'Access-Control-Request-Headers' => 'X-Tenant-ID',
        ]),
        nextResponse()
    );

    expect($response->getStatusCode())->toBe(204)
        ->and($response->headers->get('Access-Control-Allow-Methods'))->toBe('PATCH')
        ->and($response->headers->get('Access-Control-Allow-Headers'))->toBe('x-tenant-id');
});

it('denies an invalid preflight without invoking the application', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()
            ->allowOrigins(['https://example.com'])
            ->allowMethods(['POST'])
    ));
    $called = false;

    $response = $middleware->handle(
        makeRequest('OPTIONS', 'https://unknown.example', ['Access-Control-Request-Method' => 'POST']),
        static function (Request $request) use (&$called): Response {
            $called = true;

            return new Response;
        }
    );

    expect($response->getStatusCode())->toBe(403)->and($called)->toBeFalse();
});

it('rejects malformed requested headers even when the origin and method are allowed', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()
            ->allowOrigins(['https://example.com'])
            ->allowMethods(['POST'])
            ->allowHeaders(['Content-Type'])
    ));
    $called = false;

    $response = $middleware->handle(
        makeRequest('OPTIONS', 'https://example.com', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'Content-Type, Invalid Header',
        ]),
        static function (Request $request) use (&$called): Response {
            $called = true;

            return new Response;
        }
    );

    expect($response->getStatusCode())->toBe(403)->and($called)->toBeFalse();
});

it('supports credentials and rejects dangerous wildcards', function (): void {
    $policy = CorsPolicy::make()
        ->allowOrigins(['https://example.com'])
        ->allowCredentials();

    expect($policy->allowsCredentials())->toBeTrue()
        ->and(fn (): CorsPolicy => CorsPolicy::make()->allowOrigins(['*'])->allowCredentials())->toThrow(InvalidArgumentException::class)
        ->and(fn (): CorsPolicy => CorsPolicy::make()->allowOrigins(['https://*.example.com'])->allowCredentials())->toThrow(InvalidArgumentException::class);
});

it('normalizes origins and matches wildcard subdomains strictly', function (): void {
    $policy = CorsPolicy::make()->allowOrigins(['HTTPS://Example.COM/']);
    $wildcard = CorsPolicy::make()->allowOrigins(['https://*.example.com']);

    expect($policy->allowsOrigin('https://example.com/'))->toBeTrue()
        ->and($policy->allowsOrigin('https://example.com.evil.test'))->toBeFalse()
        ->and($wildcard->allowsOrigin('https://tenant.example.com'))->toBeTrue()
        ->and($wildcard->allowsOrigin('https://example.com'))->toBeFalse();
});

it('supports route parameter resolvers without requiring Eloquent', function (): void {
    $resolver = new RouteParameterCorsResolver(
        'site',
        fn (string $site, Request $request): CorsPolicy => CorsPolicy::make()->allowOrigins(['https://'.$site.'.example.com'])
    );
    $request = makeRequest('GET', 'https://tenant.example.com');
    $request->setRouteResolver(static fn (): object => new class
    {
        public function parameter(string $name): string
        {
            return 'tenant';
        }
    });

    $response = makeCorsMiddleware($resolver)->handle($request, nextResponse());

    expect($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://tenant.example.com');
});

it('keeps policy state isolated between requests in one middleware instance', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()->allowOrigins([$request->headers->get('Origin')])
    ));

    $first = $middleware->handle(makeRequest('GET', 'https://one.example'), nextResponse());
    $second = $middleware->handle(makeRequest('GET', 'https://two.example'), nextResponse());

    expect($first->headers->get('Access-Control-Allow-Origin'))->toBe('https://one.example')
        ->and($second->headers->get('Access-Control-Allow-Origin'))->toBe('https://two.example');
});

it('caches policies with a request-complete key', function (): void {
    $count = 0;
    $resolver = new ClosureCorsResolver(function (Request $request) use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins([$request->headers->get('Origin')]);
    });
    $middleware = makeCorsMiddleware($resolver, cachedCorsPolicyCache());
    $firstRequest = makeRequest('GET', 'https://one.example');

    $middleware->handle($firstRequest, nextResponse());
    $middleware->handle(makeRequest('GET', 'https://one.example'), nextResponse());
    $middleware->handle(makeRequest('GET', 'https://two.example'), nextResponse());

    expect($count)->toBe(2);
});

it('does not cache when caching is disabled', function (): void {
    $count = 0;
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(function (Request $request) use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins(['https://example.com']);
    }));
    $request = makeRequest('GET', 'https://example.com');

    $middleware->handle($request, nextResponse());
    $middleware->handle($request, nextResponse());

    expect($count)->toBe(2);
});

it('fails closed when a resolver throws', function (): void {
    $nextCalled = false;
    $middleware = makeCorsMiddleware(
        new ClosureCorsResolver(function (Request $request): CorsPolicy {
            throw new RuntimeException('resolver failed');
        }),
        configuration: [
            'cors-resolver' => [
                'paths' => ['api/*'],
                'failure_mode' => 'deny',
                'resolver_exception_mode' => 'deny',
            ],
        ],
    );

    $response = $middleware->handle(makeRequest('GET', 'https://example.com'), function (Request $request) use (&$nextCalled): Response {
        $nextCalled = true;

        return nextResponse()($request);
    });

    expect($response->getStatusCode())->toBe(Response::HTTP_SERVICE_UNAVAILABLE)
        ->and($response->headers->get('Vary'))->toBe('Origin')
        ->and($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse()
        ->and($nextCalled)->toBeFalse();
});

it('rethrows resolver exceptions when configured to throw', function (): void {
    $middleware = makeCorsMiddleware(
        new ClosureCorsResolver(function (Request $request): CorsPolicy {
            throw new RuntimeException('resolver failed');
        }),
        configuration: [
            'cors-resolver' => [
                'paths' => ['api/*'],
                'failure_mode' => 'deny',
                'resolver_exception_mode' => 'throw',
            ],
        ],
    );

    expect(fn (): Response => $middleware->handle(makeRequest('GET', 'https://example.com'), nextResponse()))
        ->toThrow(RuntimeException::class, 'resolver failed');
});

it('dispatches an event when a CORS request is denied', function (): void {
    $events = Mockery::mock(Dispatcher::class);
    $events->shouldReceive('dispatch')
        ->once()
        ->with(Mockery::on(static fn (object $event): bool => $event instanceof CorsRequestDenied
            && $event->reason === 'origin_not_allowed'
            && $event->origin === 'https://unknown.example'
            && $event->preflight === false
            && $event->requestedMethod === 'GET'))
        ->andReturnNull();
    $middleware = makeCorsMiddleware(
        new ClosureCorsResolver(
            fn (Request $request): CorsPolicy => CorsPolicy::make()->allowOrigins(['https://example.com'])
        ),
        configuration: [
            'cors-resolver' => [
                'paths' => ['api/*'],
                'failure_mode' => 'deny',
            ],
        ],
        events: $events,
    );

    $middleware->handle(makeRequest('GET', 'https://unknown.example'), nextResponse());
});

it('dispatches resolver failure events without exposing the exception', function (): void {
    $events = Mockery::mock(Dispatcher::class);
    $events->shouldReceive('dispatch')
        ->once()
        ->with(Mockery::on(static fn (object $event): bool => $event instanceof CorsResolverFailed
            && $event->exception->getMessage() === 'resolver failed'
            && $event->mode === 'deny'))
        ->andReturnNull();
    $middleware = makeCorsMiddleware(
        new ClosureCorsResolver(function (Request $request): CorsPolicy {
            throw new RuntimeException('resolver failed');
        }),
        configuration: [
            'cors-resolver' => [
                'paths' => ['api/*'],
                'failure_mode' => 'deny',
                'resolver_exception_mode' => 'deny',
            ],
        ],
        events: $events,
    );

    $response = $middleware->handle(makeRequest('GET', 'https://example.com'), nextResponse());

    expect($response->getStatusCode())->toBe(Response::HTTP_SERVICE_UNAVAILABLE);
});

it('rechecks the cache after acquiring a recomputation lock', function (): void {
    $store = Mockery::mock(ArrayStore::class)->makePartial();
    $repository = new CacheRepository($store);
    $context = CorsResolverContext::fromRequest(makeRequest('GET', 'https://example.com'), 'resolver-a', ['api/*']);
    $key = $context->cacheKey().':0';
    $cachedPolicy = CorsPolicy::make()->allowOrigins(['https://peer.example.com']);
    $lock = Mockery::mock(Lock::class);

    $store->shouldReceive('lock')
        ->once()
        ->andReturn($lock);
    $lock->shouldReceive('block')
        ->once()
        ->andReturnUsing(function (int $seconds, Closure $callback) use ($repository, $key, $cachedPolicy): CorsPolicy {
            $repository->put($key, $cachedPolicy, 300);

            return $callback();
        });

    $count = 0;
    $cache = new CorsPolicyCache($repository, 300);
    $result = $cache->remember($context, function () use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins(['https://example.com']);
    });

    expect($result)->toBe($cachedPolicy)
        ->and($count)->toBe(0);
});

it('dispatches an event when a cached policy is missed', function (): void {
    $events = Mockery::mock(Dispatcher::class);
    $events->shouldReceive('dispatch')
        ->once()
        ->with(Mockery::on(static fn (object $event): bool => $event instanceof CorsPolicyCacheMissed
            && $event->key !== ''))
        ->andReturnNull();
    $cache = new CorsPolicyCache(
        new CacheRepository(new ArrayStore),
        300,
        events: $events,
    );
    $context = CorsResolverContext::fromRequest(makeRequest('GET', 'https://example.com'), 'resolver-a', ['api/*']);

    $cache->remember($context, static fn (): CorsPolicy => CorsPolicy::make()->allowOrigins(['https://example.com']));
});

it('falls back to recomputation when the cache lock times out', function (): void {
    $store = new ArrayStore;
    $repository = new CacheRepository($store);
    $context = CorsResolverContext::fromRequest(makeRequest('GET', 'https://example.com'), 'resolver-a', ['api/*']);
    $key = $context->cacheKey().':0';
    $lock = $store->lock('laravel-cors-resolver:v1:lock:'.hash('sha256', $key), 10);
    $lock->get();

    try {
        $count = 0;
        $cache = new CorsPolicyCache($repository, 300, lockWaitSeconds: 0);
        $cache->remember($context, function () use (&$count): CorsPolicy {
            $count++;

            return CorsPolicy::make()->allowOrigins(['https://example.com']);
        });
    } finally {
        $lock->release();
    }

    expect($count)->toBe(1);
});

it('supports explicit cache invalidation', function (): void {
    $count = 0;
    $resolver = new ClosureCorsResolver(function (Request $request) use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins(['https://example.com']);
    });
    $cache = cachedCorsPolicyCache();
    $middleware = makeCorsMiddleware($resolver, $cache);
    $request = makeRequest('GET', 'https://example.com');

    $middleware->handle($request, nextResponse());
    $context = CorsResolverContext::fromRequest($request, ClosureCorsResolver::class, ['api/*']);
    $cache->forget($context);
    $middleware->handle($request, nextResponse());

    expect($count)->toBe(2);
});

it('includes the cache namespace, version, and tenant in the context key', function (): void {
    $request = makeRequest('GET', 'https://example.com');
    $first = CorsResolverContext::fromRequest(
        $request,
        ClosureCorsResolver::class,
        ['api/*'],
        'tenant-cors',
        'v2',
        'tenant-a',
    );
    $second = CorsResolverContext::fromRequest(
        $request,
        ClosureCorsResolver::class,
        ['api/*'],
        'tenant-cors',
        'v2',
        'tenant-b',
    );

    expect($first->cacheKey())->toStartWith('tenant-cors:v2:')
        ->and($first->cacheKey())->not->toBe($second->cacheKey())
        ->and($first->tenantKey())->toBe('tenant-a');
});

it('invalidates all cached policies for a resolver', function (): void {
    $count = 0;
    $cache = cachedCorsPolicyCache();
    $request = makeRequest('GET', 'https://example.com');
    $context = CorsResolverContext::fromRequest($request, ClosureCorsResolver::class, ['api/*']);
    $resolve = function () use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins(['https://example.com']);
    };

    $cache->remember($context, $resolve);
    $cache->remember($context, $resolve);
    $cache->invalidateResolver(ClosureCorsResolver::class);
    $cache->remember($context, $resolve);

    expect($count)->toBe(2);
});

it('invalidates cached policies for one tenant without affecting another', function (): void {
    $count = 0;
    $cache = cachedCorsPolicyCache();
    $request = makeRequest('GET', 'https://example.com');
    $tenantA = CorsResolverContext::fromRequest($request, ClosureCorsResolver::class, ['api/*'], tenantKey: 'tenant-a');
    $tenantB = CorsResolverContext::fromRequest($request, ClosureCorsResolver::class, ['api/*'], tenantKey: 'tenant-b');
    $resolve = function () use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins(['https://example.com']);
    };

    $cache->remember($tenantA, $resolve);
    $cache->remember($tenantB, $resolve);
    $cache->invalidateTenant('tenant-a');
    $cache->remember($tenantA, $resolve);
    $cache->remember($tenantB, $resolve);

    expect($count)->toBe(3);
});

it('invalidates a tenant policy for one resolver only', function (): void {
    $count = 0;
    $cache = cachedCorsPolicyCache();
    $request = makeRequest('GET', 'https://example.com');
    $firstResolver = CorsResolverContext::fromRequest($request, 'resolver-a', ['api/*'], tenantKey: 'tenant-a');
    $secondResolver = CorsResolverContext::fromRequest($request, 'resolver-b', ['api/*'], tenantKey: 'tenant-a');
    $resolve = function () use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins(['https://example.com']);
    };

    $cache->remember($firstResolver, $resolve);
    $cache->remember($secondResolver, $resolve);
    $cache->invalidateTenant('tenant-a', 'resolver-a');
    $cache->remember($firstResolver, $resolve);
    $cache->remember($secondResolver, $resolve);

    expect($count)->toBe(3);
});

it('uses the configured route parameter as the tenant cache scope', function (): void {
    $count = 0;
    $resolver = new ClosureCorsResolver(function (Request $request) use (&$count): CorsPolicy {
        $count++;

        return CorsPolicy::make()->allowOrigins(['https://example.com']);
    });
    $cache = cachedCorsPolicyCache();
    $configuration = [
        'cors-resolver' => [
            'paths' => ['api/*'],
            'failure_mode' => 'deny',
            'cache' => ['tenant_parameter' => 'tenant'],
        ],
    ];
    $middleware = makeCorsMiddleware($resolver, $cache, $configuration);
    $firstRequest = makeRequest('GET', 'https://example.com');
    $firstRequest->setRouteResolver(static fn (): object => new class
    {
        public function parameter(string $name): string
        {
            return 'tenant-a';
        }
    });
    $secondRequest = makeRequest('GET', 'https://example.com');
    $secondRequest->setRouteResolver(static fn (): object => new class
    {
        public function parameter(string $name): string
        {
            return 'tenant-b';
        }
    });

    $middleware->handle($firstRequest, nextResponse());
    $middleware->handle($firstRequest, nextResponse());
    $middleware->handle($secondRequest, nextResponse());

    expect($count)->toBe(2);
});

it('adds CORS headers to application error responses', function (): void {
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(
        fn (Request $request): CorsPolicy => CorsPolicy::make()->allowOrigins(['https://example.com'])
    ));

    $response = $middleware->handle(makeRequest('GET', 'https://example.com'), nextResponse(500));

    expect($response->getStatusCode())->toBe(500)
        ->and($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://example.com');
});

it('does not resolve outside configured paths', function (): void {
    $called = false;
    $middleware = makeCorsMiddleware(new ClosureCorsResolver(function (Request $request) use (&$called): CorsPolicy {
        $called = true;

        return CorsPolicy::deny();
    }));
    $request = Request::create('/web/resource', 'GET', server: ['HTTP_ORIGIN' => 'https://example.com']);

    $response = $middleware->handle($request, nextResponse());

    expect($response->getStatusCode())->toBe(200)->and($called)->toBeFalse();
});
