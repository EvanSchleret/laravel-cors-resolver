<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\RouteParameterCorsResolver;
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
