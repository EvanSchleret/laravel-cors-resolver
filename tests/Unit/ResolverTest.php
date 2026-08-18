<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\CorsFailure;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use EvanSchleret\LaravelCorsResolver\Resolvers\ClosureCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\NullCorsResolver;
use EvanSchleret\LaravelCorsResolver\Resolvers\RouteParameterCorsResolver;
use EvanSchleret\LaravelCorsResolver\Responses\ClosureCorsFailureResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

it('returns a deny policy from the null resolver', function (): void {
    expect((new NullCorsResolver)->resolve(Request::create('/api/resource')))
        ->toEqual(CorsPolicy::deny());
});

it('rejects an invalid closure resolver result', function (): void {
    $resolver = new ClosureCorsResolver(static fn (Request $request): ?CorsPolicy => null);

    expect(fn (): CorsPolicy => $resolver->resolve(Request::create('/api/resource')))
        ->toThrow(UnexpectedValueException::class);
});

it('rejects an invalid route parameter resolver result', function (): void {
    $resolver = new RouteParameterCorsResolver('tenant', static fn (string $tenant, Request $request): ?CorsPolicy => null);
    $request = Request::create('/api/resource');
    $request->setRouteResolver(static fn (): object => new class
    {
        public function parameter(string $name): string
        {
            return 'tenant-a';
        }
    });

    expect(fn (): CorsPolicy => $resolver->resolve($request))
        ->toThrow(UnexpectedValueException::class);
});

it('normalizes and validates resolver context cache segments', function (): void {
    $request = Request::create('/api/resource', 'post', ['filter' => ['z' => 1, 'a' => 2]]);
    $context = CorsResolverContext::fromRequest($request, 'resolver', ['api/*'], 'custom', 2, 'tenant');

    expect($context->cacheKey())->toStartWith('custom:2:')
        ->and($context->resolverKey())->toBe('resolver')
        ->and($context->tenantKey())->toBe('tenant')
        ->and($context->cacheKey('other', 'v2'))->toStartWith('other:v2:');

    expect(fn (): CorsResolverContext => CorsResolverContext::fromRequest($request, 'resolver', [], 'invalid/value'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn (): CorsResolverContext => $context->cacheKey('invalid/value'))
        ->toThrow(InvalidArgumentException::class);
});

it('rejects invalid closure failure responses', function (): void {
    $resolver = new ClosureCorsFailureResponse(static fn (Request $request, CorsFailure $failure): ?Response => null);

    expect(fn (): Response => $resolver->respond(Request::create('/api/resource'), new CorsFailure('test', 403, true)))
        ->toThrow(UnexpectedValueException::class);
});
