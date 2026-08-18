<?php

declare(strict_types=1);

use EvanSchleret\LaravelCorsResolver\Cache\CorsPolicyCache;
use EvanSchleret\LaravelCorsResolver\CorsFailureResponse;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use EvanSchleret\LaravelCorsResolver\Http\Middleware\ResolveCors;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

uses(TestCase::class)->in('Feature');

function makeCorsMiddleware(CorsResolver $resolver, ?CorsPolicyCache $cache = null, array $configuration = [], ?Dispatcher $events = null, ?CorsFailureResponse $failureResponse = null): ResolveCors
{
    $config = new ConfigRepository(array_merge([
        'cors-resolver' => [
            'paths' => ['api/*'],
            'failure_mode' => 'deny',
        ],
    ], $configuration));

    return new ResolveCors($resolver, $cache ?? new CorsPolicyCache(null, 0), $config, $events, $failureResponse);
}

function makeRequest(string $method, string $origin, array $headers = []): Request
{
    $server = ['HTTP_ORIGIN' => $origin];

    foreach ($headers as $name => $value) {
        $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
    }

    return Request::create('/api/resource', $method, server: $server);
}

function nextResponse(int $status = Response::HTTP_OK, array $headers = []): Closure
{
    return static fn (Request $request): Response => new Response('', $status, $headers);
}

function cachedCorsPolicyCache(int $ttl = 300): CorsPolicyCache
{
    return new CorsPolicyCache(new CacheRepository(new ArrayStore), $ttl);
}
