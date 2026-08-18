<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Http\Middleware;

use Closure;
use EvanSchleret\LaravelCorsResolver\Cache\CorsPolicyCache;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use EvanSchleret\LaravelCorsResolver\Events\CorsRequestDenied;
use EvanSchleret\LaravelCorsResolver\Events\CorsResolverFailed;
use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;
use EvanSchleret\LaravelCorsResolver\Exceptions\CorsResolverException;
use EvanSchleret\LaravelCorsResolver\Support\OriginNormalizer;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class ResolveCors
{
    public function __construct(
        private readonly CorsResolver $resolver,
        private readonly CorsPolicyCache $cache,
        private readonly ConfigRepository $config,
        private readonly ?Dispatcher $events = null,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $origin = $request->headers->get('Origin');

        if ($origin === null || trim($origin) === '' || ! $this->matchesConfiguredPath($request)) {
            return $next($request);
        }

        $paths = $this->configuredPaths();
        $context = CorsResolverContext::fromRequest(
            $request,
            get_class($this->resolver),
            $paths,
            $this->cacheNamespace(),
            $this->cacheVersion(),
            $this->tenantKey($request),
        );
        try {
            $policy = $this->cache->remember($context, fn (): CorsPolicy => $this->resolvePolicy($request));
        } catch (CorsResolverException $exception) {
            $mode = $this->resolverExceptionMode();
            $original = $exception->getPrevious();
            $this->dispatch(new CorsResolverFailed(
                $request,
                $original instanceof Throwable ? $original : $exception,
                $mode,
            ));

            return $this->handleResolverException($request, $exception, $mode);
        }

        if ($request->isMethod('OPTIONS')) {
            return $this->handlePreflight($request, $next, $policy, $origin);
        }

        $response = $next($request);
        $this->addVary($response, ['Origin']);

        $originAllowed = $policy->allowsOrigin($origin);
        $methodAllowed = $policy->allowsMethod($request->getMethod());

        if ($originAllowed && $methodAllowed) {
            $this->addActualHeaders($response, $policy, $origin);
        } else {
            $this->recordDenied(
                $request,
                $origin,
                $originAllowed ? 'method_not_allowed' : 'origin_not_allowed',
                false,
                $request->getMethod(),
            );
        }

        return $response;
    }

    private function handlePreflight(Request $request, Closure $next, CorsPolicy $policy, string $origin): Response
    {
        $requestedMethod = strtoupper(trim((string) $request->headers->get('Access-Control-Request-Method')));
        $headersValid = true;

        try {
            $requestedHeaders = $this->requestedHeaders($request->headers->get('Access-Control-Request-Headers'));
        } catch (CorsConfigurationException) {
            $headersValid = false;
            $requestedHeaders = [];
        }

        if (! $headersValid) {
            $this->recordDenied($request, $origin, 'invalid_requested_headers', true, $requestedMethod);

            return new Response('', Response::HTTP_FORBIDDEN, [
                'Vary' => 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers',
            ]);
        }

        $allowed = $requestedMethod !== ''
            && $policy->allowsOrigin($origin)
            && $policy->allowsMethod($requestedMethod)
            && $policy->allowsHeaders($requestedHeaders);

        if (! $allowed) {
            $this->recordDenied($request, $origin, $this->preflightDenialReason($policy, $origin, $requestedMethod, $requestedHeaders), true, $requestedMethod);

            if ($this->failureMode() === 'passthrough') {
                $response = $next($request);
                $this->addVary($response, ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers']);

                return $response;
            }

            return new Response('', Response::HTTP_FORBIDDEN, [
                'Vary' => 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers',
            ]);
        }

        $response = new Response('', Response::HTTP_NO_CONTENT);
        $this->addVary($response, ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers']);
        $this->addPreflightHeaders($response, $policy, $origin, $requestedHeaders);

        return $response;
    }

    private function addActualHeaders(Response $response, CorsPolicy $policy, string $origin): void
    {
        $response->headers->set('Access-Control-Allow-Origin', $this->responseOrigin($policy, $origin));

        if ($policy->allowsCredentials()) {
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }

        if ($policy->exposedHeaders() !== []) {
            $response->headers->set('Access-Control-Expose-Headers', implode(', ', $policy->exposedHeaders()));
        }
    }

    /** @param list<string> $requestedHeaders */
    private function addPreflightHeaders(Response $response, CorsPolicy $policy, string $origin, array $requestedHeaders): void
    {
        $response->headers->set('Access-Control-Allow-Origin', $this->responseOrigin($policy, $origin));
        $response->headers->set('Access-Control-Allow-Methods', implode(', ', $policy->allowedMethods()));
        $response->headers->set('Access-Control-Allow-Headers', $policy->allowedHeaders() === [] ? implode(', ', $requestedHeaders) : implode(', ', $policy->allowedHeaders()));
        $response->headers->set('Access-Control-Max-Age', (string) $policy->maxAgeValue());

        if ($policy->allowsCredentials()) {
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }
    }

    private function responseOrigin(CorsPolicy $policy, string $origin): string
    {
        return $policy->allowsAllOrigins() ? '*' : $this->normalizedOrigin($origin);
    }

    private function normalizedOrigin(string $origin): string
    {
        try {
            return OriginNormalizer::normalize($origin);
        } catch (CorsConfigurationException) {
            return $origin;
        }
    }

    /** @return list<string> */
    private function requestedHeaders(?string $value): array
    {
        if ($value === null || trim($value) === '') {
            return [];
        }

        $headers = [];

        foreach (explode(',', $value) as $header) {
            $header = trim($header);

            if ($header === '' || preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/', $header) !== 1) {
                throw new CorsConfigurationException('The preflight request contains an invalid requested header.');
            }

            $headers[] = strtolower($header);
        }

        return array_values(array_unique($headers));
    }

    private function matchesConfiguredPath(Request $request): bool
    {
        $paths = $this->configuredPaths();

        return $paths !== [] && Str::is($paths, $request->path());
    }

    /** @return list<string> */
    private function configuredPaths(): array
    {
        $paths = $this->config->get('cors-resolver.paths', []);

        if (! is_array($paths)) {
            throw new CorsConfigurationException('cors-resolver.paths must be an array.');
        }

        return array_values(array_filter($paths, static fn (mixed $path): bool => is_string($path) && $path !== ''));
    }

    private function cacheNamespace(): string
    {
        $configuration = $this->config->get('cors-resolver.cache', []);

        return is_array($configuration) && is_string($configuration['namespace'] ?? null)
            ? $configuration['namespace']
            : 'laravel-cors-resolver';
    }

    private function cacheVersion(): string
    {
        $configuration = $this->config->get('cors-resolver.cache', []);

        return is_array($configuration) && is_string($configuration['version'] ?? null)
            ? $configuration['version']
            : 'v1';
    }

    private function tenantKey(Request $request): ?string
    {
        $configuration = $this->config->get('cors-resolver.cache', []);
        $parameter = is_array($configuration) ? $configuration['tenant_parameter'] ?? null : null;

        if (! is_string($parameter) || $parameter === '') {
            return null;
        }

        $tenant = $request->route($parameter);

        if (is_string($tenant)) {
            return (string) $tenant;
        }

        if (is_object($tenant) && method_exists($tenant, 'getRouteKey')) {
            $key = $tenant->getRouteKey();

            if (is_string($key) || is_int($key)) {
                return (string) $key;
            }
        }

        return null;
    }

    private function failureMode(): string
    {
        $mode = (string) $this->config->get('cors-resolver.failure_mode', 'deny');

        if (! in_array($mode, ['deny', 'passthrough'], true)) {
            throw new CorsConfigurationException('cors-resolver.failure_mode must be deny or passthrough.');
        }

        return $mode;
    }

    private function resolverExceptionMode(): string
    {
        $mode = (string) $this->config->get('cors-resolver.resolver_exception_mode', 'deny');

        if (! in_array($mode, ['deny', 'throw'], true)) {
            throw new CorsConfigurationException('cors-resolver.resolver_exception_mode must be deny or throw.');
        }

        return $mode;
    }

    private function resolvePolicy(Request $request): CorsPolicy
    {
        try {
            return $this->resolver->resolve($request);
        } catch (Throwable $exception) {
            throw new CorsResolverException($exception);
        }
    }

    private function handleResolverException(Request $request, CorsResolverException $exception, string $mode): Response
    {
        if ($mode === 'throw') {
            $previous = $exception->getPrevious();

            if ($previous instanceof Throwable) {
                throw $previous;
            }

            throw $exception;
        }

        $response = new Response('', Response::HTTP_SERVICE_UNAVAILABLE);
        $this->addVary($response, $request->isMethod('OPTIONS')
            ? ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers']
            : ['Origin']);

        return $response;
    }

    /** @param list<string> $requestedHeaders */
    private function preflightDenialReason(CorsPolicy $policy, string $origin, string $requestedMethod, array $requestedHeaders): string
    {
        if ($requestedMethod === '') {
            return 'invalid_requested_method';
        }

        if (! $policy->allowsOrigin($origin)) {
            return 'origin_not_allowed';
        }

        if (! $policy->allowsMethod($requestedMethod)) {
            return 'method_not_allowed';
        }

        if (! $policy->allowsHeaders($requestedHeaders)) {
            return 'headers_not_allowed';
        }

        return 'preflight_denied';
    }

    private function recordDenied(Request $request, string $origin, string $reason, bool $preflight, ?string $requestedMethod = null): void
    {
        $this->dispatch(new CorsRequestDenied($request, $origin, $reason, $preflight, $requestedMethod));
    }

    private function dispatch(object $event): void
    {
        if (! $this->observabilityEnabled() || $this->events === null) {
            return;
        }

        try {
            $this->events->dispatch($event);
        } catch (Throwable) {
        }
    }

    private function observabilityEnabled(): bool
    {
        $configuration = $this->config->get('cors-resolver.observability', []);

        return is_array($configuration) && ($configuration['enabled'] ?? true) === true;
    }

    /** @param list<string> $values */
    private function addVary(Response $response, array $values): void
    {
        $current = $response->headers->get('Vary', '');
        $headers = array_filter(array_map('trim', explode(',', $current)));
        $known = array_map('strtolower', $headers);

        foreach ($values as $value) {
            if (! in_array(strtolower($value), $known, true)) {
                $headers[] = $value;
                $known[] = strtolower($value);
            }
        }

        $response->headers->set('Vary', implode(', ', $headers));
    }
}
