<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Http\Middleware;

use Closure;
use EvanSchleret\LaravelCorsResolver\Cache\CorsPolicyCache;
use EvanSchleret\LaravelCorsResolver\CorsPolicy;
use EvanSchleret\LaravelCorsResolver\CorsResolver;
use EvanSchleret\LaravelCorsResolver\CorsResolverContext;
use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;
use EvanSchleret\LaravelCorsResolver\Support\OriginNormalizer;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

final class ResolveCors
{
    public function __construct(
        private readonly CorsResolver $resolver,
        private readonly CorsPolicyCache $cache,
        private readonly ConfigRepository $config,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $origin = $request->headers->get('Origin');

        if ($origin === null || trim($origin) === '' || ! $this->matchesConfiguredPath($request)) {
            return $next($request);
        }

        $paths = $this->configuredPaths();
        $context = CorsResolverContext::fromRequest($request, get_class($this->resolver), $paths);
        $policy = $this->cache->remember($context, fn (): CorsPolicy => $this->resolver->resolve($request));

        if ($request->isMethod('OPTIONS')) {
            return $this->handlePreflight($request, $next, $policy, $origin);
        }

        $response = $next($request);
        $this->addVary($response, ['Origin']);

        if ($policy->allowsOrigin($origin) && $policy->allowsMethod($request->getMethod())) {
            $this->addActualHeaders($response, $policy, $origin);
        }

        return $response;
    }

    private function handlePreflight(Request $request, Closure $next, CorsPolicy $policy, string $origin): Response
    {
        $requestedMethod = strtoupper(trim((string) $request->headers->get('Access-Control-Request-Method')));
        try {
            $requestedHeaders = $this->requestedHeaders($request->headers->get('Access-Control-Request-Headers'));
        } catch (CorsConfigurationException) {
            $requestedHeaders = [];
        }
        $allowed = $requestedMethod !== ''
            && $policy->allowsOrigin($origin)
            && $policy->allowsMethod($requestedMethod)
            && $policy->allowsHeaders($requestedHeaders);

        if (! $allowed) {
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

    private function failureMode(): string
    {
        $mode = (string) $this->config->get('cors-resolver.failure_mode', 'deny');

        if (! in_array($mode, ['deny', 'passthrough'], true)) {
            throw new CorsConfigurationException('cors-resolver.failure_mode must be deny or passthrough.');
        }

        return $mode;
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
