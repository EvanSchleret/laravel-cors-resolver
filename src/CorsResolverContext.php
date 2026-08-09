<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver;

use Illuminate\Http\Request;

final class CorsResolverContext
{
    private function __construct(private readonly string $cacheKey) {}

    /** @param list<string> $paths */
    public static function fromRequest(Request $request, string $resolverKey, array $paths): self
    {
        $headers = $request->headers->all();
        ksort($headers);

        $query = $request->query->all();
        self::sortRecursive($query);

        $payload = [
            'resolver' => $resolverKey,
            'paths' => $paths,
            'method' => strtoupper($request->getMethod()),
            'scheme_host' => $request->getSchemeAndHttpHost(),
            'path' => $request->path(),
            'query' => $query,
            'headers' => $headers,
            'body_hash' => hash('sha256', $request->getContent()),
        ];

        return new self('laravel-cors-resolver:'.hash('sha256', json_encode($payload, JSON_THROW_ON_ERROR)));
    }

    public function cacheKey(): string
    {
        return $this->cacheKey;
    }

    /** @param array<int|string, mixed> $value */
    private static function sortRecursive(array &$value): void
    {
        foreach ($value as &$item) {
            if (is_array($item)) {
                self::sortRecursive($item);
            }
        }

        if (! array_is_list($value)) {
            ksort($value);
        }
    }
}
