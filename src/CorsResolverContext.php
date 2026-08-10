<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver;

use Illuminate\Http\Request;
use InvalidArgumentException;

final class CorsResolverContext
{
    private function __construct(
        private readonly string $fingerprint,
        private readonly string $resolverKey,
        private readonly ?string $tenantKey,
        private readonly string $namespace,
        private readonly string $version,
    ) {}

    /** @param list<string> $paths */
    public static function fromRequest(
        Request $request,
        string $resolverKey,
        array $paths,
        string $namespace = 'laravel-cors-resolver',
        string|int $version = 'v1',
        ?string $tenantKey = null,
    ): self {
        $namespace = self::normalizeSegment($namespace, 'namespace');
        $version = self::normalizeSegment((string) $version, 'version');

        $headers = $request->headers->all();
        ksort($headers);

        $query = $request->query->all();
        self::sortRecursive($query);

        $payload = [
            'resolver' => $resolverKey,
            'tenant' => $tenantKey,
            'paths' => $paths,
            'method' => strtoupper($request->getMethod()),
            'scheme_host' => $request->getSchemeAndHttpHost(),
            'path' => $request->path(),
            'query' => $query,
            'headers' => $headers,
            'body_hash' => hash('sha256', $request->getContent()),
        ];

        return new self(
            hash('sha256', json_encode($payload, JSON_THROW_ON_ERROR)),
            $resolverKey,
            $tenantKey,
            $namespace,
            $version,
        );
    }

    public function cacheKey(?string $namespace = null, string|int|null $version = null): string
    {
        $namespace ??= $this->namespace;
        $version = (string) ($version ?? $this->version);

        return self::normalizeSegment($namespace, 'namespace').':'.self::normalizeSegment($version, 'version').':'.$this->fingerprint;
    }

    public function resolverKey(): string
    {
        return $this->resolverKey;
    }

    public function tenantKey(): ?string
    {
        return $this->tenantKey;
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

    private static function normalizeSegment(string $value, string $name): string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9._-]+$/', $value) !== 1) {
            throw new InvalidArgumentException(sprintf('The cache %s must contain only letters, numbers, dots, underscores, or hyphens.', $name));
        }

        return $value;
    }
}
