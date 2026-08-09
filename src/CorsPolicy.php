<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver;

use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;
use EvanSchleret\LaravelCorsResolver\Support\OriginNormalizer;

final class CorsPolicy
{
    /**
     * @param  list<string>  $allowedOrigins
     * @param  list<string>  $allowedMethods
     * @param  list<string>  $allowedHeaders
     * @param  list<string>  $exposedHeaders
     */
    private function __construct(
        private readonly array $allowedOrigins,
        private readonly array $allowedMethods,
        private readonly array $allowedHeaders,
        private readonly array $exposedHeaders,
        private readonly int $maxAge,
        private readonly bool $allowCredentials,
    ) {}

    public static function make(): self
    {
        return new self([], ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], [], [], 0, false);
    }

    public static function deny(): self
    {
        return new self([], [], [], [], 0, false);
    }

    /** @param list<string>|string $origins */
    public function allowOrigins(array|string $origins): self
    {
        return $this->with(allowedOrigins: $this->normalizeOrigins($origins));
    }

    /** @param list<string>|string $methods */
    public function allowMethods(array|string $methods): self
    {
        return $this->with(allowedMethods: $this->normalizeTokens($methods, true));
    }

    /** @param list<string>|string $headers */
    public function allowHeaders(array|string $headers): self
    {
        return $this->with(allowedHeaders: $this->normalizeTokens($headers));
    }

    /** @param list<string>|string $headers */
    public function exposeHeaders(array|string $headers): self
    {
        return $this->with(exposedHeaders: $this->normalizeTokens($headers));
    }

    public function maxAge(int $seconds): self
    {
        if ($seconds < 0) {
            throw new CorsConfigurationException('CORS max_age cannot be negative.');
        }

        return $this->with(maxAge: $seconds);
    }

    public function allowCredentials(bool $allow = true): self
    {
        if ($allow && ($this->containsWildcard($this->allowedOrigins) || $this->containsWildcard($this->allowedMethods) || $this->containsWildcard($this->allowedHeaders))) {
            throw new CorsConfigurationException('CORS wildcards cannot be combined with credentials.');
        }

        return $this->with(allowCredentials: $allow);
    }

    public function allowsOrigin(string $origin): bool
    {
        foreach ($this->allowedOrigins as $allowedOrigin) {
            if (OriginNormalizer::matches($allowedOrigin, $origin) && (! $this->allowCredentials || $allowedOrigin !== '*')) {
                return true;
            }
        }

        return false;
    }

    public function allowsMethod(string $method): bool
    {
        return in_array(strtoupper($method), $this->allowedMethods, true) || in_array('*', $this->allowedMethods, true);
    }

    /**
     * @param  list<string>  $headers
     */
    public function allowsHeaders(array $headers): bool
    {
        if (in_array('*', $this->allowedHeaders, true)) {
            return ! $this->allowCredentials;
        }

        $allowedHeaders = array_map('strtolower', $this->allowedHeaders);

        foreach ($headers as $header) {
            if (! in_array(strtolower($header), $allowedHeaders, true)) {
                return false;
            }
        }

        return true;
    }

    /** @return list<string> */
    public function allowedOrigins(): array
    {
        return $this->allowedOrigins;
    }

    /** @return list<string> */
    public function allowedMethods(): array
    {
        return $this->allowedMethods;
    }

    /** @return list<string> */
    public function allowedHeaders(): array
    {
        return $this->allowedHeaders;
    }

    /** @return list<string> */
    public function exposedHeaders(): array
    {
        return $this->exposedHeaders;
    }

    public function maxAgeValue(): int
    {
        return $this->maxAge;
    }

    public function allowsCredentials(): bool
    {
        return $this->allowCredentials;
    }

    public function allowsAllOrigins(): bool
    {
        return in_array('*', $this->allowedOrigins, true);
    }

    /** @return array<string, list<string>|int|bool> */
    public function toArray(): array
    {
        return [
            'allowed_origins' => $this->allowedOrigins,
            'allowed_methods' => $this->allowedMethods,
            'allowed_headers' => $this->allowedHeaders,
            'exposed_headers' => $this->exposedHeaders,
            'max_age' => $this->maxAge,
            'allow_credentials' => $this->allowCredentials,
        ];
    }

    /**
     * @param  list<string>|null  $allowedOrigins
     * @param  list<string>|null  $allowedMethods
     * @param  list<string>|null  $allowedHeaders
     * @param  list<string>|null  $exposedHeaders
     */
    private function with(
        ?array $allowedOrigins = null,
        ?array $allowedMethods = null,
        ?array $allowedHeaders = null,
        ?array $exposedHeaders = null,
        ?int $maxAge = null,
        ?bool $allowCredentials = null,
    ): self {
        $policy = new self(
            $allowedOrigins ?? $this->allowedOrigins,
            $allowedMethods ?? $this->allowedMethods,
            $allowedHeaders ?? $this->allowedHeaders,
            $exposedHeaders ?? $this->exposedHeaders,
            $maxAge ?? $this->maxAge,
            $allowCredentials ?? $this->allowCredentials,
        );

        if ($policy->allowCredentials && ($policy->containsWildcard($policy->allowedOrigins) || $policy->containsWildcard($policy->allowedMethods) || $policy->containsWildcard($policy->allowedHeaders))) {
            throw new CorsConfigurationException('CORS wildcards cannot be combined with credentials.');
        }

        return $policy;
    }

    /**
     * @param  list<string>|string  $origins
     * @return list<string>
     */
    private function normalizeOrigins(array|string $origins): array
    {
        $origins = is_array($origins) ? $origins : [$origins];

        return array_values(array_unique(array_map(static fn (string $origin): string => OriginNormalizer::normalize($origin), $origins)));
    }

    /**
     * @param  list<string>|string  $tokens
     * @return list<string>
     */
    private function normalizeTokens(array|string $tokens, bool $uppercase = false): array
    {
        $tokens = is_array($tokens) ? $tokens : [$tokens];
        $normalized = [];

        foreach ($tokens as $token) {
            $token = trim($token);

            if ($token === '*') {
                $normalized[] = $token;

                continue;
            }

            if ($token === '' || preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/', $token) !== 1) {
                throw new CorsConfigurationException(sprintf('Invalid CORS header or method token [%s].', $token));
            }

            $normalized[] = $uppercase ? strtoupper($token) : strtolower($token);
        }

        return array_values(array_unique($normalized));
    }

    /** @param list<string> $values */
    private function containsWildcard(array $values): bool
    {
        return in_array('*', $values, true) || array_filter($values, static fn (string $value): bool => str_contains($value, '*')) !== [];
    }
}
