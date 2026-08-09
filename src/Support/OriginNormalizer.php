<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Support;

use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;

final class OriginNormalizer
{
    public static function normalize(string $origin): string
    {
        if ($origin === '' || preg_match('/[\x00-\x1F\x7F\s]/', $origin) === 1) {
            throw new CorsConfigurationException('A CORS origin must be a non-empty origin without whitespace.');
        }

        if ($origin === '*') {
            return $origin;
        }

        $origin = rtrim($origin, '/');

        if ($origin === '') {
            throw new CorsConfigurationException('A CORS origin must be a non-empty origin.');
        }

        if (str_contains($origin, '*')) {
            return self::normalizeWildcard($origin);
        }

        $parts = parse_url($origin);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw self::invalidOrigin($origin);
        }

        $scheme = strtolower((string) $parts['scheme']);

        if (! in_array($scheme, ['http', 'https'], true)) {
            throw self::invalidOrigin($origin);
        }

        if (array_key_exists('user', $parts)
            || array_key_exists('pass', $parts)
            || array_key_exists('query', $parts)
            || array_key_exists('fragment', $parts)
            || (array_key_exists('path', $parts) && $parts['path'] !== '')) {
            throw self::invalidOrigin($origin);
        }

        $host = self::normalizeHost((string) $parts['host'], $origin);
        $port = isset($parts['port']) ? (int) $parts['port'] : null;

        if ($port !== null && filter_var($port, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]) === false) {
            throw self::invalidOrigin($origin);
        }

        if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
            $port = null;
        }

        return $scheme.'://'.$host.($port === null ? '' : ':'.$port);
    }

    public static function matches(string $allowedOrigin, string $requestOrigin): bool
    {
        try {
            $requestOrigin = self::normalize($requestOrigin);
        } catch (CorsConfigurationException) {
            return false;
        }

        if ($allowedOrigin === '*') {
            return true;
        }

        if (! str_contains($allowedOrigin, '*')) {
            return $allowedOrigin === $requestOrigin;
        }

        $pattern = '/^'.str_replace('\\*', '([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)', preg_quote($allowedOrigin, '/')).'$/i';

        return preg_match($pattern, $requestOrigin) === 1;
    }

    private static function normalizeWildcard(string $origin): string
    {
        if (preg_match('/^(https?):\/\/\*\.([^:\/?#]+)(?::([0-9]{1,5}))?$/i', $origin, $matches) !== 1) {
            throw self::invalidOrigin($origin);
        }

        $scheme = strtolower($matches[1]);
        $host = self::normalizeHost($matches[2], $origin);

        if (! str_contains($host, '.') || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            throw self::invalidOrigin($origin);
        }

        $port = isset($matches[3]) ? (int) $matches[3] : null;

        if ($port !== null && filter_var($port, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]) === false) {
            throw self::invalidOrigin($origin);
        }

        if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
            $port = null;
        }

        return $scheme.'://*.'.$host.($port === null ? '' : ':'.$port);
    }

    private static function normalizeHost(string $host, string $origin): string
    {
        if (str_starts_with($host, '[') || str_ends_with($host, ']')) {
            if (! str_starts_with($host, '[') || ! str_ends_with($host, ']')) {
                throw self::invalidOrigin($origin);
            }

            $ipv6 = substr($host, 1, -1);

            if (filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                throw self::invalidOrigin($origin);
            }

            $packed = inet_pton($ipv6);
            $canonical = $packed === false ? false : inet_ntop($packed);

            if ($canonical === false) {
                throw self::invalidOrigin($origin);
            }

            return '['.strtolower($canonical).']';
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $host;
        }

        if (preg_match('/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\z/i', $host) !== 1) {
            throw self::invalidOrigin($origin);
        }

        return strtolower($host);
    }

    private static function invalidOrigin(string $origin): CorsConfigurationException
    {
        return new CorsConfigurationException(sprintf('Invalid CORS origin [%s].', $origin));
    }
}
