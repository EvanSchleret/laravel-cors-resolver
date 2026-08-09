<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Support;

use EvanSchleret\LaravelCorsResolver\Exceptions\CorsConfigurationException;

final class OriginNormalizer
{
    public static function normalize(string $origin): string
    {
        $origin = trim($origin);

        if ($origin === '' || preg_match('/[\x00-\x1F\x7F\s]/', $origin) === 1) {
            throw new CorsConfigurationException('A CORS origin must be a non-empty origin without whitespace.');
        }

        if ($origin === '*') {
            return $origin;
        }

        $origin = rtrim($origin, '/');

        if (str_contains($origin, '*')) {
            return self::normalizeWildcard($origin);
        }

        $parts = parse_url($origin);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw new CorsConfigurationException(sprintf('Invalid CORS origin [%s].', $origin));
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        $port = isset($parts['port']) ? (int) $parts['port'] : null;

        if (! in_array($scheme, ['http', 'https'], true) || $host === '') {
            throw new CorsConfigurationException(sprintf('Invalid CORS origin [%s].', $origin));
        }

        if (isset($parts['user'], $parts['pass'], $parts['path'], $parts['query'], $parts['fragment'])) {
            throw new CorsConfigurationException(sprintf('Invalid CORS origin [%s].', $origin));
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new CorsConfigurationException(sprintf('Invalid CORS origin [%s].', $origin));
        }

        if (isset($parts['path']) && $parts['path'] !== '') {
            throw new CorsConfigurationException(sprintf('Invalid CORS origin [%s].', $origin));
        }

        if ($port !== null && filter_var($port, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]) === false) {
            throw new CorsConfigurationException(sprintf('Invalid CORS origin [%s].', $origin));
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

        $pattern = '/^'.str_replace('\\*', '([a-z0-9-]+(?:\\.[a-z0-9-]+)*)', preg_quote($allowedOrigin, '/')).'$/i';

        return preg_match($pattern, $requestOrigin) === 1;
    }

    private static function normalizeWildcard(string $origin): string
    {
        if (preg_match('/^(https?):\/\/\*\.([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(?::([0-9]{1,5}))?$/i', $origin, $matches) !== 1) {
            throw new CorsConfigurationException(sprintf('Invalid wildcard CORS origin [%s].', $origin));
        }

        $scheme = strtolower($matches[1]);
        $port = isset($matches[3]) ? (int) $matches[3] : null;

        if ($port !== null && filter_var($port, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]) === false) {
            throw new CorsConfigurationException(sprintf('Invalid wildcard CORS origin [%s].', $origin));
        }

        if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
            $port = null;
        }

        return $scheme.'://*.'.strtolower($matches[2]).($port === null ? '' : ':'.$port);
    }
}
