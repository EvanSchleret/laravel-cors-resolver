<?php

declare(strict_types=1);

namespace EvanSchleret\LaravelCorsResolver\Exceptions;

use RuntimeException;
use Throwable;

final class CorsResolverException extends RuntimeException
{
    public function __construct(Throwable $previous)
    {
        parent::__construct('The CORS resolver failed.', 0, $previous);
    }
}
