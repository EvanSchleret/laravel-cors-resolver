<?php

declare(strict_types=1);

namespace Tests;

use EvanSchleret\LaravelCorsResolver\Providers\LaravelCorsResolverServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [LaravelCorsResolverServiceProvider::class];
    }
}
