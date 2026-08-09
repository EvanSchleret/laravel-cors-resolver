<?php

declare(strict_types=1);

namespace Tests;

use EvanSchleret\LaravelCorsResolver\CorsResolver;

abstract class HttpKernelTestCase extends TestCase
{
    protected function defineEnvironment($app): void
    {
        $app['config']->set('cors.paths', []);
    }

    public function setHttpKernelCorsResolver(CorsResolver $resolver): void
    {
        $this->instance(CorsResolver::class, $resolver);
    }

    protected function defineRoutes($router): void
    {
        $router->match(['GET', 'POST', 'OPTIONS'], '/api/resource', static function () {
            return response()->json(['handled' => true]);
        })->middleware('cors.resolve');
    }
}
