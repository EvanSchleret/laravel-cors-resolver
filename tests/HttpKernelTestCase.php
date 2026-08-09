<?php

declare(strict_types=1);

namespace Tests;

use EvanSchleret\LaravelCorsResolver\CorsResolver;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;

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

    public function setNativeCorsConfiguration(array $configuration): void
    {
        $this->app['config']->set('cors', $configuration);
    }

    protected function defineRoutes($router): void
    {
        $router->bind('resource', static fn (string $value): string => 'bound-'.$value);

        $router->match(['GET', 'POST', 'OPTIONS'], '/api/resource', static function () {
            return response()->json(['handled' => true]);
        })->middleware('cors.resolve');

        $router->match(['GET', 'OPTIONS'], '/api/bound-resources/{resource}', static function (Request $request) {
            return response()->json(['resource' => $request->route('resource')]);
        })->middleware([SubstituteBindings::class, 'cors.resolve']);

        $router->match(['GET', 'OPTIONS'], '/api/private-resource', static function () {
            return response()->json(['private' => true]);
        })->middleware(['cors.resolve', 'auth']);
    }
}
