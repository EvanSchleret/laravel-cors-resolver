<?php

declare(strict_types=1);

return [
    'paths' => ['api/*'],

    'resolver' => null,

    'failure_mode' => 'deny',

    'cache' => [
        'enabled' => false,
        'store' => null,
        'ttl' => 300,
        'namespace' => 'laravel-cors-resolver',
        'version' => 'v1',
        'tenant_parameter' => null,
    ],
];
