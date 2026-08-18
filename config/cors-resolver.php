<?php

declare(strict_types=1);

return [
    'paths' => ['api/*'],

    'resolver' => null,

    'failure_mode' => 'deny',

    'resolver_exception_mode' => 'deny',

    'observability' => [
        'enabled' => true,
    ],

    'cache' => [
        'enabled' => false,
        'store' => null,
        'ttl' => 300,
        'namespace' => 'laravel-cors-resolver',
        'version' => 'v1',
        'tenant_parameter' => null,
        'lock' => [
            'enabled' => true,
            'ttl' => 10,
            'wait' => 5,
        ],
    ],
];
