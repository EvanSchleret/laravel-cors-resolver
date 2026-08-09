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
    ],
];
