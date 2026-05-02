<?php

declare(strict_types=1);

use Yiisoft\Security\CryptProviderInterface;
use Yiisoft\Security\CryptProvider\AesAeadCryptProvider;
use Yiisoft\Security\CryptProvider\AesCbcCryptProvider;
use Yiisoft\Security\CryptProvider\SodiumCryptProvider;

/** @var array $params */

return [
    //CryptProviderInterface::class => AesAeadCryptProvider::class,
    //CryptProviderInterface::class => AesCbcCryptProvider::class,
    CryptProviderInterface::class => SodiumCryptProvider::class,
];
