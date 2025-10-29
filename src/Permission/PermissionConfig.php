<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Permission;

final readonly class PermissionConfig
{
    public function __construct(
        private string $token,
        private string $authCenterUrl,
        private int $timeout = 10,
    ) {}

    public function getToken(): string
    {
        return $this->token;
    }

    public function getAuthCenterUrl(): string
    {
        return $this->authCenterUrl;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }
}
