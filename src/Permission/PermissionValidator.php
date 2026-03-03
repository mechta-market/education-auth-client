<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Permission;

use MechtaMarket\AuthClient\Exception\UnauthorizedException;
use MechtaMarket\AuthClient\Token\Jwt;
use MechtaMarket\AuthClient\Token\TokenExtractor;
use Psr\Http\Message\ServerRequestInterface;

final readonly class PermissionValidator
{
    public function __construct(
        private ServerRequestInterface $request,
        private TokenExtractor $tokenExtractor,
    ) {}

    public function validate(array $roleNames): bool
    {
        $token = $this->tokenExtractor->extract($this->request) ?? throw new UnauthorizedException('No authentication token provided');

        $payload = Jwt::decode($token);

        $authRoles = (array) ($payload->resource_access?->education?->roles ?? []);

        return !empty(array_intersect($roleNames, $authRoles));
    }
}