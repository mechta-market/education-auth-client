<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Token;

use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use UnexpectedValueException;

final readonly class TokenParser
{
    public function parse(string $token): UuidInterface
    {
        $decoded = Jwt::decode($token);

        if (!property_exists($decoded, 'resource_access') || !property_exists($decoded, 'emp_id')) {
            throw new UnexpectedValueException('Token resource_access not set');
        }
        if (!property_exists($decoded->resource_access, 'education')) {
            throw new UnexpectedValueException('Token resource_access invalid');
        }

        return Uuid::fromString($decoded->emp_id);
    }
}
