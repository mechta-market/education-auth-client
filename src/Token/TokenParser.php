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

        if (!property_exists($decoded, 'payload')) {
            throw new UnexpectedValueException('Token payload not set');
        }
        if (
            !property_exists($decoded->payload, 'zup_subdivision_id') ||
            !property_exists($decoded->payload, 'user_id') ||
            !property_exists($decoded->payload, 'zup_user_id')
        ) {
            throw new UnexpectedValueException('Token payload invalid');
        }

        return Uuid::fromString($decoded->payload->zup_user_id);
    }
}
