<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Token;

use MechtaMarket\AuthClient\Exception\BeforeValidException;
use MechtaMarket\AuthClient\Exception\ExpiredException;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use UnexpectedValueException;

readonly class TokenParser
{
    /**
     * @param string $token
     * @return UuidInterface
     * @throws BeforeValidException
     * @throws ExpiredException
     */
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
