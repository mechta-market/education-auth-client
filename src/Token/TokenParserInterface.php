<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Token;

use MechtaMarket\AuthClient\Exception\BeforeValidException;
use MechtaMarket\AuthClient\Exception\ExpiredException;
use Ramsey\Uuid\UuidInterface;

interface TokenParserInterface
{
    /**
     * @param string $token
     * @return UuidInterface
     * @throws BeforeValidException
     * @throws ExpiredException
     */
    public function parse(string $token): UuidInterface;
}
