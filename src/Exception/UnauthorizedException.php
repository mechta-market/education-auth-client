<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Exception;

use Throwable;

final class UnauthorizedException extends AuthClientException
{
    public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message ?? 'Unauthorized', 401, $previous);
    }
}
