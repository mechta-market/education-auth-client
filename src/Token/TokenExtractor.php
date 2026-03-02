<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Token;

use Psr\Http\Message\ServerRequestInterface;

final readonly class TokenExtractor
{
    public function extract(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');
        if ($header && str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        $token = $request->getQueryParams()['token'] ?? null;

        return is_string($token) ? $token : null;
    }
}