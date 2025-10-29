<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use MechtaMarket\AuthClient\Exception\UnauthorizedException;
use MechtaMarket\AuthClient\Token\TokenParser;

final readonly class LaravelTokenParserMiddleware
{
    public function __construct(
        private TokenParser $tokenParser,
    ) {}

    /**
     * @throws UnauthorizedException
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (!$token = $this->extractToken($request)) {
            throw new UnauthorizedException('No authentication token provided');
        }

        $userId = $this->tokenParser->parse($token);
        $request->attributes->set('user_id', $userId);

        return $next($request);
    }

    private function extractToken(Request $request): ?string
    {
        $header = $request->header('Authorization');
        if (is_string($header) && str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        $token = $request->query('token');
        return is_string($token) ? $token : null;
    }
}
