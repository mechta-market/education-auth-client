<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Middleware;

use MechtaMarket\AuthClient\Exception\UnauthorizedException;
use MechtaMarket\AuthClient\Token\TokenExtractor;
use MechtaMarket\AuthClient\Token\TokenParser;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class SpiralTokenParserMiddleware implements MiddlewareInterface
{
    public function __construct(
        private TokenParser $tokenParser,
        private TokenExtractor $tokenExtractor,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$token = $this->tokenExtractor->extract($request)) {
            throw new UnauthorizedException('No authentication token provided');
        }

        $userId = $this->tokenParser->parse($token);
        $request = $request->withAttribute('user_id', $userId);

        return $handler->handle($request);
    }
}
