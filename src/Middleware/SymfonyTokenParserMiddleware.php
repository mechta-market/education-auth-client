<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Middleware;

use MechtaMarket\AuthClient\Exception\UnauthorizedException;
use MechtaMarket\AuthClient\Token\TokenParser;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final readonly class SymfonyTokenParserMiddleware implements EventSubscriberInterface
{
    public function __construct(
        private TokenParser $tokenParser,
    ) {}

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 10],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $authRequired = $request->attributes->get('_auth_required', false);

        if (!$authRequired) {
            return;
        }

        if (!$token = $this->extractToken($request)) {
            throw new UnauthorizedException('No authentication token provided');
        }

        $userId = $this->tokenParser->parse($token);
        $request->attributes->set('user_id', $userId);
    }

    private function extractToken(Request $request): ?string
    {
        $header = $request->headers->get('Authorization');
        if (is_string($header) && str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        $token = $request->query->get('token');
        return is_string($token) ? $token : null;
    }
}
