<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Permission;

use MechtaMarket\AuthClient\Exception\AuthClientException;
use MechtaMarket\AuthClient\Exception\UnauthorizedException;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class PermissionValidator
{
    private HttpClientInterface $httpClient;

    public function __construct(
        PermissionConfig $config,
        private readonly int $retryAttempts = 3,
        private readonly int $retryDelay = 100,
    ) {
        $this->httpClient = HttpClient::create([
            'base_uri' => $config->getAuthCenterUrl(),
            'timeout' => $config->getTimeout(),
            'headers' => [
                'Authorization' => trim(sprintf('Bearer %s', $config->getToken())),
            ],
        ]);
    }

    /**
     * @throws AuthClientException
     * @throws ClientExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     */
    public function validate(string $permissionName, UuidInterface $userId): bool
    {
        $responseData = $this->checkPermissionWithRetry($permissionName, $userId);

        return $responseData['has_permission'];
    }

    /**
     * @throws AuthClientException
     * @throws ClientExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     */
    private function checkPermissionWithRetry(string $permissionName, UuidInterface $userId): array
    {
        $lastException = null;

        for ($attempt = 1; $attempt <= $this->retryAttempts; $attempt++) {
            try {
                return $this->checkPermission($permissionName, $userId);
            } catch (AuthClientException $exception) {
                $lastException = $exception;

                if ($exception instanceof UnauthorizedException) {
                    throw $exception;
                }

                if ($attempt < $this->retryAttempts) {
                    usleep($this->retryDelay * 1000);
                    continue;
                }
            }
        }

        throw $lastException ?? new AuthClientException('Permission check failed');
    }

    /**
     * @throws AuthClientException
     * @throws ClientExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     * @throws UnauthorizedException
     */
    private function checkPermission(string $permissionName, UuidInterface $userId): array
    {
        try {
            $response = $this->httpClient->request(
                'GET',
                sprintf('user/%s/permission/%s', $userId->toString(), $permissionName),
            );

            $statusCode = $response->getStatusCode();
            if ($statusCode === 401) {
                throw new UnauthorizedException('AuthClient not authenticated');
            }

            $responseData = json_decode($response->getContent(false), true);

            if ($statusCode !== 200) {
                if (isset($responseData['code']) && $responseData['code'] === 'object_not_found') {
                    return ['has_permission' => false];
                }

                throw new AuthClientException(
                    "Unexpected response from AuthCenter: {$statusCode}",
                );
            }
            if (!is_array($responseData)) {
                throw new AuthClientException('Invalid response format from Auth Center');
            }

            return $responseData;
        } catch (TransportExceptionInterface $exception) {
            throw new AuthClientException(
                'Failed to communicate with AuthCenter: ' . $exception->getMessage(),
                0,
                $exception,
            );
        }
    }
}
