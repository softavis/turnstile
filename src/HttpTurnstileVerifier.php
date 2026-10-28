<?php

declare(strict_types=1);

namespace Softavis\Turnstile;

use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Softavis\Turnstile\Exception\HttpStatusException;
use Softavis\Turnstile\Exception\ResponseException;
use Softavis\Turnstile\Exception\TransportException;

final readonly class HttpTurnstileVerifier implements TurnstileVerifier
{
    private const ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    private const MAX_TOKEN_LENGTH = 2048;

    public function __construct(
        private string $secret,
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private StreamFactoryInterface $streamFactory,
    ) {
        if (trim($this->secret) === '') {
            throw new InvalidArgumentException('The Turnstile secret must not be empty.');
        }
    }

    public function verify(VerificationRequest $request): VerificationResult
    {
        if (trim($request->response) === '' || strlen($request->response) > self::MAX_TOKEN_LENGTH) {
            return new VerificationResult(
                accepted: false,
                rejectionReasons: [RejectionReason::InvalidToken],
            );
        }

        $fields = [
            'secret' => $this->secret,
            'response' => $request->response,
        ];

        if ($request->remoteIp !== null) {
            $fields['remoteip'] = $request->remoteIp;
        }

        if ($request->idempotencyKey !== null) {
            $fields['idempotency_key'] = $request->idempotencyKey;
        }

        $httpRequest = $this->requestFactory
            ->createRequest('POST', self::ENDPOINT)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streamFactory->createStream(http_build_query($fields, '', '&', PHP_QUERY_RFC1738)));

        try {
            $response = $this->httpClient->sendRequest($httpRequest);
        } catch (ClientExceptionInterface $exception) {
            throw new TransportException($exception);
        }

        $statusCode = $response->getStatusCode();
        if ($statusCode < 200 || $statusCode >= 300) {
            throw new HttpStatusException($statusCode);
        }

        try {
            $body = json_decode($response->getBody()->getContents(), false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new ResponseException($exception);
        } catch (RuntimeException $exception) {
            throw new ResponseException($exception);
        }

        if (!is_object($body) || !property_exists($body, 'success') || !is_bool($body->success)) {
            throw new ResponseException();
        }

        $metadata = [];
        foreach (['hostname', 'action', 'challenge_ts', 'cdata'] as $field) {
            if (property_exists($body, $field)) {
                if (!is_string($body->{$field})) {
                    throw new ResponseException();
                }

                $metadata[$field] = $body->{$field};
            }
        }

        $errorCodes = [];
        if (property_exists($body, 'error-codes')) {
            if (!is_array($body->{'error-codes'}) || !array_is_list($body->{'error-codes'})) {
                throw new ResponseException();
            }

            foreach ($body->{'error-codes'} as $errorCode) {
                if (!is_string($errorCode)) {
                    throw new ResponseException();
                }

                $errorCodes[] = $errorCode;
            }
        }

        $rejectionReasons = [];
        if (!$body->success) {
            $rejectionReasons[] = RejectionReason::CloudflareRejected;
        } else {
            if ($request->expectedAction !== null
                && (!isset($metadata['action']) || $metadata['action'] !== $request->expectedAction)
            ) {
                $rejectionReasons[] = RejectionReason::ActionMismatch;
            }

            if ($request->expectedHostnames !== null
                && (!isset($metadata['hostname'])
                    || !$this->hostnameIsAllowed($metadata['hostname'], $request->expectedHostnames))
            ) {
                $rejectionReasons[] = RejectionReason::HostnameMismatch;
            }
        }

        return new VerificationResult(
            accepted: $body->success && $rejectionReasons === [],
            errorCodes: $errorCodes,
            rejectionReasons: $rejectionReasons,
            hostname: $metadata['hostname'] ?? null,
            action: $metadata['action'] ?? null,
            challengeTimestamp: $metadata['challenge_ts'] ?? null,
            cdata: $metadata['cdata'] ?? null,
        );
    }

    /**
     * @param list<string> $expectedHostnames
     */
    private function hostnameIsAllowed(string $hostname, array $expectedHostnames): bool
    {
        foreach ($expectedHostnames as $expectedHostname) {
            if (strcasecmp($hostname, $expectedHostname) === 0) {
                return true;
            }
        }

        return false;
    }
}
