<?php

declare(strict_types=1);

namespace Softavis\Turnstile\Tests;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Softavis\Turnstile\Exception\HttpStatusException;
use Softavis\Turnstile\Exception\ResponseException;
use Softavis\Turnstile\Exception\TransportException;
use Softavis\Turnstile\HttpTurnstileVerifier;
use Softavis\Turnstile\RejectionReason;
use Softavis\Turnstile\VerificationRequest;

final class HttpTurnstileVerifierTest extends TestCase
{
    private StubHttpClient $client;
    private HttpFactory $factory;
    private HttpTurnstileVerifier $verifier;

    protected function setUp(): void
    {
        $this->client = new StubHttpClient(new Response(200, [], '{"success":true}'));
        $this->factory = new HttpFactory();
        $this->verifier = new HttpTurnstileVerifier($this->client, $this->factory, $this->factory);
    }

    public function testSendsOneCorrectlyEncodedPostRequest(): void
    {
        $request = new VerificationRequest('secret value', 'token+with & symbols');

        self::assertTrue($this->verifier->verify($request)->isAccepted());
        self::assertCount(1, $this->client->requests);

        $sentRequest = $this->client->requests[0];
        self::assertSame('POST', $sentRequest->getMethod());
        self::assertSame(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            (string) $sentRequest->getUri(),
        );
        self::assertSame('application/x-www-form-urlencoded', $sentRequest->getHeaderLine('Content-Type'));

        parse_str($sentRequest->getBody()->getContents(), $fields);
        self::assertSame([
            'secret' => 'secret value',
            'response' => 'token+with & symbols',
        ], $fields);
    }

    public function testOptionalFieldsAreOnlySentWhenSupplied(): void
    {
        $this->verifier->verify(new VerificationRequest(
            'secret',
            'token',
            remoteIp: '192.0.2.1',
            idempotencyKey: '550e8400-e29b-41d4-a716-446655440000',
        ));

        parse_str($this->client->requests[0]->getBody()->getContents(), $fields);
        self::assertSame([
            'secret' => 'secret',
            'response' => 'token',
            'remoteip' => '192.0.2.1',
            'idempotency_key' => '550e8400-e29b-41d4-a716-446655440000',
        ], $fields);

        $this->client->requests = [];
        $this->client->response = new Response(200, [], '{"success":true}');
        $this->verifier->verify(new VerificationRequest('secret', 'token'));
        parse_str($this->client->requests[0]->getBody()->getContents(), $fields);
        self::assertArrayNotHasKey('remoteip', $fields);
        self::assertArrayNotHasKey('idempotency_key', $fields);
    }

    public function testEmptyAndOversizedTokensAreRejectedWithoutHttp(): void
    {
        $empty = $this->verifier->verify(new VerificationRequest('secret', " \t\n"));
        $oversized = $this->verifier->verify(new VerificationRequest('secret', str_repeat('x', 2049)));

        self::assertFalse($empty->isAccepted());
        self::assertSame([RejectionReason::InvalidToken], $empty->rejectionReasons());
        self::assertFalse($oversized->isAccepted());
        self::assertSame([RejectionReason::InvalidToken], $oversized->rejectionReasons());
        self::assertCount(0, $this->client->requests);
    }

    public function testMaximumLengthTokenIsSentUnmodified(): void
    {
        $token = str_repeat('x', 2048);
        $this->verifier->verify(new VerificationRequest('secret', $token));

        parse_str($this->client->requests[0]->getBody()->getContents(), $fields);
        self::assertSame($token, $fields['response']);
    }

    public function testAcceptsCloudflareSuccessAndExposesMetadata(): void
    {
        $this->client->response = new Response(200, [], json_encode([
            'success' => true,
            'hostname' => 'forms.example.test',
            'action' => 'signup',
            'challenge_ts' => '2025-01-02T03:04:05.000Z',
            'cdata' => 'opaque-value',
            'unknown_future_field' => ['harmless' => true],
        ], JSON_THROW_ON_ERROR));

        $result = $this->verifier->verify(new VerificationRequest('secret', 'token'));

        self::assertTrue($result->isAccepted());
        self::assertSame('forms.example.test', $result->hostname());
        self::assertSame('signup', $result->action());
        self::assertSame('2025-01-02T03:04:05.000Z', $result->challengeTimestamp());
        self::assertSame('opaque-value', $result->cdata());
        self::assertSame([], $result->errorCodes());
    }

    public function testCloudflareRejectionPreservesUnknownErrorCodes(): void
    {
        $this->client->response = new Response(200, [], '{"success":false,"error-codes":["invalid-input-response","future_code"]}');

        $result = $this->verifier->verify(new VerificationRequest('secret', 'token'));

        self::assertFalse($result->isAccepted());
        self::assertSame(['invalid-input-response', 'future_code'], $result->errorCodes());
        self::assertSame([RejectionReason::CloudflareRejected], $result->rejectionReasons());
    }

    public function testExpectedActionMustMatchExactly(): void
    {
        $this->client->response = new Response(200, [], '{"success":true,"action":"signup"}');
        self::assertTrue($this->verifier->verify(
            new VerificationRequest('secret', 'token', expectedAction: 'signup'),
        )->isAccepted());

        $this->client->response = new Response(200, [], '{"success":true,"action":"Signup"}');
        $result = $this->verifier->verify(new VerificationRequest('secret', 'token', expectedAction: 'signup'));
        self::assertFalse($result->isAccepted());
        self::assertSame([RejectionReason::ActionMismatch], $result->rejectionReasons());

        $this->client->response = new Response(200, [], '{"success":true}');
        $result = $this->verifier->verify(new VerificationRequest('secret', 'token', expectedAction: 'signup'));
        self::assertFalse($result->isAccepted());
        self::assertSame([RejectionReason::ActionMismatch], $result->rejectionReasons());
    }

    public function testExpectedHostnameUsesCaseInsensitiveExactMatching(): void
    {
        $this->client->response = new Response(200, [], '{"success":true,"hostname":"Forms.Example.Test"}');
        self::assertTrue($this->verifier->verify(
            new VerificationRequest('secret', 'token', expectedHostnames: ['forms.example.test']),
        )->isAccepted());

        $this->client->response = new Response(200, [], '{"success":true,"hostname":"forms.example.test.attacker.invalid"}');
        $result = $this->verifier->verify(
            new VerificationRequest('secret', 'token', expectedHostnames: ['forms.example.test']),
        );
        self::assertFalse($result->isAccepted());
        self::assertSame([RejectionReason::HostnameMismatch], $result->rejectionReasons());

        $this->client->response = new Response(200, [], '{"success":true}');
        $result = $this->verifier->verify(
            new VerificationRequest('secret', 'token', expectedHostnames: ['forms.example.test']),
        );
        self::assertFalse($result->isAccepted());
        self::assertSame([RejectionReason::HostnameMismatch], $result->rejectionReasons());
    }

    public function testBothConfiguredExpectationsMustMatch(): void
    {
        $this->client->response = new Response(
            200,
            [],
            '{"success":true,"hostname":"example.test","action":"login"}',
        );

        $result = $this->verifier->verify(new VerificationRequest(
            'secret',
            'token',
            expectedAction: 'signup',
            expectedHostnames: ['example.test'],
        ));

        self::assertFalse($result->isAccepted());
        self::assertSame([RejectionReason::ActionMismatch], $result->rejectionReasons());
    }

    public function testRejectsInvalidRequestConfiguration(): void
    {
        foreach ([
            fn () => new VerificationRequest('', 'token'),
            fn () => new VerificationRequest('secret', 'token', remoteIp: 'not-an-ip'),
            fn () => new VerificationRequest(' ', 'token'),
            fn () => new VerificationRequest('secret', 'token', idempotencyKey: 'not-a-uuid'),
            fn () => new VerificationRequest('secret', 'token', expectedAction: ' '),
            fn () => new VerificationRequest('secret', 'token', expectedHostnames: []),
            fn () => new VerificationRequest('secret', 'token', expectedHostnames: ['']),
        ] as $invalidRequest) {
            try {
                $invalidRequest();
                self::fail('Expected invalid request configuration to throw.');
            } catch (\InvalidArgumentException) {
                self::assertCount(0, $this->client->requests);
            }
        }
    }

    public function testNetworkFailureIsWrappedWithoutSensitiveMessageContent(): void
    {
        $this->client->exception = new StubNetworkException(new Request('POST', 'https://example.test'));

        try {
            $this->verifier->verify(new VerificationRequest('secret-value', 'token-value'));
            self::fail('Expected a transport exception.');
        } catch (TransportException $exception) {
            self::assertStringNotContainsString('secret-value', $exception->getMessage());
            self::assertStringNotContainsString('token-value', $exception->getMessage());
            self::assertCount(1, $this->client->requests);
        }
    }

    public function testClientRequestExceptionIsWrapped(): void
    {
        $request = new Request('POST', 'https://example.test');
        $clientException = new StubRequestException($request);
        $this->client->exception = $clientException;

        try {
            $this->verifier->verify(new VerificationRequest('secret', 'token'));
            self::fail('Expected a transport exception.');
        } catch (TransportException $exception) {
            self::assertSame($clientException, $exception->getPrevious());
        }
    }

    public function testNonSuccessfulHttpStatusThrowsWithoutResponseBody(): void
    {
        $this->client->response = new Response(503, [], 'secret-value token-value');

        try {
            $this->verifier->verify(new VerificationRequest('secret-value', 'token-value'));
            self::fail('Expected an HTTP status exception.');
        } catch (HttpStatusException $exception) {
            self::assertSame(503, $exception->statusCode());
            self::assertStringNotContainsString('secret-value', $exception->getMessage());
            self::assertStringNotContainsString('token-value', $exception->getMessage());
            self::assertStringNotContainsString('secret-value', (string) $exception);
        }
    }

    public function testMalformedJsonThrowsTypedResponseException(): void
    {
        $this->client->response = new Response(200, [], 'secret-value token-value not-json');

        try {
            $this->verifier->verify(new VerificationRequest('secret-value', 'token-value'));
            self::fail('Expected a response exception.');
        } catch (ResponseException $exception) {
            self::assertStringNotContainsString('secret-value', (string) $exception);
            self::assertStringNotContainsString('token-value', (string) $exception);
        }
    }

    #[DataProvider('malformedResponseProvider')]
    public function testMalformedResponseStructuresThrow(string $body): void
    {
        $this->client->response = new Response(200, [], $body);

        $this->expectException(ResponseException::class);
        $this->verifier->verify(new VerificationRequest('secret', 'token'));
    }

    public static function malformedResponseProvider(): iterable
    {
        yield 'top-level array' => ['[]'];
        yield 'missing success' => ['{"hostname":"example.test"}'];
        yield 'non-boolean success' => ['{"success":1}'];
        yield 'non-string action' => ['{"success":true,"action":false}'];
        yield 'non-string hostname' => ['{"success":true,"hostname":[]}'];
        yield 'non-list error codes' => ['{"success":false,"error-codes":{"code":"invalid"}}'];
        yield 'non-string error code' => ['{"success":false,"error-codes":[false]}'];
    }

    public function testUnknownResponseFieldsDoNotCauseRejection(): void
    {
        $this->client->response = new Response(
            200,
            [],
            '{"success":true,"new_metadata":{"version":2}}',
        );

        self::assertTrue($this->verifier->verify(new VerificationRequest('secret', 'token'))->isAccepted());
    }
}

final class StubHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    public ?\Throwable $exception = null;

    public function __construct(public ResponseInterface $response)
    {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        if ($this->exception !== null) {
            throw $this->exception;
        }

        return $this->response;
    }
}

final class StubNetworkException extends \RuntimeException implements NetworkExceptionInterface
{
    public function __construct(private readonly RequestInterface $request)
    {
        parent::__construct('Underlying transport error included token-value and secret-value.');
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }
}

final class StubRequestException extends \RuntimeException implements \Psr\Http\Client\RequestExceptionInterface
{
    public function __construct(private readonly RequestInterface $request)
    {
        parent::__construct('Underlying request failure.');
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }
}
