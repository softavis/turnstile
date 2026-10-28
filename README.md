# softavis/turnstile

[![CI](https://img.shields.io/github/actions/workflow/status/softavis/turnstile/ci.yml?branch=master&style=flat&label=CI)](https://github.com/softavis/turnstile/actions/workflows/ci.yml)
[![PHP requirement](https://img.shields.io/badge/PHP-%5E8.2-777BB4?logo=php&style=flat)](https://github.com/softavis/turnstile/blob/master/composer.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/softavis/turnstile/blob/master/LICENSE)

<!-- Enable these badges after registering the package on Packagist:
[![Latest Stable Version](https://img.shields.io/packagist/v/softavis/turnstile?style=flat)](https://packagist.org/packages/softavis/turnstile)
[![Total Downloads](https://img.shields.io/packagist/dt/softavis/turnstile?style=flat)](https://packagist.org/packages/softavis/turnstile)
-->

A small, framework-independent PHP library for verifying Cloudflare Turnstile tokens on the server. It provides a reusable verification layer with explicit security policies; a separate Symfony integration can consume the verifier interface without coupling this package to a framework.

This package only verifies tokens. It does not provide widgets, framework integrations, middleware, authentication, or CSRF handling.

## Why this package?

We want to reuse the same server-side Turnstile verification across projects and frameworks, with a framework-independent core and a separate Symfony integration. This architecture fits our needs and may fit yours; other packages remain valid choices.

- Explicit PSR-18 client and PSR-17 factories, without requiring a particular HTTP implementation or automatic discovery.
- Configurable expected action and hostname checks, with rejected verification distinguished from operational failure.
- A focused verification API without frontend rendering or application authentication logic.

## Requirements and installation

PHP 8.2 or later, the Filter and JSON extensions, and PSR-18/PSR-17 implementations are required. The library itself depends only on the PSR HTTP client and factory interfaces:

```sh
composer require softavis/turnstile
```

For example, install Guzzle as a PSR-18 client and Guzzle PSR-7 as the PSR-17 request and stream factory:

```sh
composer require guzzlehttp/guzzle:^7.9 guzzlehttp/psr7:^2.7
```

The package does not select or discover a transport implementation. Supply the client and both factories explicitly.

## Usage

```php
<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Softavis\Turnstile\Exception\TurnstileException;
use Softavis\Turnstile\HttpTurnstileVerifier;
use Softavis\Turnstile\VerificationRequest;

$httpClient = new Client([
    'connect_timeout' => 3.0,
    'timeout' => 10.0,
]);
$psr17Factory = new HttpFactory();

// Obtain these values from your application's explicit configuration and form handling.
$secret = $configuration['turnstile_secret'];
$token = $submittedTurnstileToken;
$verifier = new HttpTurnstileVerifier($secret, $httpClient, $psr17Factory, $psr17Factory);

try {
    $result = $verifier->verify(new VerificationRequest(
        response: $token,
        remoteIp: $trustedClientIp ?? null,
        expectedAction: 'signup',
        expectedHostnames: ['www.example.com', 'example.com'],
    ));

    if (!$result->isAccepted()) {
        // Reject the form submission. Refresh/reissue the challenge before a retry.
        foreach ($result->errorCodes() as $errorCode) {
            // Handle Cloudflare error codes without assuming the list is exhaustive.
        }

        foreach ($result->rejectionReasons() as $reason) {
            // Local reasons are RejectionReason enum cases, separate from Cloudflare codes.
        }
    } else {
        // Continue processing the submission.
    }
} catch (TurnstileException $exception) {
    // Verification could not be completed reliably; handle as an operational failure.
}
```

`TurnstileVerifier` is the small interface intended for consumers such as a future Symfony bundle. `HttpTurnstileVerifier` posts once to Cloudflare's HTTPS Siteverify endpoint. `VerificationResult::isAccepted()` is the acceptance check; the result also exposes Cloudflare error codes and available `hostname`, `action`, `challengeTimestamp`, and `cdata` metadata.

The Guzzle timeout values above are examples to adjust for your application. Timeout support and configuration come from the injected HTTP implementation; PSR-18 itself does not standardize timeout options.

### Expected action and hostname

Set `expectedAction` to an action value your application controls, and `expectedHostnames` to the exact hostname(s) it intends to accept. Do not derive either expectation from untrusted request data. Action comparison is exact. Hostname comparison is case-insensitive but exact: there is no suffix or wildcard matching. A missing Cloudflare response field rejects the verification whenever that expectation is configured. An empty hostname allowlist is invalid. Omitting either expectation disables that additional check; Cloudflare's own token validation still runs.

When supplied, `remoteIp` must be a valid IP address and `idempotencyKey` must be a UUID.

### Rejections and operational failures

An empty/whitespace-only token or a token longer than Cloudflare's documented 2,048-character limit is rejected locally without an HTTP call. Cloudflare `success: false` and configured action/hostname mismatches also produce a rejected result. Local rejection reasons are `RejectionReason` enum cases; Cloudflare's `errorCodes()` remain separate and preserve unknown future code strings.

Network/client failures, non-2xx HTTP status codes, and malformed responses throw typed exceptions under `Softavis\Turnstile\Exception\TurnstileException`: `TransportException`, `HttpStatusException`, and `ResponseException`. Invalid verifier configuration or request options throw `InvalidArgumentException`. Treat operational failures as inability to verify, not as acceptance.

The library does not log and its generated exception messages do not include the secret, token, request body, or raw response body. An underlying transport exception retained as the previous exception may contain sensitive request details. Application logging should redact secrets, tokens, and other sensitive data, including details retained by transport exceptions.

## Token lifecycle and application security

Turnstile tokens are single-use and expire after 300 seconds (five minutes). After an unsuccessful form submission, obtain a fresh token before retrying instead of reusing the prior token. Cloudflare remains authoritative for expiry and replay checks; this library does not recreate those checks locally.

Pass the secret and token explicitly from application configuration and form handling. The library does not read environment variables, globals, framework requests, or forwarding headers. Only supply `remoteIp` when your application has a trustworthy client IP; the library does not infer one.

Turnstile does not replace CSRF protection, rate limiting, or other application security controls.

### Cloudflare test credentials

Cloudflare provides test credentials that always pass or always fail validation. For example, its documented always-pass pair is sitekey `1x00000000000000000000AA` and secret `1x0000000000000000000000000000000AA`; these are for testing and must not be used in production. Test validation returns fixed metadata (`hostname: localhost`, `action: test`, and `cdata: test-data`), so these credentials cannot exercise your production hostname/action expectations. Use appropriately configured non-test keys in a controlled environment to verify those policies.

See Cloudflare's [server-side validation guide](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) and [testing documentation](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) for current details.

## Symfony integration

A dedicated Symfony integration is being developed as [`softavis/turnstile-bundle`](https://github.com/softavis/turnstile-bundle). It will use this library as its verification layer. The bundle is upcoming and is not yet released or available to install.

## Alternatives

These are independent Symfony integrations with their own features and approaches, and may suit your application's needs:

- [vuillaume-agency/symfony-turnstile](https://github.com/vuillaume-agency/symfony-turnstile)
- [pixelopen/cloudflare-turnstile-bundle](https://github.com/pixelopen/cloudflare-turnstile-bundle)

## Development

```sh
composer install
composer test
composer analyse
composer style
```

The test suite uses stubbed HTTP clients and real PSR-7 messages; it makes no live Cloudflare requests and requires no credentials.
