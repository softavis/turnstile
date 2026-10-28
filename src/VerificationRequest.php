<?php

declare(strict_types=1);

namespace Softavis\Turnstile;

use InvalidArgumentException;

use function filter_var;

use const FILTER_VALIDATE_IP;

final readonly class VerificationRequest
{
    /** @var list<string>|null */
    public ?array $expectedHostnames;

    /**
     * @param array<array-key, mixed>|null $expectedHostnames Null disables hostname checking.
     */
    public function __construct(
        public string $response,
        public ?string $remoteIp = null,
        public ?string $idempotencyKey = null,
        public ?string $expectedAction = null,
        ?array $expectedHostnames = null,
    ) {
        if ($remoteIp !== null && filter_var($remoteIp, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException('The remote IP must be a valid IP address when supplied.');
        }

        if ($idempotencyKey !== null
            && preg_match('/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/iD', $idempotencyKey) !== 1
        ) {
            throw new InvalidArgumentException('The idempotency key must be a UUID when supplied.');
        }

        if ($expectedAction !== null && trim($expectedAction) === '') {
            throw new InvalidArgumentException('The expected action must not be empty when supplied.');
        }

        if ($expectedHostnames !== null) {
            if ($expectedHostnames === [] || !array_is_list($expectedHostnames)) {
                throw new InvalidArgumentException('Expected hostnames must be a non-empty list when supplied.');
            }

            foreach ($expectedHostnames as $hostname) {
                if (!is_string($hostname) || trim($hostname) === '') {
                    throw new InvalidArgumentException('Expected hostnames must contain non-empty strings.');
                }
            }
        }

        $this->expectedHostnames = $expectedHostnames;
    }
}
