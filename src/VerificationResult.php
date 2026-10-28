<?php

declare(strict_types=1);

namespace Softavis\Turnstile;

final readonly class VerificationResult
{
    /**
     * @param list<string> $errorCodes Cloudflare error codes, kept separate from local rejection reasons.
     * @param list<RejectionReason> $rejectionReasons
     */
    public function __construct(
        private bool $accepted,
        private array $errorCodes = [],
        private array $rejectionReasons = [],
        private ?string $hostname = null,
        private ?string $action = null,
        private ?string $challengeTimestamp = null,
        private ?string $cdata = null,
    ) {
    }

    public function isAccepted(): bool
    {
        return $this->accepted;
    }

    /**
     * @return list<string>
     */
    public function errorCodes(): array
    {
        return $this->errorCodes;
    }

    /**
     * @return list<RejectionReason>
     */
    public function rejectionReasons(): array
    {
        return $this->rejectionReasons;
    }

    public function hostname(): ?string
    {
        return $this->hostname;
    }

    public function action(): ?string
    {
        return $this->action;
    }

    public function challengeTimestamp(): ?string
    {
        return $this->challengeTimestamp;
    }

    public function cdata(): ?string
    {
        return $this->cdata;
    }
}
