<?php

declare(strict_types=1);

namespace Softavis\Turnstile\Exception;

final class HttpStatusException extends TurnstileException
{
    public function __construct(private readonly int $statusCode)
    {
        parent::__construct(sprintf('Turnstile returned an unsuccessful HTTP status (%d).', $statusCode));
    }

    public function statusCode(): int
    {
        return $this->statusCode;
    }
}
