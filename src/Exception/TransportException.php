<?php

declare(strict_types=1);

namespace Softavis\Turnstile\Exception;

final class TransportException extends TurnstileException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct('The Turnstile verification request could not be completed.', 0, $previous);
    }
}
