<?php

declare(strict_types=1);

namespace Softavis\Turnstile\Exception;

final class ResponseException extends TurnstileException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct('Turnstile returned a malformed verification response.', 0, $previous);
    }
}
