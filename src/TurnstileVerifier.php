<?php

declare(strict_types=1);

namespace Softavis\Turnstile;

interface TurnstileVerifier
{
    public function verify(VerificationRequest $request): VerificationResult;
}
