<?php

declare(strict_types=1);

namespace Softavis\Turnstile;

enum RejectionReason: string
{
    case InvalidToken = 'invalid_token';
    case CloudflareRejected = 'cloudflare_rejected';
    case ActionMismatch = 'action_mismatch';
    case HostnameMismatch = 'hostname_mismatch';
}
