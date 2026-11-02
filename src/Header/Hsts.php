<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Header;

/**
 * Strict-Transport-Security. Only meaningful over HTTPS, the listener emits it on secure requests only.
 */
final readonly class Hsts
{
    public function __construct(
        public int $maxAge = 31536000,
        public bool $includeSubDomains = true,
        public bool $preload = false,
    ) {
        if ($maxAge < 0) {
            throw new \InvalidArgumentException('The HSTS max-age cannot be negative.');
        }

        if ($preload && (!$includeSubDomains || $maxAge < 31536000)) {
            throw new \InvalidArgumentException('HSTS preload requires includeSubDomains and a max-age of at least 31536000 seconds.');
        }
    }

    public function toHeaderValue(): string
    {
        return 'max-age='.$this->maxAge
            .($this->includeSubDomains ? '; includeSubDomains' : '')
            .($this->preload ? '; preload' : '');
    }
}
