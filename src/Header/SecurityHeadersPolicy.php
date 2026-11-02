<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Header;

/**
 * The set of security headers an application sends. A null header (or false for nosniff) is not sent.
 */
final readonly class SecurityHeadersPolicy
{
    private const array FRAME_OPTIONS = ['DENY', 'SAMEORIGIN'];
    private const array REFERRER_POLICIES = [
        'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
        'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
    ];
    private const array OPENER_POLICIES = ['unsafe-none', 'same-origin-allow-popups', 'same-origin', 'noopener-allow-popups'];
    private const array RESOURCE_POLICIES = ['same-site', 'same-origin', 'cross-origin'];

    /**
     * @param list<string> $excludedPaths path prefixes (e.g. "/_profiler") for which no header is added
     */
    public function __construct(
        public ?Hsts $hsts = null,
        public ?ContentSecurityPolicy $contentSecurityPolicy = null,
        public ?PermissionsPolicy $permissionsPolicy = null,
        public ?string $referrerPolicy = null,
        public bool $contentTypeNosniff = true,
        public ?string $frameOptions = null,
        public ?string $crossOriginOpenerPolicy = null,
        public ?string $crossOriginResourcePolicy = null,
        public array $excludedPaths = [],
    ) {
        self::assertOneOf('X-Frame-Options', $frameOptions, self::FRAME_OPTIONS);
        self::assertOneOf('Referrer-Policy', $referrerPolicy, self::REFERRER_POLICIES);
        self::assertOneOf('Cross-Origin-Opener-Policy', $crossOriginOpenerPolicy, self::OPENER_POLICIES);
        self::assertOneOf('Cross-Origin-Resource-Policy', $crossOriginResourcePolicy, self::RESOURCE_POLICIES);
    }

    public function isExcluded(string $path): bool
    {
        foreach ($this->excludedPaths as $prefix) {
            $prefix = rtrim($prefix, '/');

            if ($path === $prefix || str_starts_with($path, $prefix.'/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, string> header name => value
     */
    public function headers(bool $secure, ?string $nonce = null): array
    {
        $headers = [];

        if ($secure && null !== $this->hsts) {
            $headers['Strict-Transport-Security'] = $this->hsts->toHeaderValue();
        }

        if (null !== $this->contentSecurityPolicy) {
            $headers[$this->contentSecurityPolicy->headerName()] = $this->contentSecurityPolicy->toHeaderValue($nonce);
        }

        if (null !== $this->permissionsPolicy) {
            $headers[PermissionsPolicy::HEADER] = $this->permissionsPolicy->toHeaderValue();
        }

        if ($this->contentTypeNosniff) {
            $headers['X-Content-Type-Options'] = 'nosniff';
        }

        foreach ([
            'Referrer-Policy' => $this->referrerPolicy,
            'X-Frame-Options' => $this->frameOptions,
            'Cross-Origin-Opener-Policy' => $this->crossOriginOpenerPolicy,
            'Cross-Origin-Resource-Policy' => $this->crossOriginResourcePolicy,
        ] as $name => $value) {
            if (null !== $value) {
                $headers[$name] = $value;
            }
        }

        return $headers;
    }

    public function usesNonce(): bool
    {
        return $this->contentSecurityPolicy?->usesNonce() ?? false;
    }

    /**
     * @param list<string> $allowed
     */
    private static function assertOneOf(string $header, ?string $value, array $allowed): void
    {
        if (null !== $value && !\in_array($value, $allowed, true)) {
            throw new \InvalidArgumentException(\sprintf('Invalid %s value "%s", expected one of: %s.', $header, $value, implode(', ', $allowed)));
        }
    }
}
