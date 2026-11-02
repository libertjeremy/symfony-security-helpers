<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Header;

/**
 * Content-Security-Policy built from a directive map. Sources are written as they appear on the wire
 * (`'self'`, `https://example.com`, `data:`). Directives listed in $nonceDirectives get a per-response
 * `'nonce-…'` source appended when a nonce is given to toHeaderValue().
 */
final readonly class ContentSecurityPolicy
{
    public const string HEADER = 'Content-Security-Policy';
    public const string REPORT_ONLY_HEADER = 'Content-Security-Policy-Report-Only';

    /**
     * @param array<string, list<string>> $directives      directive name => sources (empty list = valueless directive)
     * @param list<string>                $nonceDirectives directives receiving the nonce
     */
    public function __construct(
        public array $directives,
        public array $nonceDirectives = [],
        public bool $reportOnly = false,
    ) {
        foreach ($directives as $name => $sources) {
            if (1 !== preg_match('/^[a-z][a-z0-9-]*$/', $name)) {
                throw new \InvalidArgumentException(\sprintf('Invalid CSP directive name "%s".', $name));
            }

            foreach ($sources as $source) {
                if (1 !== preg_match('/^[^\s;,\x00-\x1f\x7f]+$/', $source)) {
                    throw new \InvalidArgumentException(\sprintf('Invalid CSP source "%s" in directive "%s".', $source, $name));
                }
            }
        }

        foreach ($nonceDirectives as $name) {
            if (!isset($directives[$name])) {
                throw new \InvalidArgumentException(\sprintf('The nonce directive "%s" is not declared in the policy.', $name));
            }
        }
    }

    public function headerName(): string
    {
        return $this->reportOnly ? self::REPORT_ONLY_HEADER : self::HEADER;
    }

    public function usesNonce(): bool
    {
        return [] !== $this->nonceDirectives;
    }

    public function toHeaderValue(?string $nonce = null): string
    {
        $parts = [];

        foreach ($this->directives as $name => $sources) {
            if (null !== $nonce && \in_array($name, $this->nonceDirectives, true)) {
                $sources[] = "'nonce-".$nonce."'";
            }

            $parts[] = implode(' ', [$name, ...$sources]);
        }

        return implode('; ', $parts);
    }
}
