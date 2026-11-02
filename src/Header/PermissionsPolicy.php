<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Header;

/**
 * Permissions-Policy built from a feature map. Allowlist entries are `self`, `*` or an origin
 * (`https://example.com`, quoted on output); an empty list disables the feature (`geolocation=()`).
 */
final readonly class PermissionsPolicy
{
    public const string HEADER = 'Permissions-Policy';

    /**
     * @param array<string, list<string>> $features feature name => allowlist
     */
    public function __construct(public array $features)
    {
        foreach ($features as $feature => $allowlist) {
            if (1 !== preg_match('/^[a-z][a-z0-9-]*$/', $feature)) {
                throw new \InvalidArgumentException(\sprintf('Invalid Permissions-Policy feature "%s".', $feature));
            }

            foreach ($allowlist as $entry) {
                if (1 !== preg_match('/^[^\s;,"()\x00-\x1f\x7f]+$/', $entry)) {
                    throw new \InvalidArgumentException(\sprintf('Invalid Permissions-Policy allowlist entry "%s" for "%s".', $entry, $feature));
                }
            }
        }
    }

    public function toHeaderValue(): string
    {
        $parts = [];

        foreach ($this->features as $feature => $allowlist) {
            $entries = array_map(
                static fn (string $entry): string => \in_array($entry, ['self', '*'], true) ? $entry : '"'.$entry.'"',
                $allowlist,
            );

            $parts[] = $feature.'=('.implode(' ', $entries).')';
        }

        return implode(', ', $parts);
    }
}
