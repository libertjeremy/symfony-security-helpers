<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Voter;

/**
 * Métadonnées d'un voter résolues une seule fois par classe : la liste des
 * attributs déclarés et le routage attribut -> méthode à appeler.
 */
final class VoterMetadata implements VoterMetadataInterface
{
    /**
     * @param array<string, string> $attributes        nom de constante => valeur d'attribut ('voter.x.y')
     * @param array<string, string> $methodsByAttribute valeur d'attribut => nom de méthode à invoquer
     */
    public function __construct(
        private readonly array $attributes,
        private readonly array $methodsByAttribute,
    ) {
    }

    #[\Override]
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    #[\Override]
    public function getMethodsByAttribute(): array
    {
        return $this->methodsByAttribute;
    }

    #[\Override]
    public function supports(string $attribute): bool
    {
        return isset($this->methodsByAttribute[$attribute]);
    }

    #[\Override]
    public function methodFor(string $attribute): ?string
    {
        return $this->methodsByAttribute[$attribute] ?? null;
    }
}
