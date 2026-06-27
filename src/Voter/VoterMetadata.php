<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Voter;

/**
 * Métadonnées d'un voter résolues une seule fois par classe : la liste des
 * attributs déclarés et le routage attribut -> méthode à appeler.
 */
final class VoterMetadata
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

    /**
     * @return array<string, string> nom de constante => valeur d'attribut ('voter.x.y')
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * @return array<string, string> valeur d'attribut => nom de méthode à invoquer
     */
    public function getMethodsByAttribute(): array
    {
        return $this->methodsByAttribute;
    }

    public function supports(string $attribute): bool
    {
        return isset($this->methodsByAttribute[$attribute]);
    }

    public function methodFor(string $attribute): ?string
    {
        return $this->methodsByAttribute[$attribute] ?? null;
    }
}
