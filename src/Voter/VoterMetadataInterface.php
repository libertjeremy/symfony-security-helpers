<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Voter;

/**
 * Métadonnées d'un voter : liste des attributs déclarés et routage
 * attribut -> méthode à invoquer.
 */
interface VoterMetadataInterface
{
    /**
     * @return array<string, string> nom de constante => valeur d'attribut ('voter.x.y')
     */
    public function getAttributes(): array;

    /**
     * @return array<string, string> valeur d'attribut => nom de méthode à invoquer
     */
    public function getMethodsByAttribute(): array;

    public function supports(string $attribute): bool;

    public function methodFor(string $attribute): ?string;

    /**
     * La méthode routée par #[AsVoterFor] attend un VoterContext (subject + token)
     * au lieu des deux arguments séparés des méthodes de convention.
     */
    public function expectsContext(string $attribute): bool;
}
