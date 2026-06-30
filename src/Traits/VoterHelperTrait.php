<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Traits;

use LibertJeremy\Symfony\SecurityHelpers\Voter\VoterMetadata;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use function Symfony\Component\String\u;

trait VoterHelperTrait
{
    protected const string VOTER_PREFIX = 'voter.';

    /**
     * Métadonnées résolues une seule fois par classe concrète (les constantes
     * sont immuables au runtime). Clé = static::class pour rester correct malgré
     * l'héritage : une propriété statique de trait est partagée dans toute la
     * hiérarchie qui ne la redéclare pas.
     *
     * @var array<class-string, VoterMetadataInterface>
     */
    private static array $voterMetadataCache = [];

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $this->supportsAttribute($attribute);
    }

    #[\Override]
    public function supportsAttribute(string $attribute): bool
    {
        if (!$this->attributeIsValid($attribute)) {
            return false;
        }

        return $this->voterMetadata()->supports($attribute);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $function = $this->voterMetadata()->methodFor($attribute);

        if (null === $function || !method_exists($this, $function)) {
            throw new \LogicException(sprintf('Unable to vote on attribute "%s". Method "%s" not found in %s', $attribute, $function ?? '?', static::class));
        }

        return $this->$function($subject, $token);
    }

    /**
     * @return array<string, string> nom de constante => valeur d'attribut ('voter.x.y')
     */
    protected function getAttributes(): array
    {
        return $this->voterMetadata()->getAttributes();
    }

    protected function attributeIsValid(string $attribute): bool
    {
        return str_starts_with($attribute, self::VOTER_PREFIX);
    }

    private function convertAttributeKeyToFunctionIfNeeded(string $attribute): string
    {
        $function = strtolower($attribute);

        if (str_contains($function, '_')) {
            $function = u($function)->camel()->toString();
        }

        return $function;
    }

    private function voterMetadata(): VoterMetadataInterface
    {
        return self::$voterMetadataCache[static::class] ??= $this->computeVoterMetadata();
    }

    private function computeVoterMetadata(): VoterMetadataInterface
    {
        $attributes = [];
        $methodsByAttribute = [];

        foreach ((new \ReflectionClass($this))->getConstants() as $constantName => $constantValue) {
            if (!\is_string($constantName) || !\is_string($constantValue) || !$this->attributeIsValid($constantValue)) {
                continue;
            }

            $attributes[$constantName] = $constantValue;
            $methodsByAttribute[$constantValue] = $this->convertAttributeKeyToFunctionIfNeeded($constantName);
        }

        return new VoterMetadata($attributes, $methodsByAttribute);
    }
}
