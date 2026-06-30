<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Traits;

use LibertJeremy\Symfony\SecurityHelpers\Attribute\AsVoterForInterface;
use LibertJeremy\Symfony\SecurityHelpers\Voter\VoterContext;
use LibertJeremy\Symfony\SecurityHelpers\Voter\VoterMetadata;
use LibertJeremy\Symfony\SecurityHelpers\Voter\VoterMetadataInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use function Symfony\Component\String\u;

trait VoterHelperTrait
{
    protected const string VOTER_PREFIX = 'voter.';

    /**
     * Métadonnées résolues une seule fois par classe concrète (les constantes et
     * les attributs sont immuables au runtime). Clé = static::class pour rester
     * correct malgré l'héritage : une propriété statique de trait est partagée
     * dans toute la hiérarchie qui ne la redéclare pas.
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
        $metadata = $this->voterMetadata();

        $function = $metadata->methodFor($attribute);

        if (null === $function || !method_exists($this, $function)) {
            throw new \LogicException(sprintf('Unable to vote on attribute "%s". Method "%s" not found in %s', $attribute, $function ?? '?', static::class));
        }

        if ($metadata->expectsContext($attribute)) {
            return $this->$function(new VoterContext($subject, $token));
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

        foreach (($reflection = new \ReflectionClass($this))->getConstants() as $constantName => $constantValue) {
            if (!\is_string($constantName) || !\is_string($constantValue) || !$this->attributeIsValid($constantValue)) {
                continue;
            }

            $conventionMethod = $this->convertAttributeKeyToFunctionIfNeeded($constantName);

            trigger_error(sprintf('Resolving voter attribute "%s" by naming convention (constant "%s::%s" -> method "%s()") is deprecated. Declare the method with #[AsVoterFor(self::%s)] instead.', $constantValue, static::class, $constantName, $conventionMethod, $constantName), \E_USER_DEPRECATED);

            $attributes[$constantName] = $constantValue;
            $methodsByAttribute[$constantValue] = $conventionMethod;
        }

        $contextAttributes = [];

        foreach ($reflection->getMethods() as $method) {
            foreach ($method->getAttributes(AsVoterForInterface::class, \ReflectionAttribute::IS_INSTANCEOF) as $reflectionAttribute) {
                $attributeValue = $reflectionAttribute->newInstance()->getAttribute();

                $conventionMethod = $methodsByAttribute[$attributeValue] ?? null;

                if (
                    null !== $conventionMethod
                    && $reflection->hasMethod($conventionMethod)
                ) {
                    continue;
                }

                $methodsByAttribute[$attributeValue] = $method->getName();
                $contextAttributes[$attributeValue] = true;
            }
        }

        return new VoterMetadata($attributes, $methodsByAttribute, $contextAttributes);
    }
}
