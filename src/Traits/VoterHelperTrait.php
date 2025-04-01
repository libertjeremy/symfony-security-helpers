<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Traits;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use function Symfony\Component\String\u;

trait VoterHelperTrait
{
    protected const string VOTER_PREFIX = 'voter.';

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

        return \in_array($attribute, $this->getAttributes());
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $attributes = array_flip($this->getAttributes());

        $function = $this->convertAttributeKeyToFunctionIfNeeded($attributes[$attribute]);

        if (!method_exists($this, $function)) {
            throw new \LogicException(sprintf('Unable to vote on attribute "%s". Method "%s" not found in %s', $attribute, $function, static::class));
        }

        return $this->$function($subject, $token);
    }

    /**
     * @return array<string>
     */
    protected function getAttributes(): array
    {
        $returnAttributes = [];

        foreach ((new \ReflectionClass($this))->getConstants() as $keyForPotentialAttribute => $potentialAttribute) {
            if (
                !\is_string($keyForPotentialAttribute)
                || !\is_string($potentialAttribute)
                || !$this->attributeIsValid($potentialAttribute)
            ) {
                continue;
            }

            $returnAttributes[$keyForPotentialAttribute] = $potentialAttribute;
        }

        return $returnAttributes;
    }

    protected function attributeIsValid(string $attribute): bool
    {
        return str_starts_with($attribute, self::VOTER_PREFIX);
    }

    private function convertAttributeKeyToFunctionIfNeeded(string $attribute): string
    {
        $function = strtolower($attribute);

        if (str_contains($function , '_')) {
            $function = u($function)->camel()->toString();
        }

        return $function;
    }
}
