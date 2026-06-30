<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Attribute;

/**
 * Déclare explicitement qu'une méthode traite un attribut de voter, en
 * alternative à la convention de nommage CONSTANTE -> méthode camelCase.
 *
 * La convention reste prioritaire : #[AsVoterFor] n'est consulté que si aucune
 * méthode de convention n'existe pour l'attribut. La méthode annotée reçoit un
 * unique argument VoterContext (subject + token), pas les deux séparément.
 *
 * Répétable : une même méthode peut traiter plusieurs attributs.
 *
 *     #[AsVoterFor(self::EDIT)]
 *     #[AsVoterFor(self::NEW)]
 *     protected function canWrite(VoterContext $context): bool { ... }
 */
#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
final class AsVoterFor implements AsVoterForInterface
{
    public function __construct(
        private readonly string $attribute,
    ) {
    }

    #[\Override]
    public function getAttribute(): string
    {
        return $this->attribute;
    }
}
