<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Attribute;

/**
 * Contrat des attributs de routage de vote. Le trait résout les méthodes via
 * cette interface (ReflectionAttribute::IS_INSTANCEOF), pas via une classe
 * concrète : tout attribut implémentant ce contrat est pris en charge.
 */
interface AsVoterForInterface
{
    /**
     * Valeur d'attribut de voter traitée par la méthode ('voter.x.y').
     */
    public function getAttribute(): string;
}
