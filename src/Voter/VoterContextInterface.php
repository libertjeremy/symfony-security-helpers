<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Contexte passé aux méthodes de vote routées par #[AsVoterFor] : il encapsule
 * le sujet et le token plutôt que de les passer comme deux arguments distincts.
 */
interface VoterContextInterface
{
    public function getSubject(): mixed;

    public function getToken(): TokenInterface;
}
