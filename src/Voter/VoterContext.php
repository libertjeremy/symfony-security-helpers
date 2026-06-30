<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Contexte passé aux méthodes de vote routées par #[AsVoterFor] : il encapsule
 * le sujet et le token plutôt que de les passer comme deux arguments distincts.
 */
final class VoterContext implements VoterContextInterface
{
    public function __construct(
        private readonly mixed $subject,
        private readonly TokenInterface $token,
    ) {
    }

    #[\Override]
    public function getSubject(): mixed
    {
        return $this->subject;
    }

    #[\Override]
    public function getToken(): TokenInterface
    {
        return $this->token;
    }
}
