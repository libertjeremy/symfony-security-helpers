<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Tests\Traits;

use LibertJeremy\Symfony\SecurityHelpers\Attribute\AsVoterFor;
use LibertJeremy\Symfony\SecurityHelpers\Traits\VoterHelperTrait;
use LibertJeremy\Symfony\SecurityHelpers\Voter\VoterContextInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class VoterHelperTraitTest extends TestCase
{
    private TokenInterface $token;
    private DocumentVoterFixture $voter;

    #[\Override]
    protected function setUp(): void
    {
        $this->token = new UsernamePasswordToken(new InMemoryUser('alice', null, ['ROLE_USER']), 'main', ['ROLE_USER']);
        $this->voter = new DocumentVoterFixture();
    }

    public function testConventionMethodGrantsAccess(): void
    {
        self::assertSame(VoterInterface::ACCESS_GRANTED, @$this->voter->vote($this->token, 'alice-doc', [DocumentVoterFixture::VIEW]));
    }

    public function testConventionMethodDeniesAccess(): void
    {
        self::assertSame(VoterInterface::ACCESS_DENIED, @$this->voter->vote($this->token, 'bob-doc', [DocumentVoterFixture::VIEW]));
    }

    public function testAttributeDeclaredMethodReceivesContextAndGrants(): void
    {
        self::assertSame(VoterInterface::ACCESS_GRANTED, $this->voter->vote($this->token, 'alice-doc', [DocumentVoterFixture::EDIT]));
    }

    public function testAttributeDeclaredMethodReceivesContextAndDenies(): void
    {
        self::assertSame(VoterInterface::ACCESS_DENIED, $this->voter->vote($this->token, 'bob-doc', [DocumentVoterFixture::EDIT]));
    }

    public function testUnknownAttributeAbstains(): void
    {
        self::assertSame(VoterInterface::ACCESS_ABSTAIN, $this->voter->vote($this->token, 'alice-doc', ['voter.document.unknown']));
    }

    public function testAttributeWithoutPrefixAbstains(): void
    {
        self::assertSame(VoterInterface::ACCESS_ABSTAIN, $this->voter->vote($this->token, 'alice-doc', ['ROLE_USER']));
    }

    public function testSupportsOnlyDeclaredAttributes(): void
    {
        self::assertTrue($this->voter->supportsAttribute(DocumentVoterFixture::EDIT));
        self::assertFalse($this->voter->supportsAttribute('voter.document.unknown'));
    }
}

/**
 * @extends Voter<string, mixed>
 */
final class DocumentVoterFixture extends Voter
{
    use VoterHelperTrait;

    public const string VIEW = 'voter.document.view';
    public const string EDIT = 'voter.document.edit';

    protected function view(mixed $subject, TokenInterface $token): bool
    {
        return \is_string($subject) && str_starts_with($subject, $token->getUserIdentifier());
    }

    #[AsVoterFor(self::EDIT)]
    protected function canEdit(VoterContextInterface $context): bool
    {
        $subject = $context->getSubject();

        return \is_string($subject) && str_starts_with($subject, $context->getToken()->getUserIdentifier());
    }
}
