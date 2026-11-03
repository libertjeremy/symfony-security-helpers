<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Tests\Header;

use LibertJeremy\Symfony\SecurityHelpers\Header\PermissionsPolicy;
use PHPUnit\Framework\TestCase;

final class PermissionsPolicyTest extends TestCase
{
    public function testQgPolicy(): void
    {
        $policy = new PermissionsPolicy(['camera' => ['self'], 'microphone' => ['self'], 'geolocation' => []]);

        self::assertSame('camera=(self), microphone=(self), geolocation=()', $policy->toHeaderValue());
    }

    public function testOriginsAreQuotedAndWildcardIsNot(): void
    {
        $policy = new PermissionsPolicy(['fullscreen' => ['self', 'https://example.com'], 'autoplay' => ['*']]);

        self::assertSame('fullscreen=(self "https://example.com"), autoplay=(*)', $policy->toHeaderValue());
    }

    public function testEntryBreakingTheStructureIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new PermissionsPolicy(['camera' => ['self) , geolocation=(*']]);
    }

    public function testInvalidFeatureNameIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new PermissionsPolicy(['Camera=*' => []]);
    }
}
