<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Tests\Header;

use LibertJeremy\Symfony\SecurityHelpers\Header\ContentSecurityPolicy;
use PHPUnit\Framework\TestCase;

final class ContentSecurityPolicyTest extends TestCase
{
    public function testDirectivesAreJoinedWithSemicolons(): void
    {
        $policy = new ContentSecurityPolicy([
            'default-src' => ["'self'"],
            'img-src' => ["'self'", 'data:', 'blob:'],
        ]);

        self::assertSame("default-src 'self'; img-src 'self' data: blob:", $policy->toHeaderValue());
    }

    public function testValuelessDirectiveHasNoTrailingSpace(): void
    {
        $policy = new ContentSecurityPolicy(['default-src' => ["'self'"], 'upgrade-insecure-requests' => []]);

        self::assertSame("default-src 'self'; upgrade-insecure-requests", $policy->toHeaderValue());
    }

    public function testNonceIsAppendedToNonceDirectivesOnly(): void
    {
        $policy = new ContentSecurityPolicy(
            ['default-src' => ["'self'"], 'script-src' => ["'self'"]],
            ['script-src'],
        );

        self::assertSame("default-src 'self'; script-src 'self' 'nonce-abc'", $policy->toHeaderValue('abc'));
    }

    public function testNonceIsIgnoredWhenNoneIsGiven(): void
    {
        $policy = new ContentSecurityPolicy(['script-src' => ["'self'"]], ['script-src']);

        self::assertSame("script-src 'self'", $policy->toHeaderValue());
    }

    public function testReportOnlyChangesTheHeaderName(): void
    {
        self::assertSame('Content-Security-Policy-Report-Only', (new ContentSecurityPolicy([], [], true))->headerName());
        self::assertSame('Content-Security-Policy', (new ContentSecurityPolicy([]))->headerName());
    }

    public function testSourceInjectingADirectiveIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ContentSecurityPolicy(['default-src' => ["'self'; script-src *"]]);
    }

    public function testSourceWithNewlineIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ContentSecurityPolicy(['default-src' => ["'self'\r\nSet-Cookie:x"]]);
    }

    public function testInvalidDirectiveNameIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ContentSecurityPolicy(['Default Src' => ["'self'"]]);
    }

    public function testNonceDirectiveMustBeDeclared(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ContentSecurityPolicy(['default-src' => ["'self'"]], ['script-src']);
    }
}
