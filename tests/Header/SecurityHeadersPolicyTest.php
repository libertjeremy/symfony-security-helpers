<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Tests\Header;

use LibertJeremy\Symfony\SecurityHelpers\Header\ContentSecurityPolicy;
use LibertJeremy\Symfony\SecurityHelpers\Header\Hsts;
use LibertJeremy\Symfony\SecurityHelpers\Header\PermissionsPolicy;
use LibertJeremy\Symfony\SecurityHelpers\Header\SecurityHeadersPolicy;
use PHPUnit\Framework\TestCase;

final class SecurityHeadersPolicyTest extends TestCase
{
    public function testDefaultPolicyOnlySendsNosniff(): void
    {
        self::assertSame(['X-Content-Type-Options' => 'nosniff'], (new SecurityHeadersPolicy())->headers(true));
    }

    public function testFullPolicyOnSecureRequest(): void
    {
        $policy = new SecurityHeadersPolicy(
            hsts: new Hsts(),
            contentSecurityPolicy: new ContentSecurityPolicy(['default-src' => ["'self'"]]),
            permissionsPolicy: new PermissionsPolicy(['camera' => ['self']]),
            referrerPolicy: 'strict-origin-when-cross-origin',
            frameOptions: 'DENY',
            crossOriginOpenerPolicy: 'same-origin',
            crossOriginResourcePolicy: 'same-site',
        );

        self::assertSame([
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy' => "default-src 'self'",
            'Permissions-Policy' => 'camera=(self)',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'X-Frame-Options' => 'DENY',
            'Cross-Origin-Opener-Policy' => 'same-origin',
            'Cross-Origin-Resource-Policy' => 'same-site',
        ], $policy->headers(true));
    }

    public function testHstsIsOmittedOnInsecureRequest(): void
    {
        $headers = (new SecurityHeadersPolicy(hsts: new Hsts()))->headers(false);

        self::assertArrayNotHasKey('Strict-Transport-Security', $headers);
    }

    public function testNosniffCanBeDisabled(): void
    {
        self::assertSame([], (new SecurityHeadersPolicy(contentTypeNosniff: false))->headers(true));
    }

    public function testNonceIsPassedToTheContentSecurityPolicy(): void
    {
        $policy = new SecurityHeadersPolicy(contentSecurityPolicy: new ContentSecurityPolicy(['script-src' => ["'self'"]], ['script-src']));

        self::assertSame("script-src 'self' 'nonce-n1'", $policy->headers(true, 'n1')['Content-Security-Policy']);
        self::assertTrue($policy->usesNonce());
    }

    public function testPolicyWithoutCspDoesNotUseNonce(): void
    {
        self::assertFalse((new SecurityHeadersPolicy())->usesNonce());
    }

    public function testExcludedPrefixMatchesPathAndChildren(): void
    {
        $policy = new SecurityHeadersPolicy(excludedPaths: ['/_profiler', '/wdt/']);

        self::assertTrue($policy->isExcluded('/_profiler'));
        self::assertTrue($policy->isExcluded('/_profiler/abc123'));
        self::assertTrue($policy->isExcluded('/wdt/token'));
    }

    public function testExcludedPrefixDoesNotMatchSiblingPath(): void
    {
        $policy = new SecurityHeadersPolicy(excludedPaths: ['/_profiler']);

        self::assertFalse($policy->isExcluded('/_profilerx'));
        self::assertFalse($policy->isExcluded('/'));
    }

    public function testInvalidFrameOptionsIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SecurityHeadersPolicy(frameOptions: 'ALLOW-FROM https://evil.example');
    }

    public function testInvalidReferrerPolicyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SecurityHeadersPolicy(referrerPolicy: 'sometimes');
    }

    public function testInvalidCrossOriginOpenerPolicyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SecurityHeadersPolicy(crossOriginOpenerPolicy: 'nope');
    }

    public function testInvalidCrossOriginResourcePolicyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SecurityHeadersPolicy(crossOriginResourcePolicy: 'nope');
    }
}
