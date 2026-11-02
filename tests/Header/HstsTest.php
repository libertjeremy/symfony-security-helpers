<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Tests\Header;

use LibertJeremy\Symfony\SecurityHelpers\Header\Hsts;
use PHPUnit\Framework\TestCase;

final class HstsTest extends TestCase
{
    public function testDefaultsAreOneYearWithSubDomains(): void
    {
        self::assertSame('max-age=31536000; includeSubDomains', (new Hsts())->toHeaderValue());
    }

    public function testPreloadIsAppended(): void
    {
        self::assertSame('max-age=63072000; includeSubDomains; preload', (new Hsts(63072000, true, true))->toHeaderValue());
    }

    public function testWithoutSubDomains(): void
    {
        self::assertSame('max-age=300', (new Hsts(300, false))->toHeaderValue());
    }

    public function testNegativeMaxAgeIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Hsts(-1);
    }

    public function testPreloadWithoutSubDomainsIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Hsts(31536000, false, true);
    }

    public function testPreloadWithShortMaxAgeIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Hsts(300, true, true);
    }
}
