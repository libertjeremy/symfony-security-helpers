<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\Tests\EventListener;

use LibertJeremy\Symfony\SecurityHelpers\EventListener\SecurityHeadersListener;
use LibertJeremy\Symfony\SecurityHelpers\Header\ContentSecurityPolicy;
use LibertJeremy\Symfony\SecurityHelpers\Header\Hsts;
use LibertJeremy\Symfony\SecurityHelpers\Header\SecurityHeadersPolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Controller\ArgumentResolver;
use Symfony\Component\HttpKernel\Controller\ControllerResolver;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class SecurityHeadersListenerTest extends TestCase
{
    public function testHeadersAreAddedToTheMainResponse(): void
    {
        $response = $this->handle(new SecurityHeadersPolicy(frameOptions: 'DENY'), Request::create('https://qg.test/'), new Response());

        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
        self::assertSame('DENY', $response->headers->get('X-Frame-Options'));
    }

    public function testExistingHeaderIsNeverOverridden(): void
    {
        $response = new Response('', 200, ['x-frame-options' => 'SAMEORIGIN']);

        $response = $this->handle(new SecurityHeadersPolicy(frameOptions: 'DENY'), Request::create('https://qg.test/'), $response);

        self::assertSame('SAMEORIGIN', $response->headers->get('X-Frame-Options'));
    }

    public function testHstsIsSentOnSecureRequest(): void
    {
        $response = $this->handle(new SecurityHeadersPolicy(hsts: new Hsts()), Request::create('https://qg.test/'), new Response());

        self::assertSame('max-age=31536000; includeSubDomains', $response->headers->get('Strict-Transport-Security'));
    }

    public function testHstsIsNotSentOnInsecureRequest(): void
    {
        $response = $this->handle(new SecurityHeadersPolicy(hsts: new Hsts()), Request::create('http://qg.test/'), new Response());

        self::assertFalse($response->headers->has('Strict-Transport-Security'));
    }

    public function testExcludedPathGetsNoHeader(): void
    {
        $response = $this->handle(new SecurityHeadersPolicy(excludedPaths: ['/_profiler']), Request::create('https://qg.test/_profiler/abc'), new Response());

        self::assertFalse($response->headers->has('X-Content-Type-Options'));
    }

    public function testSubRequestResponseIsLeftUntouched(): void
    {
        $listener = new SecurityHeadersListener(new SecurityHeadersPolicy());
        $kernel = $this->kernel($listener, new Response());

        $response = $kernel->handle(Request::create('https://qg.test/'), HttpKernelInterface::SUB_REQUEST);

        self::assertFalse($response->headers->has('X-Content-Type-Options'));
    }

    public function testNonceIsGeneratedPerRequestAndInjectedInTheCsp(): void
    {
        $policy = new SecurityHeadersPolicy(contentSecurityPolicy: new ContentSecurityPolicy(['script-src' => ["'self'"]], ['script-src']));
        $request = Request::create('https://qg.test/');

        $response = $this->handle($policy, $request, new Response());

        $nonce = $request->attributes->get(SecurityHeadersListener::NONCE_ATTRIBUTE);
        self::assertIsString($nonce);
        self::assertSame(24, \strlen($nonce));
        self::assertSame("script-src 'self' 'nonce-".$nonce."'", $response->headers->get('Content-Security-Policy'));
    }

    public function testNonceDiffersBetweenRequests(): void
    {
        $policy = new SecurityHeadersPolicy(contentSecurityPolicy: new ContentSecurityPolicy(['script-src' => ["'self'"]], ['script-src']));
        $requestOne = Request::create('https://qg.test/');
        $requestTwo = Request::create('https://qg.test/');

        $this->handle($policy, $requestOne, new Response());
        $this->handle($policy, $requestTwo, new Response());

        self::assertNotSame($requestOne->attributes->get(SecurityHeadersListener::NONCE_ATTRIBUTE), $requestTwo->attributes->get(SecurityHeadersListener::NONCE_ATTRIBUTE));
    }

    public function testNoNonceAttributeWhenCspDoesNotUseOne(): void
    {
        $request = Request::create('https://qg.test/');

        $this->handle(new SecurityHeadersPolicy(contentSecurityPolicy: new ContentSecurityPolicy(['default-src' => ["'self'"]])), $request, new Response());

        self::assertFalse($request->attributes->has(SecurityHeadersListener::NONCE_ATTRIBUTE));
    }

    private function handle(SecurityHeadersPolicy $policy, Request $request, Response $response): Response
    {
        return $this->kernel(new SecurityHeadersListener($policy), $response)->handle($request);
    }

    private function kernel(SecurityHeadersListener $listener, Response $response): HttpKernel
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber($listener);
        $dispatcher->addListener('kernel.request', static function (RequestEvent $event) use ($response): void {
            $event->setResponse($response);
        }, 0);

        return new HttpKernel($dispatcher, new ControllerResolver(), new RequestStack(), new ArgumentResolver());
    }
}
