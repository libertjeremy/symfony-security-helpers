<?php

declare(strict_types=1);

namespace LibertJeremy\Symfony\SecurityHelpers\EventListener;

use LibertJeremy\Symfony\SecurityHelpers\Header\SecurityHeadersPolicy;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Adds the policy's headers to main-request responses. A header the application already set is never
 * overridden; HSTS is sent on secure requests only. When the CSP uses a nonce, it is generated on kernel.request
 * and exposed as the NONCE_ATTRIBUTE request attribute so templates can print it.
 */
final readonly class SecurityHeadersListener implements EventSubscriberInterface
{
    public const string NONCE_ATTRIBUTE = '_csp_nonce';

    public function __construct(private SecurityHeadersPolicy $policy)
    {
    }

    #[\Override]
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 256],
            KernelEvents::RESPONSE => ['onKernelResponse', -256],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest() || !$this->policy->usesNonce()) {
            return;
        }

        $event->getRequest()->attributes->set(self::NONCE_ATTRIBUTE, base64_encode(random_bytes(16)));
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        if ($this->policy->isExcluded($request->getPathInfo())) {
            return;
        }

        $nonce = $request->attributes->get(self::NONCE_ATTRIBUTE);
        $headers = $event->getResponse()->headers;

        foreach ($this->policy->headers($request->isSecure(), \is_string($nonce) ? $nonce : null) as $name => $value) {
            if (!$headers->has($name)) {
                $headers->set($name, $value);
            }
        }
    }
}
