# symfony-security-helpers

Security helpers for Symfony 6.4, 7.x and 8.x applications: a voter helper trait and a configurable HTTP
security-headers listener. The wiring (configuration, services) lives in
[`symfony-security-helpers-bundle`](https://github.com/libertjeremy/symfony-security-helpers-bundle).

## Security headers

`SecurityHeadersPolicy` is a readonly value object describing the headers to send;
`SecurityHeadersListener` (an event subscriber) adds them to every main-request response.

- A header already present on the response is never overridden.
- `Strict-Transport-Security` is sent on secure requests only.
- Paths listed in `excludedPaths` (prefix match on a path boundary, e.g. `/_profiler`) get no header.
- Every CSP source and Permissions-Policy entry is validated, so a value cannot inject another directive or header.
- CSP nonce (optional): list the directives that must receive it in `nonceDirectives`; the listener generates one
  per request and stores it in the `_csp_nonce` request attribute (`SecurityHeadersListener::NONCE_ATTRIBUTE`).

### Example: a PWA that scans barcodes with WebAssembly

```php
use LibertJeremy\Symfony\SecurityHelpers\EventListener\SecurityHeadersListener;
use LibertJeremy\Symfony\SecurityHelpers\Header\ContentSecurityPolicy;
use LibertJeremy\Symfony\SecurityHelpers\Header\Hsts;
use LibertJeremy\Symfony\SecurityHelpers\Header\PermissionsPolicy;
use LibertJeremy\Symfony\SecurityHelpers\Header\SecurityHeadersPolicy;

$policy = new SecurityHeadersPolicy(
    hsts: new Hsts(maxAge: 31536000, includeSubDomains: true),
    contentSecurityPolicy: new ContentSecurityPolicy([
        'default-src' => ["'self'"],
        'script-src' => ["'self'", "'wasm-unsafe-eval'"],
        'style-src' => ["'self'"],
        'img-src' => ["'self'", 'data:', 'blob:'],
        'connect-src' => ["'self'", 'https://world.openfoodfacts.org'],
        'font-src' => ["'self'"],
        'manifest-src' => ["'self'"],
        'worker-src' => ["'self'"],
        'frame-ancestors' => ["'none'"],
        'base-uri' => ["'self'"],
        'form-action' => ["'self'"],
    ]),
    permissionsPolicy: new PermissionsPolicy([
        'camera' => ['self'],
        'microphone' => ['self'],
        'geolocation' => [],
    ]),
    referrerPolicy: 'strict-origin-when-cross-origin',
    frameOptions: 'DENY',
    excludedPaths: ['/_profiler', '/_wdt'],
);

$dispatcher->addSubscriber(new SecurityHeadersListener($policy));
```

This sends `Permissions-Policy: camera=(self), microphone=(self), geolocation=()` and the CSP
`default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self' https://world.openfoodfacts.org; font-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`.

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse   # level 10
vendor/bin/php-cs-fixer fix --dry-run --diff
```
