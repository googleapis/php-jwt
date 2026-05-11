<?php

namespace Firebase\JWT;

use PHPUnit\Framework\TestCase;

class ReadmeTest extends TestCase
{
    private const CODEBLOCK_REGEX = '/^(?m)(\s*)(`{3,}|~{3,})[ \t]*(.*?)\n([\s\S]*?)\1\2\s*$/m';

    private array $payload = [
        'iss' => 'example.org',
        'aud' => 'example.com',
        'iat' => 1356999524,
        'nbf' => 1357000000,
    ];

    public function testExample()
    {
        $codeblock = $this->extractCodeBlock('Example');
        $output = $codeblock->invoke();

        $header = ['typ' => 'JWT', 'alg' => 'HS256'];

        $this->assertEquals(
            print_r((object) $this->payload, true) . print_r((object) $header, true),
            $output
        );
    }

    public function testExampleEncodeDecodeHeaders()
    {
        $codeblock = $this->extractCodeBlock('Example encode/decode headers');
        $output = $codeblock->invoke();

        $header = [
            'typ' => 'JWT',
            'x-forwarded-for' => 'www.google.com',
            'alg' => 'HS256',
        ];

        $this->assertEquals(
            print_r($header, true),
            $output
        );
    }

    public function testExampleWithRS256()
    {
        $codeblock = $this->extractCodeBlock('Example with RS256 (openssl)');
        $output = $codeblock->invoke();

        $this->assertStringContainsString(
            "Decode:\n" . print_r($this->payload, true),
            $output
        );
    }

    public function testExampleWithPassphrase()
    {
        $codeblock = $this->extractCodeBlock('Example with a passphrase');

        $codeblock->replace('[YOUR_PASSPHRASE]', 'passphrase');
        $codeblock->replace(
            '/path/to/key-with-passphrase.pem',
            __DIR__ . '/data/rsa-with-passphrase.pem'
        );

        $output = $codeblock->invoke();

        $this->assertStringContainsString(
            "Decode:\n" . print_r($this->payload, true),
            $output
        );
    }

    public function testExampleWithEdDSA()
    {
        $codeblock = $this->extractCodeBlock('Example with EdDSA (libsodium and Ed25519 signature)');

        $output = $codeblock->invoke();

        $this->assertStringContainsString(
            "Decode:\n" . print_r($this->payload, true),
            $output
        );
    }

    public function testExampleWithMultipleKeys()
    {
        $codeblock = $this->extractCodeBlock('Example with multiple keys');

        $keys = [
            '$privateRsKey' => 'rsa1-private.pem',
            '$publicRsKey' => 'rsa1-public.pub',
            '$privateEcKey' => 'ed25519-1.sec',
            '$publicEcKey' => 'ed25519-1.pub',
        ];
        foreach ($keys as $varName => $keyFile) {
            $codeblock->replace(
                \sprintf('// %s = \'...\'', $varName),
                \sprintf('%s = file_get_contents(\'%s/data/%s\')', $varName, __DIR__, $keyFile)
            );
        }

        $output = $codeblock->invoke();

        $this->assertStringContainsString(
            "Decode 1:\n" . print_r($this->payload, true),
            $output
        );

        $this->assertStringContainsString(
            "Decode 2:\n" . print_r($this->payload, true),
            $output
        );
    }

    public function testUsingJWKs()
    {
        $codeblock = $this->extractCodeBlock('Using JWKs');

        $privateKey = file_get_contents(__DIR__ . '/data/rsa1-private.pem');
        $jwt = JWT::encode($this->payload, $privateKey, 'RS256', 'jwk1');

        $keysJson = file_get_contents(__DIR__ . '/data/rsa-jwkset.json');
        $jwkSet = json_decode($keysJson, true);

        $codeblock->replace('$jwt', \sprintf("'%s'", $jwt));
        $codeblock->replace(
            '[\'keys\' => []]',
            var_export($jwkSet, true)
        );

        $output = $codeblock->invoke();

        $this->assertEquals(
            print_r((object) $this->payload, true),
            $output
        );
    }

    public function testUsingCachedKeySets()
    {
        // We must accept a failure because we are not signing the keys
        // This is the farthest we can go without retreiving an actual JWT
        // or hosting our own JWKs url.
        $this->expectException(SignatureInvalidException::class);
        $this->expectExceptionMessage('Signature verification failed');

        $codeblock = $this->extractCodeBlock('Using Cached Key Sets');

        $jwk = json_decode(file_get_contents('https://www.gstatic.com/iap/verify/public_key-jwk'), true);
        $privateKey = file_get_contents(__DIR__ . '/data/ecdsa256-private.pem');
        $jwt = JWT::encode($this->payload, $privateKey, 'ES256', $jwk['keys'][0]['kid']);

        $codeblock->replace('eyJhbGci...', $jwt);
        $codeblock->invoke();
    }

    private function extractCodeBlock(string $header)
    {
        // Normalize line endings to \n to make regex handling consistent across platforms
        $markdown = str_replace(["\r\n", "\r"], "\n", file_get_contents(__DIR__ . '/../README.md'));

        // find by header
        $pattern = '/^#+\s*' . preg_quote($header, '/') . '\s*\n([\s\S]*?)(?=^#+.*$|\Z)/m';
        if (!preg_match($pattern, $markdown, $matches)) {
            throw new \Exception('Header "' . $header . '" not found in README.md');
        }
        $markdown = trim($matches[1]);

        // extract fenced codeblock
        if (!preg_match_all(self::CODEBLOCK_REGEX, $markdown, $matches, PREG_SET_ORDER)) {
            throw new \Exception('No code block found in README.md under header "' . $header . '"');
        }
        $codeblock = $matches[0][4];

        return new class($codeblock) {
            public function __construct(public string $codeblock)
            {
            }

            public function invoke()
            {
                try {
                    ob_start();
                    eval($this->codeblock);
                    return ob_get_clean();
                } catch (\Exception $e) {
                    ob_end_clean();
                    throw $e;
                }
            }

            public function replace($old, $new)
            {
                $this->codeblock = str_replace($old, $new, $this->codeblock);
            }
        };
    }
}
