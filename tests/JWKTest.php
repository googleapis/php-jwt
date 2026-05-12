<?php

namespace Firebase\JWT;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class JWKTest extends TestCase
{
    private static $keys;

    public static function setUpBeforeClass(): void
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        self::$keys = JWK::parseKeySet($jwkSet);
    }

    public function testMissingKty()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('JWK must contain a "kty" parameter');

        $badJwk = ['kid' => 'foo'];
        $keys = JWK::parseKeySet(['keys' => [$badJwk]]);
    }

    public function testInvalidAlgorithm()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('No supported algorithms found in JWK Set');

        $badJwk = ['kty' => 'BADTYPE', 'alg' => 'RSA256'];
        $keys = JWK::parseKeySet(['keys' => [$badJwk]]);
    }

    public function testParsePrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RSA private keys are not supported');

        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        $jwkSet['keys'][0]['d'] = 'privatekeyvalue';

        JWK::parseKeySet($jwkSet);
    }

    public function testParsePrivateKeyWithoutAlg()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('JWK must contain an "alg" parameter');

        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        unset($jwkSet['keys'][0]['alg']);

        JWK::parseKeySet($jwkSet);
    }

    public function testParsePrivateKeyWithoutAlgWithDefaultAlgParameter()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        unset($jwkSet['keys'][0]['alg']);

        $jwks = JWK::parseKeySet($jwkSet, 'foo');
        $this->assertSame('foo', $jwks['jwk1']->getAlgorithm());
    }

    public function testParseKeyWithEmptyDValue()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );

        // empty or null values are ok
        $jwkSet['keys'][0]['d'] = null;

        $keys = JWK::parseKeySet($jwkSet);
        $this->assertTrue(\is_array($keys));
    }

    /** @dataProvider provideParseJwkKeySet */
    public function testParseJwkKeySet($jwkFile, $keyId, $pubkeyFile)
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/' . $jwkFile),
            true
        );
        $keys = JWK::parseKeySet($jwkSet);
        $this->assertTrue(\is_array($keys));
        $this->assertArrayHasKey($keyId, $keys);

        // verify public key
        $keyMaterial = $keys[$keyId]->getKeyMaterial();
        $publicKey = openssl_pkey_get_details($keyMaterial)['key'];

        $this->assertEquals(
            file_get_contents(__DIR__ . '/data/' . $pubkeyFile),
            $publicKey
        );
    }

    public function provideParseJwkKeySet()
    {
        return [
            ['rsa-jwkset.json', 'jwk1', 'rsa1-public.pub'],
            ['rsa-jwkset-2.json', 'jwk2', 'rsa-jwk2-public.pub'],
        ];
    }

    public function testParseJwkKey_empty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JWK must not be empty');

        JWK::parseKeySet(['keys' => [[]]]);
    }

    public function testParseJwkKeySet_empty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JWK Set did not contain any keys');

        JWK::parseKeySet(['keys' => []]);
    }

    /**
     * @depends testParseJwkKeySet
     */
    public function testDecodeByJwkKeySetTokenExpired()
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/rsa1-private.pem');
        $payload = ['exp' => strtotime('-1 hour')];
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');

        $this->expectException(ExpiredException::class);

        JWT::decode($msg, self::$keys);
    }

    /**
     * @dataProvider provideDecodeByJwkKeySet
     */
    public function testDecodeByJwkKeySet($pemFile, $jwkFile, $alg, $keyId)
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/' . $pemFile);
        $payload = ['sub' => 'foo', 'exp' => strtotime('+10 seconds')];
        $msg = JWT::encode($payload, $privKey1, $alg, $keyId);

        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/' . $jwkFile),
            true
        );

        $keys = JWK::parseKeySet($jwkSet);
        $result = JWT::decode($msg, $keys);

        $this->assertSame('foo', $result->sub);
    }

    public function provideDecodeByJwkKeySet()
    {
        return [
            ['rsa1-private.pem', 'rsa-jwkset.json', 'RS256', 'jwk1'],
            ['ecdsa256-private.pem', 'ec-jwkset.json', 'ES256', 'jwk1'],
            ['ecdsa384-private.pem', 'ec-jwkset.json', 'ES384', 'jwk4'],
            ['ecdsa512-private.pem', 'ec-jwkset.json', 'ES512', 'jwk5'],
            ['ed25519-1.sec', 'ed25519-jwkset.json', 'EdDSA', 'jwk1'],
        ];
    }

    /**
     * @depends testParseJwkKeySet
     */
    public function testDecodeByMultiJwkKeySet()
    {
        $privKey2 = file_get_contents(__DIR__ . '/data/rsa2-private.pem');
        $payload = ['sub' => 'bar', 'exp' => strtotime('+10 seconds')];
        $msg = JWT::encode($payload, $privKey2, 'RS256', 'jwk2');

        $result = JWT::decode($msg, self::$keys);

        $this->assertSame('bar', $result->sub);
    }

    public function testDecodeByOctetJwkKeySet()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/octet-jwkset.json'),
            true
        );
        $keys = JWK::parseKeySet($jwkSet);
        $payload = ['sub' => 'foo', 'exp' => strtotime('+10 seconds')];
        foreach ($keys as $keyId => $key) {
            $msg = JWT::encode($payload, $key->getKeyMaterial(), $key->getAlgorithm(), $keyId);
            $result = JWT::decode($msg, $keys);

            $this->assertSame('foo', $result->sub);
        }
    }

    public function testOctetJwkMissingK()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('k not set');

        $badJwk = ['kty' => 'oct', 'alg' => 'HS256'];
        $keys = JWK::parseKeySet(['keys' => [$badJwk]]);
    }

    public function testParseKey()
    {
        // Use a known module and exponent, and ensure it parses as expected
        $jwk = [
            'alg' => 'RS256',
            'kty' => 'RSA',
            'n' => 'hsYvCPtkUV7SIxwkOkJsJfhwV_CMdXU5i0UmY2QEs-Pa7v0-0y-s4EjEDtsQ8Yow6hc670JhkGBcMzhU4DtrqNGROXebyOse5FX0m0UvWo1qXqNTf28uBKB990mY42Icr8sGjtOw8ajyT9kufbmXi3eZKagKpG0TDGK90oBEfoGzCxoFT87F95liNth_GoyU5S8-G3OqIqLlQCwxkI5s-g2qvg_aooALfh1rhvx2wt4EJVMSrdnxtPQSPAtZBiw5SwCnVglc6OnalVNvAB2JArbqC9GAzzz9pApAk28SYg5a4hPiPyqwRv-4X1CXEK8bO5VesIeRX0oDf7UoM-pVAw',
            'use' => 'sig',
            'e' => 'AQAB',
            'kid' => '838c06c62046c2d948affe137dd5310129f4d5d1'
        ];

        $key = JWK::parseKey($jwk);
        $this->assertNotNull($key);

        $openSslKey = $key->getKeyMaterial();
        $pubKey = openssl_pkey_get_public($openSslKey);
        $keyData = openssl_pkey_get_details($pubKey);

        $expectedPublicKey = <<<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhsYvCPtkUV7SIxwkOkJs
JfhwV/CMdXU5i0UmY2QEs+Pa7v0+0y+s4EjEDtsQ8Yow6hc670JhkGBcMzhU4Dtr
qNGROXebyOse5FX0m0UvWo1qXqNTf28uBKB990mY42Icr8sGjtOw8ajyT9kufbmX
i3eZKagKpG0TDGK90oBEfoGzCxoFT87F95liNth/GoyU5S8+G3OqIqLlQCwxkI5s
+g2qvg/aooALfh1rhvx2wt4EJVMSrdnxtPQSPAtZBiw5SwCnVglc6OnalVNvAB2J
ArbqC9GAzzz9pApAk28SYg5a4hPiPyqwRv+4X1CXEK8bO5VesIeRX0oDf7UoM+pV
AwIDAQAB
-----END PUBLIC KEY-----

EOF;

        $this->assertEquals($expectedPublicKey, $keyData['key']);
    }
}
