<?php

namespace Firebase\JWT;

use DomainException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use stdClass;
use TypeError;
use UnexpectedValueException;

class JWTTest extends TestCase
{
    private Key $hmacKey;

    public function setUp(): void
    {
        $this->hmacKey = $this->generateHmac256();
    }

    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode(['message' => 'f?'], $this->hmacKey->getKeyMaterial(), 'HS256');
        $expected = new stdClass();
        $expected->message = 'f?';
        $this->assertEquals($expected, JWT::decode($encoded, $this->hmacKey));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException(DomainException::class);
        JWT::encode(['message' => pack('c', 128)], $this->hmacKey->getKeyMaterial(), 'HS256');
    }

    public function testInvalidKeyOpensslSignFail()
    {
        $this->expectException(DomainException::class);
        JWT::sign('message', 'invalid key', 'openssl');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException(DomainException::class);
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->expectException(ExpiredException::class);
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];

        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($encoded, $this->hmacKey);
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'nbf' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($encoded, $this->hmacKey);
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'iat' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($encoded, $this->hmacKey);
    }

    public function testValidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testExpiredTokenWithLeeway()
    {
        $this->expectException(ExpiredException::class);
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 70, // time far in the past
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertSame($decoded->message, 'abc');
    }

    public function testExpiredExceptionPayload()
    {
        $this->expectException(ExpiredException::class);
        $payload = [
            'message' => 'abc',
            'exp' => time() - 100, // time in the past
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        try {
            JWT::decode($encoded, $this->hmacKey);
        } catch (ExpiredException $e) {
            $exceptionPayload = (array) $e->getPayload();
            $this->assertEquals($exceptionPayload, $payload);
            throw $e;
        }
    }

    /**
     * @runInSeparateProcess
     */
    public function testExpiredExceptionTimestamp()
    {
        $this->expectException(ExpiredException::class);

        JWT::$timestamp = 98765;
        $payload = [
            'message' => 'abc',
            'exp' => 1234,
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');

        try {
            JWT::decode($encoded, $this->hmacKey);
        } catch (ExpiredException $e) {
            $exTimestamp = $e->getTimestamp();
            $this->assertSame(98765, $exTimestamp);
            throw $e;
        }
    }

    public function testBeforeValidExceptionPayload()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'iat' => time() + 100, // time in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        try {
            JWT::decode($encoded, $this->hmacKey);
        } catch (BeforeValidException $e) {
            $exceptionPayload = (array) $e->getPayload();
            $this->assertEquals($exceptionPayload, $payload);
            throw $e;
        }
    }

    public function testValidTokenWithNbf()
    {
        $payload = [
            'message' => 'abc',
            'iat' => time(),
            'exp' => time() + 20, // time in the future
            'nbf' => time() - 20
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 20, // not before in near (leeway) future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testInvalidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 65,  // not before too far in future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with nbf prior to');
        JWT::decode($encoded, $this->hmacKey);
    }

    public function testValidTokenWithNbfIgnoresIat()
    {
        $payload = [
            'message' => 'abc',
            'nbf' => time() - 20, // time in the future
            'iat' => time() + 20, // time in the past
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertEquals('abc', $decoded->message);
    }

    public function testValidTokenWithNbfMicrotime()
    {
        $payload = [
            'message' => 'abc',
            'nbf' => microtime(true), // use microtime
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertEquals('abc', $decoded->message);
    }

    public function testInvalidTokenWithNbfMicrotime()
    {
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with nbf prior to');
        $payload = [
            'message' => 'abc',
            'nbf' => microtime(true) + 20, // use microtime in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($encoded, $this->hmacKey);
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 20, // issued in near (leeway) future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testInvalidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 65, // issued too far in future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with iat prior to');
        JWT::decode($encoded, $this->hmacKey);
    }

    public function testValidTokenWithIatMicrotime()
    {
        $payload = [
            'message' => 'abc',
            'iat' => microtime(true), // use microtime
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $decoded = JWT::decode($encoded, $this->hmacKey);
        $this->assertEquals('abc', $decoded->message);
    }

    public function testInvalidTokenWithIatMicrotime()
    {
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with iat prior to');
        $payload = [
            'message' => 'abc',
            'iat' => microtime(true) + 20, // use microtime in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($encoded, $this->hmacKey);
    }

    public function testInvalidToken()
    {
        $encodeKey = $this->generateHmac256();
        $decodeKey = $this->generateHmac256();
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, $encodeKey->getKeyMaterial(), $encodeKey->getAlgorithm());
        $this->expectException(SignatureInvalidException::class);
        JWT::decode($encoded, $decodeKey);
    }

    public function testNullKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $this->expectException(TypeError::class);
        JWT::decode($encoded, new Key(null, 'HS256'));
    }

    public function testEmptyKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($encoded, new Key('', 'HS256'));
    }

    public function testKIDChooser()
    {
        $keys = [
            '0' => $this->generateHmac256(),
            '1' => $this->generateHmac256(),
            '2' => $this->generateHmac256()
        ];
        $msg = JWT::encode(['message' => 'abc'], $keys['0']->getKeyMaterial(), 'HS256', '0');
        $decoded = JWT::decode($msg, $keys);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = [
            '0' => $this->generateHmac256(),
            '1' => $this->generateHmac256(),
            '2' => $this->generateHmac256()
        ];
        $msg = JWT::encode(['message' => 'abc'], $keys['0']->getKeyMaterial(), 'HS256', '0');
        $decoded = JWT::decode($msg, $keys);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], $this->hmacKey->getKeyMaterial(), 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, new Key($this->hmacKey->getKeyMaterial(), 'none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], $this->hmacKey->getKeyMaterial(), 'HS256');
        $this->expectException(UnexpectedValueException::class);
        // TODO: Generate proper RS256 key
        JWT::decode($msg, new Key($this->hmacKey->getKeyMaterial(), 'RS256'));
    }

    public function testEmptyAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], $this->hmacKey->getKeyMaterial(), 'HS256');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($msg, new Key($this->hmacKey->getKeyMaterial(), ''));
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode(['message' => 'abc'], $this->hmacKey->getKeyMaterial(), 'HS256', null, ['cty' => 'test-eit;v=1']);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals(JWT::decode($msg, $this->hmacKey), $expected);
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::decode('brokenheader.brokenbody', $this->hmacKey);
    }

    public function testInvalidSignatureEncoding()
    {
        $msg = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx';
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, $this->hmacKey);
    }

    public function testHSEncodeDecode()
    {
        $msg = JWT::encode(['message' => 'abc'], $this->hmacKey->getKeyMaterial(), 'HS256');
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals(JWT::decode($msg, $this->hmacKey), $expected);
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);
        $msg = JWT::encode(['message' => 'abc'], $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = JWT::decode($msg, new Key($pubKey, 'RS256'));
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = ['foo' => 'bar'];
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $decoded = JWT::decode($msg, new Key($pubKey, 'EdDSA'));
        $this->assertSame('bar', $decoded->foo);
    }

    public function testInvalidEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = ['foo' => 'bar'];
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        // Generate a different key.
        $keyPair = sodium_crypto_sign_keypair();
        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $this->expectException(SignatureInvalidException::class);
        JWT::decode($msg, new Key($pubKey, 'EdDSA'));
    }

    public function testRSEncodeDecodeWithPassphrase()
    {
        $privateKey = openssl_pkey_get_private(
            file_get_contents(__DIR__ . '/data/rsa-with-passphrase.pem'),
            'passphrase'
        );

        $jwt = JWT::encode(['message' => 'abc'], $privateKey, 'RS256');
        $keyDetails = openssl_pkey_get_details($privateKey);
        $pubKey = $keyDetails['key'];
        $decoded = JWT::decode($jwt, new Key($pubKey, 'RS256'));
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testDecodesEmptyArrayAsObject()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = [];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
        $this->assertEquals((object) $payload, $decoded);
    }

    public function testDecodesArraysInJWTAsArray()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = ['foo' => [1, 2, 3]];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
        $this->assertSame($payload['foo'], $decoded->foo);
    }

    /**
     * @runInSeparateProcess
     * @dataProvider provideEncodeDecode
     */
    public function testEncodeDecode($privateKeyFile, $publicKeyFile, $alg)
    {
        $privateKey = file_get_contents($privateKeyFile);
        $payload = ['foo' => 'bar'];
        $encoded = JWT::encode($payload, $privateKey, $alg);

        // Verify decoding succeeds
        $publicKey = file_get_contents($publicKeyFile);
        $decoded = JWT::decode($encoded, new Key($publicKey, $alg));

        $this->assertSame('bar', $decoded->foo);
    }

    public function provideEncodeDecode()
    {
        return [
            [__DIR__ . '/data/ecdsa-private.pem', __DIR__ . '/data/ecdsa-public.pem', 'ES256'],
            [__DIR__ . '/data/ecdsa384-private.pem', __DIR__ . '/data/ecdsa384-public.pem', 'ES384'],
            [__DIR__ . '/data/rsa1-private.pem', __DIR__ . '/data/rsa1-public.pub', 'RS512'],
            [__DIR__ . '/data/ed25519-1.sec', __DIR__ . '/data/ed25519-1.pub', 'EdDSA'],
            [__DIR__ . '/data/secp256k1-private.pem', __DIR__ . '/data/secp256k1-public.pem', 'ES256K'],
        ];
    }

    public function testEncodeDecodeWithOpenSSLAsymmetricKey()
    {
        $pem = file_get_contents(__DIR__ . '/data/rsa1-public.pub');
        $keyMaterial = openssl_pkey_get_public($pem);
        $privateKey = file_get_contents(__DIR__ . '/data/rsa1-private.pem');

        $payload = ['foo' => 'bar'];
        $encoded = JWT::encode($payload, $privateKey, 'RS512');

        // Verify decoding succeeds
        $decoded = JWT::decode($encoded, new Key($keyMaterial, 'RS512'));

        $this->assertSame('bar', $decoded->foo);
    }

    public function testGetHeaders()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $headers = new stdClass();

        $encoded = JWT::encode($payload, $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($encoded, $this->hmacKey, $headers);

        $this->assertEquals($headers->typ, 'JWT');
        $this->assertEquals($headers->alg, 'HS256');
    }

    public function testAdditionalHeaderOverrides()
    {
        $msg = JWT::encode(
            ['message' => 'abc'],
            $this->hmacKey->getKeyMaterial(),
            'HS256',
            'my_key_id',
            [
                'cty' => 'test-eit;v=1',
                'typ' => 'JOSE', // override type header
                'kid' => 'not_my_key_id', // should not override $key param
                'alg' => 'BAD', // should not override $alg param
            ]
        );
        $headers = new stdClass();
        JWT::decode($msg, $this->hmacKey, $headers);
        $this->assertEquals('test-eit;v=1', $headers->cty, 'additional field works');
        $this->assertEquals('JOSE', $headers->typ, 'typ override works');
        $this->assertEquals('my_key_id', $headers->kid, 'key param not overridden');
        $this->assertEquals('HS256', $headers->alg, 'alg param not overridden');
    }

    public function testDecodeExpectsIntegerIat()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Payload iat must be a number');

        $payload = JWT::encode(['iat' => 'not-an-int'], $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($payload, $this->hmacKey);
    }

    public function testDecodeExpectsIntegerNbf()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Payload nbf must be a number');

        $payload = JWT::encode(['nbf' => 'not-an-int'], $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($payload, $this->hmacKey);
    }

    public function testDecodeExpectsIntegerExp()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Payload exp must be a number');

        $payload = JWT::encode(['exp' => 'not-an-int'], $this->hmacKey->getKeyMaterial(), 'HS256');
        JWT::decode($payload, $this->hmacKey);
    }

    public function testEncodeThrowsWhenIatIsNotNumeric(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Payload iat must be a number');

        JWT::encode(['iat' => 'not-an-int'], $this->hmacKey->getKeyMaterial(), 'HS256');
    }

    public function testEncodeThrowsWhenNbfIsNotNumeric(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Payload nbf must be a number');

        JWT::encode(['nbf' => 'not-an-int'], $this->hmacKey->getKeyMaterial(), 'HS256');
    }

    public function testEncodeThrowsWhenExpIsNotNumeric(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Payload exp must be a number');

        JWT::encode(['exp' => 'not-an-int'], $this->hmacKey->getKeyMaterial(), 'HS256');
    }

    public function testRsaKeyLengthValidationThrowsException(): void
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Provided key is too short');

        // Generate an RSA key that is smaller than the 2048-bit minimum
        $shortRsaKey = openssl_pkey_new([
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        self::assertNotFalse($shortRsaKey, 'Failed to generate a short RSA key for testing.');
        $payload = ['message' => 'abc'];
        JWT::encode($payload, $shortRsaKey, 'RS256');
    }

    /** @dataProvider provideHmac */
    public function testHmacKeyLengthValidationThrowsExceptionEncode(string $alg, int $minLength): void
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Provided key is too short');

        $tooShortKeyBytes = str_repeat('b', $minLength - 1);
        $payload = ['message' => 'abc'];

        JWT::encode($payload, $tooShortKeyBytes, $alg);
    }

    /** @dataProvider provideHmac */
    public function testHmacKeyLengthValidationThrowsExceptionDecode(string $alg, int $minLength): void
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Provided key is too short');

        $tooShortKeyBytes = str_repeat('b', $minLength - 1);
        $payload = ['message' => 'abc'];

        $validKeyBytes = str_repeat('b', $minLength);
        $encoded = JWT::encode($payload, $validKeyBytes, $alg);

        JWT::decode($encoded, new Key($tooShortKeyBytes, $alg));
    }

    /** @dataProvider provideHmac */
    public function testHmacKeyLengthValidationPassesWithCorrectLength(string $alg, int $minLength): void
    {
        $payload = ['message' => 'test hmac length'];

        // Test with a key that is exactly the required length
        $minKeyBytes = str_repeat('b', $minLength);
        $encoded48 = JWT::encode($payload, $minKeyBytes, $alg);
        $decoded48 = JWT::decode($encoded48, new Key($minKeyBytes, $alg));
        $this->assertEquals($payload['message'], $decoded48->message);

        // Test with a key that is longer than the required length
        $largeKeyBytes = str_repeat('c', $minLength * 2); // Longer than min bytes
        $encoded64 = JWT::encode($payload, $largeKeyBytes, $alg);
        $decoded64 = JWT::decode($encoded64, new Key($largeKeyBytes, $alg));
        $this->assertEquals($payload['message'], $decoded64->message);
    }

    public function provideHmac()
    {
        return [
            ['HS384', 48],
            ['HS256', 32],
        ];
    }

    public function testEdDsaHandlesBase64UrlKeys()
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium is not available');
        }

        // Generate a deterministic Ed25519 keypair using a specific seed. The byte "\xfb"
        // translates to '+' and '/' in standard base64, which become '-' and '_' in Base64URL.
        // This guarantees our keys will contain the URL-safe characters that get incorrectly
        // stripped by base64_decode().
        $seed = str_repeat("\xfb", 32);
        $keyPair = sodium_crypto_sign_seed_keypair($seed);

        $secretKey = sodium_crypto_sign_secretkey($keyPair);
        $publicKey = sodium_crypto_sign_publickey($keyPair);

        // Convert the raw keys to Base64URL encoded strings
        $secretKeyB64u = JWT::urlsafeB64Encode($secretKey);
        $publicKeyB64u = JWT::urlsafeB64Encode($publicKey);

        // Ensure our test keys actually contain the characters that get
        // incorrectly stripped by a standard base64_decode().
        $this->assertTrue(strpos($secretKeyB64u, '-') !== false || strpos($secretKeyB64u, '_') !== false);
        $this->assertTrue(strpos($publicKeyB64u, '-') !== false || strpos($publicKeyB64u, '_') !== false);

        // Test Encoding
        $token = JWT::encode(['issue' => 596], $secretKeyB64u, 'EdDSA');
        $this->assertIsString($token);

        // Test Decoding
        $decoded = JWT::decode($token, new Key($publicKeyB64u, 'EdDSA'));
        $this->assertSame(596, $decoded->issue);
    }

    /** @dataProvider provideEcKeyInvalidLength */
    public function testEcKeyLengthValidationThrowsExceptionEncode(string $keyFile, string $alg): void
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Provided key is too short');

        $tooShortEcKey = file_get_contents(__DIR__ . '/data/' . $keyFile);
        $payload = ['message' => 'abc'];

        JWT::encode($payload, $tooShortEcKey, $alg);
    }

    public function testEcKeyLengthValidationThrowsExceptionDecode(): void
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Provided key is too short');

        $payload = ['message' => 'abc'];

        $validEcKeyBytes = file_get_contents(__DIR__ . '/data/ecdsa384-private.pem');
        $encoded = JWT::encode($payload, $validEcKeyBytes, 'ES256');

        $tooShortEcKey = file_get_contents(__DIR__ . '/data/ecdsa192-public.pem');
        JWT::decode($encoded, new Key($tooShortEcKey, 'ES256'));
    }

    /** @dataProvider provideEcKey */
    public function testEcKeyLengthValidationPassesWithCorrectLength(
        string $privateKeyFile,
        string $publicKeyFile,
        string $alg
    ): void {
        $payload = ['message' => 'test hmac length'];

        // Test with a key that is the required length
        $privateKeyBytes = file_get_contents(__DIR__ . '/data/' . $privateKeyFile);
        $encoded48 = JWT::encode($payload, $privateKeyBytes, $alg);

        $publicKeyBytes = file_get_contents(__DIR__ . '/data/' . $publicKeyFile);
        $decoded48 = JWT::decode($encoded48, new Key($publicKeyBytes, $alg));
        $this->assertEquals($payload['message'], $decoded48->message);
    }

    public function provideEcKeyInvalidLength()
    {
        return [
            ['ecdsa192-private.pem', 'ES256'],
            ['ecdsa-private.pem', 'ES384'],
        ];
    }

    public function provideEcKey()
    {
        return [
            ['ecdsa-private.pem', 'ecdsa-public.pem', 'ES256'],
            ['ecdsa384-private.pem', 'ecdsa384-public.pem', 'ES384'],
        ];
    }

    private function generateHmac256(): Key
    {
        return new Key(random_bytes(32), 'HS256');
    }
}
