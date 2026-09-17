<?php

namespace Firebase\JWT;

use LogicException;
use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;

class CachedKeySetTest extends TestCase
{
    use ProphecyTrait;

    private $testJwksUri = 'https://jwk.uri';
    private $testJwksUriKey = 'jwkshttpsjwk.uri';
    private $testJwks1 = '{"keys": [{"kid":"foo","kty":"RSA","alg":"foo","n":"","e":""}]}';
    private $testCachedJwks1 = ['foo' => ['kid' => 'foo', 'kty' => 'RSA', 'alg' => 'foo', 'n' => '', 'e' => '']];
    private $testJwks2 = '{"keys": [{"kid":"bar","kty":"RSA","alg":"bar","n":"","e":""}]}';
    private $testJwks3 = '{"keys": [{"kid":"baz","kty":"RSA","n":"","e":""}]}';

    private $googleRsaUri = 'https://www.googleapis.com/oauth2/v3/certs';
    private $googleEcUri = 'https://www.gstatic.com/iap/verify/public_key-jwk';

    public function testEmptyUriThrowsException()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('JWKS URI is empty');

        $cachedKeySet = new CachedKeySet(
            '',
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        $cachedKeySet['foo'];
    }

    public function testOffsetSetThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        $cachedKeySet['foo'] = 'bar';
    }

    public function testOffsetUnsetThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        unset($cachedKeySet['foo']);
    }

    public function testOutOfBoundsThrowsException()
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Key ID not found');

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );

        // keyID doesn't exist
        $cachedKeySet['bar'];
    }

    public function testInvalidHttpResponseThrowsException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('HTTP Error: 404 URL not found');
        $this->expectExceptionCode(404);

        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getStatusCode()
            ->shouldBeCalled()
            ->willReturn(404);
        $response->getReasonPhrase()
            ->shouldBeCalledTimes(1)
            ->willReturn('URL not found');

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldBeCalledTimes(1)
            ->willReturn($response->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $http->reveal(),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );

        isset($cachedKeySet[0]);
    }

    public function testWithExistingKeyId()
    {
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testWithDefaultAlg()
    {
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks3),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache(),
            null,
            false,
            'baz256'
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['baz']);
        $this->assertSame('baz256', $cachedKeySet['baz']->getAlgorithm());
    }

    public function testKeyIdIsCached()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn($this->testCachedJwks1);

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testCachedKeyIdRefresh()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(true);
        $cacheItem->get()
            ->shouldBeCalledOnce()
            ->willReturn($this->testCachedJwks1);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks2), // updated JWK
            $this->getMockHttpFactory(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());

        $this->assertInstanceOf(Key::class, $cachedKeySet['bar']);
        $this->assertSame('bar', $cachedKeySet['bar']->getAlgorithm());
    }

    public function testKeyIdIsCachedFromPreviousFormat()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn($this->testJwks1);

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testCachedKeyIdRefreshFromPreviousFormat()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(true);
        $cacheItem->get()
            ->shouldBeCalledOnce()
            ->willReturn($this->testJwks1);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks2), // updated JWK
            $this->getMockHttpFactory(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());

        $this->assertInstanceOf(Key::class, $cachedKeySet['bar']);
        $this->assertSame('bar', $cachedKeySet['bar']->getAlgorithm());
    }

    public function testCacheItemWithExpiresAfter()
    {
        $expiresAfter = 10;
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });
        $cacheItem->expiresAfter($expiresAfter)
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce();

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1),
            $this->getMockHttpFactory(),
            $cache->reveal(),
            $expiresAfter
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertSame('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testJwtVerify()
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/rsa1-private.pem');
        $payload = ['sub' => 'foo', 'exp' => strtotime('+10 seconds')];
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');

        // format the cached value to match the expected format
        $cachedJwks = [];
        $rsaKeySet = file_get_contents(__DIR__ . '/data/rsa-jwkset.json');
        foreach (json_decode($rsaKeySet, true)['keys'] as $k => $v) {
            $cachedJwks[$v['kid']] = $v;
        }

        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn($cachedJwks);

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->willReturn($cacheItem->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );

        $result = JWT::decode($msg, $cachedKeySet);

        $this->assertSame('foo', $result->sub);
    }

    public function testRateLimit()
    {
        // We request the key 11 times, HTTP should only be called 10 times
        $shouldBeCalledTimes = 10;

        // Instantiate the cached key set
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1, $shouldBeCalledTimes),
            $this->getMockHttpFactory($shouldBeCalledTimes),
            $this->getTestMemoryCacheItemPool(),
            10,  // expires after seconds
            true // enable rate limiting
        );

        $invalidKid = 'invalidkey';
        for ($i = 0; $i < 10; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }
        // The 11th time does not call HTTP
        $this->assertFalse(isset($cachedKeySet[$invalidKid]));
    }

    public function testRateLimitWithExpiresAfter()
    {
        // We request the key 17 times, HTTP should only be called 15 times
        $shouldBeCalledTimes = 10;
        $cachedTimes = 2;
        $afterExpirationTimes = 5;

        $totalHttpTimes = $shouldBeCalledTimes + $afterExpirationTimes;

        $cachePool = $this->getTestMemoryCacheItemPool();

        // Instantiate the cached key set
        $cachedKeySet = new CachedKeySet(
            $this->testJwksUri,
            $this->getMockHttpClient($this->testJwks1, $totalHttpTimes),
            $this->getMockHttpFactory($totalHttpTimes),
            $cachePool,
            10,   // expires after seconds
            true // enable rate limiting
        );

        // Set the rate limit cache to expire after 1 second
        $cacheItem = $cachePool->getItem('jwksratelimitjwkshttpsjwk.uri');
        $cacheItem->set([
            'expiry' => new \DateTime('+1 second', new \DateTimeZone('UTC')),
            'callsPerMinute' => 0,
        ]);
        $cacheItem->expiresAfter(1);
        $cachePool->save($cacheItem);

        $invalidKid = 'invalidkey';
        for ($i = 0; $i < $shouldBeCalledTimes; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }

        // The next calls do not call HTTP
        for ($i = 0; $i < $cachedTimes; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }

        sleep(1); // wait for cache to expire

        // These calls DO call HTTP because the cache has expired
        for ($i = 0; $i < $afterExpirationTimes; $i++) {
            $this->assertFalse(isset($cachedKeySet[$invalidKid]));
        }
    }

    /**
     * @dataProvider provideFullIntegration
     */
    public function testFullIntegration(string $jwkUri): void
    {
        if (!class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            self::markTestSkipped('Guzzle 7 only');
        }
        // Create cache and http objects
        $cache = $this->getTestMemoryCacheItemPool();
        $http = new \GuzzleHttp\Client();
        $factory = new \GuzzleHttp\Psr7\HttpFactory();

        // Determine "kid" dynamically, because these constantly change
        $response = $http->get($jwkUri);
        $json = (string) $response->getBody();
        $keys = json_decode($json, true);
        $kid = $keys['keys'][0]['kid'] ?? null;
        $this->assertNotNull($kid);

        // Instantiate the cached key set
        $cachedKeySet = new CachedKeySet(
            $jwkUri,
            $http,
            $factory,
            $cache
        );

        $this->assertArrayHasKey($kid, $cachedKeySet);
        $key = $cachedKeySet[$kid];
        $this->assertInstanceOf(Key::class, $key);
        $this->assertSame($keys['keys'][0]['alg'], $key->getAlgorithm());
    }

    public function provideFullIntegration()
    {
        return [
            [$this->googleRsaUri],
            [$this->googleEcUri, 'LYyP2g']
        ];
    }

    private function getMockHttpClient($testJwks, int $timesCalled = 1)
    {
        $body = $this->prophesize('Psr\Http\Message\StreamInterface');
        $body->__toString()
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($testJwks);

        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getBody()
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($body->reveal());
        $response->getStatusCode()
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn(200);

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($response->reveal());

        return $http->reveal();
    }

    private function getMockHttpFactory(int $timesCalled = 1)
    {
        $request = $this->prophesize('Psr\Http\Message\RequestInterface');
        $factory = $this->prophesize(RequestFactoryInterface::class);
        $factory->createRequest('GET', $this->testJwksUri)
            ->shouldBeCalledTimes($timesCalled)
            ->willReturn($request->reveal());

        return $factory->reveal();
    }

    private function getMockEmptyCache()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwksUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        return $cache->reveal();
    }

    private function getTestMemoryCacheItemPool()
    {
        return new class() implements CacheItemPoolInterface {
            private $items;
            private $deferredItems;

            public function getItem($key): CacheItemInterface
            {
                $item = current($this->getItems([$key]));
                $item->expiresAt(null); // mimic symfony cache behavior

                return $item;
            }

            public function getItems(array $keys = []): iterable
            {
                $items = [];

                foreach ($keys as $key) {
                    $items[$key] = $this->hasItem($key) ?
                        clone $this->items[$key] :
                        $this->getTestMemoryCacheItem($key);
                }

                return $items;
            }

            public function hasItem($key): bool
            {
                return isset($this->items[$key]) && $this->items[$key]->isHit();
            }

            public function clear(): bool
            {
                $this->items = [];
                $this->deferredItems = [];

                return true;
            }

            public function deleteItem($key): bool
            {
                return $this->deleteItems([$key]);
            }

            public function deleteItems(array $keys): bool
            {
                foreach ($keys as $key) {
                    unset($this->items[$key]);
                }

                return true;
            }

            public function save(CacheItemInterface $item): bool
            {
                $this->items[$item->getKey()] = $item;

                return true;
            }

            public function saveDeferred(CacheItemInterface $item): bool
            {
                $this->deferredItems[$item->getKey()] = $item;

                return true;
            }

            public function commit(): bool
            {
                foreach ($this->deferredItems as $item) {
                    $this->save($item);
                }

                $this->deferredItems = [];

                return true;
            }

            private function getTestMemoryCacheItem(string $key)
            {
                return new class($key) implements CacheItemInterface{
                    private $key;
                    private $value;
                    private $expiration;
                    private $isHit = false;

                    public function __construct(string $key)
                    {
                        $this->key = $key;
                    }

                    public function getKey(): string
                    {
                        return $this->key;
                    }

                    public function get(): mixed
                    {
                        return $this->isHit() ? $this->value : null;
                    }

                    public function isHit(): bool
                    {
                        if (!$this->isHit) {
                            return false;
                        }

                        if ($this->expiration === null) {
                            return true;
                        }

                        return $this->currentTime()->getTimestamp() < $this->expiration->getTimestamp();
                    }

                    public function set(mixed $value): static
                    {
                        $this->isHit = true;
                        $this->value = $value;

                        return $this;
                    }

                    public function expiresAt($expiration): static
                    {
                        $this->expiration = $expiration;
                        return $this;
                    }

                    public function expiresAfter($time): static
                    {
                        $this->expiration = $this->currentTime()->add(new \DateInterval("PT{$time}S"));
                        return $this;
                    }

                    protected function currentTime()
                    {
                        return new \DateTime('now', new \DateTimeZone('UTC'));
                    }
                };
            }
        };
    }
}
