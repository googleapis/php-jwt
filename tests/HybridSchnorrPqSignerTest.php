<?php

declare(strict_types=1);

namespace Firebase\JWT\Tests;

use Firebase\JWT\HybridSchnorrPqSigner;
use PHPUnit\Framework\TestCase;

final class HybridSchnorrPqSignerTest extends TestCase
{
    private string $key;

    protected function setUp(): void
    {
        $this->key = str_repeat('a', 2305);
    }

    public function testAlgorithm(): void
    {
        $this->assertSame('Hybrid-Schnorr-PQ', HybridSchnorrPqSigner::algorithm());
    }

    public function testSignAndVerify(): void
    {
        $payload = 'test.payload';
        $signature = HybridSchnorrPqSigner::sign($payload, $this->key);

        $this->assertNotEmpty($signature);
        $this->assertTrue(
            HybridSchnorrPqSigner::verify($signature, $payload, $this->key)
        );
    }

    public function testRejectsTamperedSignature(): void
    {
        $payload = 'test.payload';
        $signature = HybridSchnorrPqSigner::sign($payload, $this->key);
        $signature[0] = chr(ord($signature[0]) ^ 0xFF);

        $this->assertFalse(
            HybridSchnorrPqSigner::verify($signature, $payload, $this->key)
        );
    }

    public function testRejectsWrongKey(): void
    {
        $payload = 'test.payload';
        $key1 = str_repeat('a', 2305);
        $key2 = str_repeat('b', 2305);

        $signature = HybridSchnorrPqSigner::sign($payload, $key1);

        $this->assertFalse(
            HybridSchnorrPqSigner::verify($signature, $payload, $key2)
        );
    }
}
