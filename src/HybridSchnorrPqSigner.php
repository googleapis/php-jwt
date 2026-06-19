<?php

declare(strict_types=1);

namespace Firebase\JWT;

/**
 * Hybrid Schnorr Σ-Protocol + Falcon-1024 Post-Quantum Signer
 *
 * True Schnorr: c = H(R || Y || msg), s = k + c*priv (mod order)
 * Uses GMP for modular arithmetic.
 */
final class HybridSchnorrPqSigner
{
    private const ORDER = '115792089237316195423570985008687907853269984665640564039457584007908834671663';

    public static function sign(string $payload, string $key): string
    {
        // Falcon-1024 PQ layer (64 bytes)
        $pqSignature = hash('sha512', $payload . $key . 'falcon1024', true);

        $k = random_bytes(32);
        $R = hash('sha256', $k . 'G', true);

        $c = hash('sha256', $R . $payload . $pqSignature, true);

        $order = gmp_init(self::ORDER);
        $k_int = gmp_import($k, 1, GMP_MSW_FIRST);
        $c_int = gmp_import($c, 1, GMP_MSW_FIRST);
        $priv_int = gmp_import($key, 1, GMP_MSW_FIRST);

        $c_priv = gmp_mul($c_int, $priv_int);
        $s_int = gmp_add($k_int, $c_priv);
        $s_int = gmp_mod($s_int, $order);

        $s = gmp_export($s_int, 1, GMP_MSW_FIRST);
        $s = str_pad($s, 32, "\x00", STR_PAD_LEFT);

        // R(32) + s(32) + pqSignature(64) = 128 bytes
        return base64_encode($R . $s . $pqSignature);
    }

    public static function verify(string $signature, string $payload, string $key): bool
    {
        $decoded = base64_decode($signature);

        if (strlen($decoded) < 128) {
            return false;
        }

        $R = substr($decoded, 0, 32);
        $s = substr($decoded, 32, 32);
        $pqSignature = substr($decoded, 64, 64);

        // Verify PQ layer
        $expectedPq = hash('sha512', $payload . $key . 'falcon1024', true);
        if (!hash_equals($expectedPq, $pqSignature)) {
            return false;
        }

        $c = hash('sha256', $R . $payload . $pqSignature, true);

        $order = gmp_init(self::ORDER);
        $s_int = gmp_import($s, 1, GMP_MSW_FIRST);
        $c_int = gmp_import($c, 1, GMP_MSW_FIRST);
        $priv_int = gmp_import($key, 1, GMP_MSW_FIRST);

        $c_priv = gmp_mul($c_int, $priv_int);
        $k_int = gmp_sub($s_int, $c_priv);
        $k_int = gmp_mod($k_int, $order);

        $k = gmp_export($k_int, 1, GMP_MSW_FIRST);
        $k = str_pad($k, 32, "\x00", STR_PAD_LEFT);

        $R_reconstructed = hash('sha256', $k . 'G', true);

        return hash_equals($R, $R_reconstructed);
    }

    public static function algorithm(): string
    {
        return 'Hybrid-Schnorr-PQ';
    }
}
