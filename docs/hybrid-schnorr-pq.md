# Hybrid Schnorr-PQ Signer

## Overview

This signer combines two cryptographic primitives:
- **Schnorr Σ-Protocol** (RFC 8235) — Zero-knowledge proof capability
- **Falcon-1024** (NIST FIPS 204 Level 5) — Post-quantum resistance

## Why Hybrid?

| Layer | Purpose |
|-------|---------|
| Schnorr ZKP | Non-interactive zero-knowledge proof |
| Falcon-1024 | 256-bit quantum resistance |

## Algorithm
Generate Falcon-1024 PQ signature

Generate Schnorr nonce k

R = k * G

c = H(R || Y || msg || pq_signature)

s = k + c * priv (mod order)

Output: R || s || pq_signature


## Usage

```php
use Firebase\JWT\HybridSchnorrPqSigner;

$signer = HybridSchnorrPqSigner::sign($payload, $privateKey);
$verified = HybridSchnorrPqSigner::verify($signature, $payload, $publicKey);
References
RFC 8235 — Schnorr Signatures

NIST FIPS 204 — Falcon-1024

Falcon Website
