<?php

declare(strict_types=1);

namespace cryptex;

/**
 * Test-only namespace override that fails if invalid ciphertext reaches Argon2id.
 */
function sodium_crypto_pwhash(
    int $length,
    string $password,
    string $salt,
    int $opslimit,
    int $memlimit,
    int $algo
): string {
    throw new \LogicException('Key derivation ran before ciphertext validation');
}
