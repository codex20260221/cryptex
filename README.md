<img src="https://michaelmawhinney.com/cryptex/logo.gif" width="300px">

# Cryptex: 2-way Authenticated Encryption Class

Cryptex is a simple PHP class that performs 2-way authenticated encryption using XChaCha20 + Poly1305.


# Requirements

* PHP 8.1 or newer


# Installation

The preferred method of installation is with Packagist and Composer. The following command installs the package and adds it as a requirement to your project's composer.json:

`composer require michaelmawhinney/cryptex`

You can also download or clone the repo and include the `src/Cryptex.php` manually if you prefer.


# Usage

**Always store or transmit your `$key` and `$salt` values securely.**

```php
<?php
require 'vendor/autoload.php';

use cryptex\Cryptex;

try {

    // Your private data and secret key
    $plaintext = "You're a certified prince.";
    $key = "1-2-3-4-5"; // same combination on my luggage

    // Generate a secure random salt value
    $salt = Cryptex::generateSalt();

    // Encrypt the plaintext
    $ciphertext = Cryptex::encrypt($plaintext, $key, $salt);
    // example result (base64url v1 envelope):
    // ASf8r8WJw1wk8iVdZ46f2pW0W6A3Q-1f_Af95WSCWEMBqTwO1ATz5JblY74oe_2mlIuSMY4WbM-0rbxPGV4

    // Decrypt the ciphertext
    $result = Cryptex::decrypt($ciphertext, $key, $salt);

} catch (Exception $e) {

    // There was some error during salt generation, encryption, authentication, or decryption
    echo 'Caught exception: ' . $e->getMessage() . "\n";

}

// Verify with a timing attack safe string comparison
if (hash_equals($plaintext, $result)) {

    // Cryptex securely encrypted and decrypted the data
    echo "Pass";

} else {

    // There was some failure that did not generate any exceptions
    echo "Fail";

}

// The above example will output: Pass
```


## Ciphertext format

Cryptex now emits a versioned URL-safe Base64 payload from `encrypt()`:

- `1-byte version` (`0x01`)
- `salt` (`SODIUM_CRYPTO_PWHASH_SALTBYTES`)
- `nonce` (`SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES`)
- `ciphertext+tag`

The final string is encoded with `sodium_bin2base64(..., SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)`.

For backward compatibility, `decrypt()` also accepts legacy hex payloads (`nonce|ciphertext+tag` hex encoded).

# Testing

The PHPUnit test class is in `tests/CryptexTest.php`.

If you installed Cryptex with Composer, you can run the following command in the top-level folder of this project to perform the unit tests:

`./vendor/bin/phpunit --bootstrap vendor/autoload.php tests`

If `phpunit` is already installed on your local system, you can run this command instead:

`phpunit tests`


# Generating Documentation

Cryptex uses phpDocumentor to automatically generate documentation whenever changes are made. The generated documentation is [available online here](https://michaelmawhinney.github.io/cryptex/). However if you want to generate the documentation locally, you can run the following command in the top-level folder of this project (requires docker):

`docker run --rm -v "$(pwd):/data" "phpdoc/phpdoc:3" -d src,tests -t docs`

If you want to use another method of running/installing phpdoc, refer to the [phpDocumentor documentation](https://www.phpdoc.org/).
