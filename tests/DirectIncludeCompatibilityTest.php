<?php

declare(strict_types=1);

namespace cryptex;

use Composer\Autoload\ClassLoader;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class DirectIncludeCompatibilityTest extends TestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testDirectIncludeSupportsEncryptDecryptRoundTrip(): void
    {
        $composerLoaderReplaced = false;

        foreach (spl_autoload_functions() as $autoload) {
            if (is_array($autoload) && $autoload[0] instanceof ClassLoader) {
                spl_autoload_unregister($autoload);
                spl_autoload_register(
                    static function (string $class) use ($autoload): void {
                        if (str_starts_with($class, __NAMESPACE__ . '\\')) {
                            return;
                        }

                        $autoload[0]->loadClass($class);
                    }
                );
                $composerLoaderReplaced = true;
                break;
            }
        }

        $this->assertTrue($composerLoaderReplaced);
        $this->assertFalse(class_exists(Cryptex::class));

        require __DIR__ . '/../src/Cryptex.php';

        $salt = str_repeat("\x00", SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $plaintext = 'direct include compatibility';
        $key = 'test-only-key-material';
        $ciphertext = Cryptex::encrypt($plaintext, $key, $salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $key, $salt));
    }
}
