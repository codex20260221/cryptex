<?php

declare(strict_types=1);

namespace cryptex;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class ExceptionAutoloadTest extends TestCase
{
    #[DataProvider('publicExceptionProvider')]
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testPublicExceptionCanBeAutoloadedIndependently(string $className, string $parentClass): void
    {
        $this->assertFalse(class_exists(Cryptex::class, false));
        $this->assertFalse(class_exists($className, false));
        $this->assertTrue(class_exists($className));
        $this->assertTrue(is_subclass_of($className, $parentClass));
        $this->assertFalse(class_exists(Cryptex::class, false));

        $reflection = new ReflectionClass($className);
        $fileName = $reflection->getFileName();

        $this->assertIsString($fileName);
        $this->assertSame($reflection->getShortName() . '.php', basename($fileName));
    }

    /** @return array<string, array{class-string<\Throwable>, class-string<\Throwable>}> */
    public static function publicExceptionProvider(): array
    {
        return [
            'encryption' => [EncryptionException::class, \Exception::class],
            'encoding' => [EncodingException::class, EncryptionException::class],
            'nonce length' => [NonceLengthException::class, EncryptionException::class],
            'decryption' => [DecryptionException::class, EncryptionException::class],
            'salt length' => [SaltLengthException::class, EncryptionException::class],
        ];
    }
}
