<?php

declare(strict_types=1);

namespace cryptex;

/** Thrown when the decoded payload is too short. */
class NonceLengthException extends EncryptionException
{
}
