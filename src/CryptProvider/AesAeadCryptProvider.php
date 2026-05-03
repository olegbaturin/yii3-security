<?php

declare(strict_types=1);

namespace Yiisoft\Security\CryptProvider;

use RuntimeException;
use SensitiveParameter;
use Yiisoft\Security\CryptProviderInterface;
use Yiisoft\Strings\StringHelper;

final class AesAeadCryptProvider implements CryptProviderInterface
{
    /**
     * @var array[] Look-up table of block sizes and key sizes for each supported OpenSSL cipher.
     *
     * In each element, the key is one of the ciphers supported by OpenSSL {@see openssl_get_cipher_methods()}.
     * The value is an array of two integers, the first is the cipher's block size in bytes and the second is
     * the key size in bytes.
     *
     * > Note: Yii's encryption protocol uses the same size for cipher key, HMAC signature key and key
     * derivation salt.
     */
    private const ALLOWED_CIPHERS = [
        'AES-128-GCM' => [12, 16],
        'AES-192-GCM' => [12, 24],
        'AES-256-GCM' => [12, 32],
    ];

    private bool $randomNounce = false;

    /**
     * @var string HKDF info value for derivation of message authentication key.
     */
    private string $nounceInfo = 'nounce';

    /**
     * @var string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512.
     *
     * @see https://php.net/manual/en/function.hash-algos.php
     */
    private string $kdfAlgorithm = 'sha256';

    /**
     * @var string HKDF info value for derivation of message authentication key.
     */
    private string $authorizationKeyInfo = 'AuthorizationKey';
    /**
     * @var int Derivation iterations count.
     * Set as high as possible to hinder dictionary password attacks.
     */
    private int $derivationIterations = 600000;

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     */
    public function __construct(
        private readonly string $cipher = 'AES-256-GCM',
        private readonly int $tagLength = 16,
    ) {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('Encryption requires the OpenSSL PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException($cipher . ' is not an allowed cipher.');
        }
    }

    /**
     * @psalm-mutation-free
     *
     * @param string $algorithm Hash algorithm for key derivation. Recommend sha256, sha384 or sha512.
     */
    public function withKdfAlgorithm(string $algorithm): self
    {
        $new = clone $this;
        $new->kdfAlgorithm = $algorithm;
        return $new;
    }

    /**
     * @psalm-mutation-free
     *
     * @param string $info HKDF info value for derivation of message authentication key.
     */
    public function withAuthorizationKeyInfo(string $info): self
    {
        $new = clone $this;
        $new->authorizationKeyInfo = $info;
        return $new;
    }

    /**
     * @psalm-mutation-free
     *
     * @param int $iterations Derivation iterations count.
     * Set as high as possible to hinder dictionary password attacks.
     */
    public function withDerivationIterations(int $iterations): self
    {
        $new = clone $this;
        $new->derivationIterations = $iterations;
        return $new;
    }

    public function encrypt(
        string $data,
        bool $passwordBased,
        #[SensitiveParameter]
        string $secret,
        string $info = ''
    ): string {
        [$nounceSize, $keySize] = self::ALLOWED_CIPHERS[$this->cipher];

        $keySalt = random_bytes($keySize);
        if ($passwordBased) {
            $key = hash_pbkdf2($this->kdfAlgorithm, $secret, $keySalt, $this->derivationIterations, $keySize, true);
        } else {
            $key = hash_hkdf($this->kdfAlgorithm, $secret, $keySize, $info, $keySalt);
        }

        $iv = $this->randomNounce
                ? random_bytes($nounceSize)
                : hash_hkdf($this->kdfAlgorithm, $key, $nounceSize, $this->nounceInfo);

        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', $this->tagLength);
        if ($encrypted === false) {
            /**
             * @psalm-suppress PossiblyFalseOperand `openssl_encrypt()` is returned `false`, so `openssl_error_string()`
             * always returns string.
             */
            throw new RuntimeException('OpenSSL failure on encryption: ' . openssl_error_string());
        }

        /*
         * Output: [keySalt][MAC][IV][ciphertext]
         * - keySalt is KEY_SIZE bytes long
         * - MAC: message authentication code, length same as the output of MAC_HASH
         * - IV: initialization vector, length $blockSize
         */
        return $this->randomNounce
                ? $keySalt . $iv . $encrypted . $tag
                : $keySalt . $encrypted . $tag;
    }

    public function decrypt(
        string $data,
        bool $passwordBased,
        #[SensitiveParameter]
        string $secret,
        string $info
    ): string {
        [$nounceSize, $keySize] = self::ALLOWED_CIPHERS[$this->cipher];

        $keySalt = StringHelper::byteSubstring($data, 0, $keySize);
        if ($passwordBased) {
            $key = hash_pbkdf2($this->kdfAlgorithm, $secret, $keySalt, $this->derivationIterations, $keySize, true);
        } else {
            $key = hash_hkdf($this->kdfAlgorithm, $secret, $keySize, $info, $keySalt);
        }

        if ($this->randomNounce) {
            $iv = StringHelper::byteSubstring($data, $keySize, $nounceSize);
            $encrypted = StringHelper::byteSubstring($data, $keySize + $nounceSize, -$this->tagLength);
        } else {
            $iv = hash_hkdf($this->kdfAlgorithm, $key, $nounceSize, $this->nounceInfo);
            $encrypted = StringHelper::byteSubstring($data, $keySize, -$this->tagLength);
        }

        $tag = StringHelper::byteSubstring($data, -$this->tagLength);

        $decrypted = openssl_decrypt($encrypted, $this->cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted === false) {
            /**
             * @psalm-suppress PossiblyFalseOperand `openssl_decrypt()` is returned `false`, so `openssl_error_string()`
             * always returns string.
             */
            throw new RuntimeException('OpenSSL failure on decryption: ' . openssl_error_string());
        }

        return $decrypted;
    }
}