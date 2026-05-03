<?php

declare(strict_types=1);

namespace Yiisoft\Security\CryptProvider;

use RuntimeException;
use SensitiveParameter;
use Yiisoft\Security\CryptProviderInterface;
use Yiisoft\Strings\StringHelper;

final class SodiumCryptProvider implements CryptProviderInterface
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
        //'AEGIS-128L' => [16, 16], // >=8.4
        //'AEGIS-256' => [32, 32], // >=8.4
        'AES-256-GCM' => [SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES, SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES],
        'ChaCha20-Poly1305' => [SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES],
        'ChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES],
        'XChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES],
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
     * @var int Derivation iterations count.
     * Set as high as possible to hinder dictionary password attacks.
     */
    private int $derivationIterations = 600000;

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     */
    public function __construct(
        private readonly string $cipher = 'AES-256-GCM'
    ) {
        if (!extension_loaded('sodium')) { // libsodium
            throw new RuntimeException('Encryption requires the Sodium PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException($cipher . ' is not an allowed cipher.');
        }
        if ($cipher === 'AES-256-GCM' && !sodium_crypto_aead_aes256gcm_is_available()) {
            throw new RuntimeException($cipher . ' requires hardware supports hardware-accelerated AES.');
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

        $nounce = $this->randomNounce
                ? random_bytes($nounceSize)
                : hash_hkdf($this->kdfAlgorithm, $key, $nounceSize, $this->nounceInfo);

        $encrypted = match ($this->cipher) {
            //'AEGIS-128L' => sodium_crypto_aead_aegis128l_encrypt($data, '', $nounce, $key),
            //'AEGIS-256' => sodium_crypto_aead_aegis256_encrypt($data, '', $nounce, $key),
            'AES-256-GCM' => sodium_crypto_aead_aes256gcm_encrypt($data, '', $nounce, $key),
            'ChaCha20-Poly1305' => sodium_crypto_aead_chacha20poly1305_encrypt($data, '', $nounce, $key),
            'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_encrypt($data, '', $nounce, $key),
            'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($data, '', $nounce, $key),
        };

        if ($encrypted === false) {
            /**
             * @psalm-suppress PossiblyFalseOperand `openssl_encrypt()` is returned `false`, so `openssl_error_string()`
             * always returns string.
             */
            throw new RuntimeException('Sodium failure on encryption');
        }

        /*
         * Output: [nounce][ciphertext][tag]
         * - nounce is KEY_SIZE bytes long
         * - tag: message authentication code, length same as the output of MAC_HASH
         */
        return $this->randomNounce
                ? $keySalt . $nounce . $encrypted
                : $keySalt . $encrypted;
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
            $nounce = StringHelper::byteSubstring($data, $keySize, $nounceSize);
            $encrypted = StringHelper::byteSubstring($data, $keySize + $nounceSize);
        } else {
            $nounce = hash_hkdf($this->kdfAlgorithm, $key, $nounceSize, $this->nounceInfo);
            $encrypted = StringHelper::byteSubstring($data, $keySize);
        }

        $decrypted = match ($this->cipher) {
            //'AEGIS-128L' => sodium_crypto_aead_aegis128l_decrypt($encrypted, '', $nounce, $key),
            //'AEGIS-256' => sodium_crypto_aead_aegis256_decrypt($encrypted, '', $nounce, $key),
            'AES-256-GCM' => sodium_crypto_aead_aes256gcm_decrypt($encrypted, '', $nounce, $key),
            'ChaCha20-Poly1305' => sodium_crypto_aead_chacha20poly1305_decrypt($encrypted, '', $nounce, $key),
            'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_decrypt($encrypted, '', $nounce, $key),
            'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($encrypted, '', $nounce, $key),
        };

        if ($decrypted === false) {
            /**
             * @psalm-suppress PossiblyFalseOperand `openssl_decrypt()` is returned `false`, so `openssl_error_string()`
             * always returns string.
             */
            throw new RuntimeException('Sodium failure on decryption');
        }

        return $decrypted;
    }
}
