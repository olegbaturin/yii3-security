<?php

declare(strict_types=1);

namespace Yiisoft\Security;

use SensitiveParameter;

final class Crypt
{
    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     */
    public function __construct(
        private readonly CryptProviderInterface $cryptProvider
    ) {
    }

    /**
     * Encrypts data using a password.
     *
     * Derives keys for encryption and authentication from the password using PBKDF2 and a random salt,
     * which is deliberately slow to protect against dictionary attacks. Use {@see encryptByKey()} to
     * encrypt fast using a cryptographic key rather than a password. Key derivation time is
     * determined by {@see $derivationIterations}}, which should be set as high as possible.
     *
     * The encrypted data includes a keyed message authentication code (MAC) so there is no need
     * to hash input or output data.
     *
     * > Note: Avoid encrypting with passwords wherever possible. Nothing can protect against
     * poor-quality or compromised passwords.
     *
     * @param string $data The data to encrypt.
     * @param string $password The password to use for encryption.
     *
     * @throws \RuntimeException On OpenSSL not loaded.
     * @throws \Exception On OpenSSL error.
     *
     * @return string The encrypted data as byte string.
     *
     * @see decryptByPassword()
     * @see encryptByKey()
     */
    public function encryptByPassword(
        string $data,
        #[SensitiveParameter]
        string $password
    ): string {
        return $this->cryptProvider->encrypt($data, true, $password, '');
    }

    /**
     * Encrypts data using a cryptographic key.
     *
     * Derives keys for encryption and authentication from the input key using HKDF and a random salt,
     * which is very fast relative to {@see encryptByPassword()}. The input key must be properly
     * random — use {@see random_bytes()} to generate keys.
     * The encrypted data includes a keyed message authentication code (MAC) so there is no need
     * to hash input or output data.
     *
     * @param string $data The data to encrypt.
     * @param string $inputKey The input to use for encryption and authentication.
     * @param string $info Context/application specific information, e.g. a user ID
     * See [RFC 5869 Section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2) for more details.
     *
     * @throws \RuntimeException On OpenSSL not loaded.
     * @throws \Exception On OpenSSL error.
     *
     * @return string The encrypted data as byte string.
     *
     * @see decryptByKey()
     * @see encryptByPassword()
     */
    public function encryptByKey(
        string $data,
        #[SensitiveParameter]
        string $inputKey,
        string $info = ''
    ): string {
        return $this->cryptProvider->encrypt($data, false, $inputKey, $info);
    }

    /**
     * Verifies and decrypts data encrypted with {@see encryptByPassword()}.
     *
     * @param string $data The encrypted data to decrypt.
     * @param string $password The password to use for decryption.
     *
     * @throws \RuntimeException On OpenSSL not loaded.
     * @throws \Exception On OpenSSL errors.
     * @throws AuthenticationException On authentication failure.
     *
     * @return string The decrypted data.
     *
     * @see encryptByPassword()
     */
    public function decryptByPassword(
        string $data,
        #[SensitiveParameter]
        string $password
    ): string {
        return $this->cryptProvider->decrypt($data, true, $password, '');
    }

    /**
     * Verifies and decrypts data encrypted with {@see encryptByKey()}.
     *
     * @param string $data The encrypted data to decrypt.
     * @param string $inputKey The input to use for encryption and authentication.
     * @param string $info Context/application specific information, e.g. a user ID
     * See [RFC 5869 Section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2) for more details.
     *
     * @throws \RuntimeException On OpenSSL not loaded.
     * @throws \Exception On OpenSSL errors.
     * @throws AuthenticationException On authentication failure.
     *
     * @return string The decrypted data.
     *
     * @see encryptByKey()
     */
    public function decryptByKey(
        string $data,
        #[SensitiveParameter]
        string $inputKey,
        string $info = ''
    ): string {
        return $this->cryptProvider->decrypt($data, false, $inputKey, $info);
    }
}
