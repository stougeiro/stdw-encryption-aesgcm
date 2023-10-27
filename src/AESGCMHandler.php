<?php declare(strict_types=1);

    namespace STDW\Encryption\AESGCM;

    use STDW\Contract\EncryptionHandlerInterface;
    use STDW\Encryption\AESGCM\Exception\EncryptionCipherNotFoundException;


    class AESGCMHandler implements EncryptionHandlerInterface
    {
        protected $supported_ciphers = [
            'aes-128-gcm',
            'aes-192-gcm',
            'aes-256-gcm',
        ];

        protected string $key;

        protected string $cipher;


        public function __construct(string $key, string $cipher = 'aes-128-gcm')
        {
            $this->setKey($key);

            $this->cipher = $cipher;

            if ( ! in_array($cipher, $this->supported_ciphers)) {
                $ciphers = implode(', ', array_values($this->supported_ciphers));

                throw new EncryptionCipherNotFoundException("Unsupported cipher. Supported ciphers are: {$ciphers}.");
            }
        }


        public function encrypt(mixed $value): string
        {
            $ivlen = openssl_cipher_iv_length($this->cipher);
            $iv = openssl_random_pseudo_bytes($ivlen);
            $value = openssl_encrypt($value, $this->cipher, $this->key, 0, $iv, $tag);

            return base64_encode($value) .'.'. base64_encode($iv).'.'. base64_encode($tag);
        }

        public function decrypt(string $payload): mixed
        {
            $encrypted = explode('.', $payload);

            if (count($encrypted) != 3) {
                return '';
            }


            list($value, $iv, $tag) = $encrypted;

            $value = base64_decode($value);
            $iv = base64_decode($iv);
            $tag = base64_decode($tag);

            return openssl_decrypt($value, $this->cipher, $this->key, 0, $iv, $tag);
        }

        public function setKey(string $key): void
        {
            $this->key = $key;
        }
    }