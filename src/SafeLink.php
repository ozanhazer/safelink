<?php

namespace Alfatron\SafeLink;

class SafeLink
{
    const AES_256_CBC = 'aes-256-cbc';

    /**
     * @var string
     */
    protected $secretKey;

    /**
     * Initialization Vector
     *
     * @var string
     */
    protected $iv;

    /**
     * @var array
     */
    protected $options = [
        'timeout' => 10,  // in seconds
    ];

    /**
     * @param string|null $secretKey
     * @param array $options
     */
    public function __construct($secretKey = null, $options = [])
    {
        if (!is_null($secretKey)) {
            $this->setSecretKey($secretKey);
        }

        $this->setOptions($options);
    }

    /**
     * Encrypts the data and returns Base64 encoded string.
     *
     * @param mixed $data
     * @return string
     * @throws EncryptionException
     */
    public function encrypt($data)
    {
        $secretKey = $this->getSecretKey();
        $iv = $this->createGetIV();

        $data = serialize($data);

        $encryptedData = openssl_encrypt($data, self::AES_256_CBC, $secretKey, 0, $iv);

        if ($encryptedData === false) {
            throw new EncryptionException('An error occurred while encrypting the data.');
        }

        return $encryptedData;
    }

    /**
     * Decrypts the data.
     *
     * @param string $encryptedData
     * @param string $iv
     * @return string|boolean
     * @throws EncryptionException|VerificationException
     */
    public function decrypt($encryptedData, $iv)
    {
        $this->checkIVString($iv);
        $secretKey = $this->getSecretKey();

        $data = openssl_decrypt($encryptedData, self::AES_256_CBC, $secretKey, 0, $iv);

        if ($data === false) {
            throw new EncryptionException('An error occurred while encrypting the data.');
        }

        return unserialize($data);
    }

    /**
     * @param string $secretKey
     */
    public function setSecretKey($secretKey)
    {
        if (mb_strlen($secretKey) < 16) {
            throw new InvalidArgumentException('The secret key must be 16 characters at least.');
        }

        $this->secretKey = $secretKey;
    }

    /**
     * @return string
     */
    public function getSecretKey()
    {
        return $this->secretKey;
    }

    /**
     * @return string
     */
    public function createGetIV()
    {
        if (!$this->iv) {
            $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::AES_256_CBC));
        }
        return $this->iv;
    }

    /**
     * @return string
     */
    public function getIV()
    {
        return $this->iv;
    }

    /**
     * @param string $iv
     * @throws VerificationException
     */
    public function setIV($iv)
    {
        $this->checkIVString($iv);

        $this->iv = $iv;
    }

    /**
     * Signs the url and redirects to it. Execution is stopped after the redirection.
     *
     * @param string $link
     * @param mixed $data
     * @throws EncryptionException
     */
    public function redirect($link, $data)
    {
        header('HTTP/1.0 302', true, 302);
        header('Location: ' . $this->getRedirectionUrl($link, $data), true);
        exit;
    }

    /**
     * Signs the url. Any serializable data is accepted (e.g. object, array, integer)
     *
     * @param string $url
     * @param mixed $data
     *
     * @return string
     * @throws EncryptionException
     */
    public function getRedirectionUrl($url, $data)
    {
        if (!$data) {
            throw new InvalidArgumentException('Data cannot be empty');
        }

        $encryptedData = $this->encrypt([
            'data' => $data,
            'ts' => time(),
        ]);

        $payload = [
            's' => $encryptedData,
            'i' => $this->getIV(),
        ];

        return $url . '?' . http_build_query($payload);
    }

    /**
     * @return Response
     * @throws VerificationException
     */
    public function verify()
    {
        $iv = $_GET['i'] ?? null;
        $encryptedData = $_GET['s'] ?? null;

        try {
            $data = $this->decrypt($encryptedData, $iv);
        } catch (EncryptionException $e) {
            throw new VerificationException('Data could not be decrypted.');
        }

        if ($data === false) {
            throw new VerificationException('Data could not be unserialized.');
        }

        $response = new Response();
        $response->data = $data['data'];
        $response->timestamp = $data['ts'];

        if (time() - $response->timestamp > $this->getOption('timeout')) {
            throw new VerificationException('The link has expired.');
        }

        return $response;
    }

    /**
     * @param $iv string
     *
     * @throws VerificationException
     */
    private function checkIVString($iv)
    {
        $len = openssl_cipher_iv_length(self::AES_256_CBC);

        if (strlen($iv) != $len) {
            throw new VerificationException('Invalid IV length');
        }
    }

    /**
     * @param array $options
     */
    protected function setOptions($options)
    {
        foreach ($options as $key => $value) {
            $this->setOption($key, $value);
        }
    }

    /**
     * @param string $key
     * @return mixed
     */
    public function getOption($key)
    {
        return $this->options[$key];
    }

    /**
     * @param string $key
     * @param mixed $value
     */
    public function setOption($key, $value)
    {
        if (!array_key_exists($key, $this->options)) {
            throw new InvalidArgumentException('Invalid option: ' . $key);
        }

        $this->options[$key] = $value;
    }
}
