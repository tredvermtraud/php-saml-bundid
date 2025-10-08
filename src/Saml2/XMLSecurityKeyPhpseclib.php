<?php
namespace Onelogin\Saml2\Crypto;

use Exception;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA; // contains constants like SIGNATURE_PSS

class XMLSecurityKeyPhpseclib
{
  public const string TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
  public const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
  public const string AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
  public const string AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
  public const string AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
  public const string AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';
  public const string AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
  public const string RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
  public const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
  public const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
  public const string DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
  public const string RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  public const string RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  public const string RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
  public const string RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
  public const string RSA_SHA256_MGF1 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
  public const string HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
  /** @var PublicKey|PrivateKey|null */
  public $key;

  /** algorithm, e.g. 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' */
  public $algorithm;

  /** options for PSS (if needed) */
  private $usePss = false;
  private $hashAlgo = 'sha256';
  private $mgfHashAlgo = 'sha256';
  private $saltLength = 32;

  public function __construct($algorithmUri = null, array $opts = [])
  {
    $this->algorithm = $algorithmUri;
    if(!empty($opts['pss'])) {
      $this->usePss = true;
      $this->hashAlgo = $opts['hash'] ?? 'sha256';
      $this->mgfHashAlgo = $opts['mgfHash'] ?? $this->hashAlgo;
      $this->saltLength = $opts['saltLength'] ?? (int)hash($this->hashAlgo, '') ? strlen(hash($this->hashAlgo, '', true)) : 32;
    }
  }

  /**
   * Load a key (private or public). PublicKeyLoader autodetects formats.
   * $isPrivate optional - if you want to force private loading.
   */
  public function loadKeyFromString(string $pem, bool $isPrivate = false)
  {
    // PublicKeyLoader::load will return PrivateKey if private key data supplied,
    // or PublicKey if public/cert supplied.
    $this->key = PublicKeyLoader::load($pem);
  }

  /**
   * Sign raw bytes (e.g. canonicalized SignedInfo).
   * Returns binary signature (not base64).
   */
  public function signData(string $data): string
  {
    if($this->key === null) {
      throw new \RuntimeException("No key loaded");
    }

    // ensure private key
    if(!method_exists($this->key, 'sign')) {
      throw new \RuntimeException("Loaded key cannot sign (not a private key)");
    }

    if(!($this->key instanceof PrivateKey)) {
      throw new \RuntimeException('Provided key is not a valid RSA private key');
    }

    // configure padding/hash for private key
    $key = $this->key
      ->withPadding(RSA::SIGNATURE_PKCS1)
      ->withHash($this->hashAlgo ?? 'sha1');

    if($this->usePss) {
      $key = $this->key
        ->withPadding(RSA::SIGNATURE_PSS)
        ->withHash($this->hashAlgo)
        ->withMGFHash($this->mgfHashAlgo)
        ->withSaltLength($this->saltLength);
    }

    return $key->sign($data);
  }

  /**
   * Verify signature for provided data.
   * $signature is binary. Returns bool.
   */
  public function verifySignature(string $data, string $signature): bool
  {
    if($this->key === null) {
      throw new \RuntimeException("No key loaded");
    }

    if($this->usePss) {
      $pub = $this->key
        ->withPadding(RSA::SIGNATURE_PSS)
        ->withHash($this->hashAlgo)
        ->withMGFHash($this->mgfHashAlgo)
        ->withSaltLength($this->saltLength);
    } else {
      $pub = $this->key
        ->withPadding(RSA::SIGNATURE_PKCS1)
        ->withHash($this->hashAlgo ?? 'sha1');
    }

    return $pub->verify($data, $signature);
  }

  /**
   * @return mixed
   */
  public function getAlgorithm()
  {
    return $this->algorithm;
  }

  /**
   * Generates a session key using the openssl-extension.
   * In case of using DES3-CBC the key is checked for a proper parity bits set.
   * @return string
   * @throws Exception
   */
  public function generateSessionKey()
  {
    if(!isset($this->saltLength)) {
      throw new Exception('Unknown key size for type "' . $this->algorithm . '".');
    }
    $keysize = $this->saltLength;

    $key = openssl_random_pseudo_bytes($keysize);

    if($this->algorithm === self::TRIPLEDES_CBC) {
      /* Make sure that the generated key has the proper parity bits set.
       * Mcrypt doesn't care about the parity bits, but others may care.
       */
      for($i = 0; $i < strlen($key); $i++) {
        $byte = ord($key[$i]) & 0xfe;
        $parity = 1;
        for($j = 1; $j < 8; $j++) {
          $parity ^= ($byte >> $j) & 1;
        }
        $byte |= $parity;
        $key[$i] = chr($byte);
      }
    }

    $this->key = $key;
    return $key;
  }
}
