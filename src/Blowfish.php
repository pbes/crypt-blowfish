<?php

/**
 * PHP version 7
 *
 * Crypt_Blowfish allows for encryption and decryption on the fly using
 * the Blowfish algorithm. Crypt_Blowfish does not require the MCrypt
 * PHP extension, but uses it if available, otherwise it uses only PHP.
 * Crypt_Blowfish supports encryption/decryption with or without a secret key.
 */

namespace Crypt;

use PEAR;
use PEAR_Error;

define('CRYPT_BLOWFISH_AUTO', 1);
define('CRYPT_BLOWFISH_MCRYPT', 2);
define('CRYPT_BLOWFISH_PHP', 3);

/**
 * @author    Matthew Fonda <mfonda@php.net>
 * @author    Philippe Jausions <jausions@php.net>
 * @copyright 2005-2008 Matthew Fonda
 * @license   http://www.opensource.net/licenses/bsd-license.php New BSD
 * @link      http://pear.php.net/package/Crypt_Blowfish
 */
class Blowfish
{
    /**
     * Implementation-specific Blowfish object.
     *
     * @var object
     */
    protected $_crypt = null;

    /**
     * Initialization vector.
     *
     * @var string
     */
    protected $_iv = null;

    /**
     * Holds block size.
     *
     * @var int
     */
    protected $_block_size = 8;

    /**
     * Holds IV size.
     *
     * @var int
     */
    protected $_iv_size = 8;

    /**
     * Holds max key size.
     *
     * @var int
     */
    protected $_key_size = 56;

    /**
     * Deprecated init method - init is now a private
     * method and has been replaced with _init.
     *
     * @return bool
     */
    protected function init()
    {
        return $this->_crypt->init();
    }

    /**
     * Initializes the Blowfish object, and sets the secret key.
     *
     * @param  string $mode
     * @param  string $key
     * @return void
     */
    public function __construct(string $mode, string $key)
    {
        $this->_crypt =& self::factory($mode, $key);

        if (! PEAR::isError($this->_crypt)) {
            $this->_crypt->setKey($key);
        }
    }

    /**
     * Blowfish object factory.
     *
     * This is the recommended method to create a Blowfish instance.
     *
     * When using BLOWFISH_AUTO, you can force the package to ignore
     * the MCrypt extension, by defining CRYPT_BLOWFISH_NOMCRYPT.
     *
     * @param  string      $mode
     * @param  string|null $key
     * @param  string|null $iv
     * @param  int         $engine
     * @return object
     */
    public static function &factory(string $mode = 'ecb', string $key = null, string $iv = null, int $engine = CRYPT_BLOWFISH_AUTO)
    {
        switch ($engine) {
            case CRYPT_BLOWFISH_AUTO:
                if (! defined('CRYPT_BLOWFISH_NOMCRYPT') && extension_loaded('mcrypt')) {
                    $engine = CRYPT_BLOWFISH_MCRYPT;
                    break;
                }

                $engine = CRYPT_BLOWFISH_PHP;
                break;

            case CRYPT_BLOWFISH_MCRYPT:
                if (! PEAR::loadExtension('mcrypt')) {
                    return PEAR::raiseError('MCrypt extension is not available.');
                }

                break;
        }

        switch ($engine) {
            case CRYPT_BLOWFISH_PHP:
                $class = 'Crypt\\' . ucfirst($mode);
                $crypt = new $class(null);
                break;

            case CRYPT_BLOWFISH_MCRYPT:
                $crypt = new Mcrypt(null, $mode);
                break;
        }

        if (! is_null($key) || ! is_null($iv)) {
            $result = $crypt->setKey($key, $iv);
            if (PEAR::isError($result)) {
                return $result;
            }
        }

        return $crypt;
    }

    /**
     * Returns the algorithm's block size.
     *
     * @return int
     */
    public function getBlockSize()
    {
        return $this->_block_size;
    }

    /**
     * Returns the algorithm's IV size.
     *
     * @return int
     */
    public function getIVSize()
    {
        return $this->_iv_size;
    }

    /**
     * Returns the algorithm's maximum key size.
     *
     * @return int
     */
    public function getMaxKeySize()
    {
        return $this->_key_size;
    }

    /**
     * Deprecated isReady method
     *
     * @return bool
     */
    public function isReady()
    {
        return true;
    }

    /**
     * Encrypts a string
     *
     * Value is padded with NUL characters prior to encryption. You may
     * need to trim or cast the type when you decrypt.
     *
     * @param  string $plainText
     * @return string|PEAR_Error
     */
    public function encrypt(string $plainText)
    {
        return $this->_crypt->encrypt($plainText);
    }

    /**
     * Decrypts an encrypted string
     *
     * The value was padded with NUL characters when encrypted. You may
     * need to trim the result or cast its type.
     *
     * @param  string $cipherText
     * @return string|PEAR_Error
     */
    public function decrypt(string $cipherText)
    {
        return $this->_crypt->decrypt($cipherText);
    }

    /**
     * Sets the secret key
     * The key must be non-zero, and less than or equal to
     * 56 characters (bytes) in length.
     *
     * If you are making use of the PHP MCrypt extension, you must call this
     * method before each encrypt() and decrypt() call.
     *
     * @param  string $key
     * @return bool|PEAR_Error
     */
    public function setKey(string $key)
    {
        return $this->_crypt->setKey($key);
    }
}
