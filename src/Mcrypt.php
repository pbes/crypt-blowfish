<?php

/**
 * PHP version 7
 *
 * MCrypt PHP extension wrapper for Crypt_Blowfish package.
 */

namespace Crypt;

use PEAR;
use PEAR_Error;

/**
 * @author    Matthew Fonda <mfonda@php.net>
 * @author    Philippe Jausions <jausions@php.net>
 * @copyright 2005-2008 Matthew Fonda
 * @license   http://www.opensource.net/licenses/bsd-license.php New BSD
 * @link      http://pear.php.net/package/Crypt_Blowfish
 */
class Mcrypt extends Blowfish
{
    /**
     * Mcrypt td resource.
     *
     * @var resource
     */
    protected $_td = null;

    /**
     * @param  string $key
     * @param  string $mode
     * @param  string $iv
     * @return void
     */
    public function __construct(string $key = null, string $mode = 'ecb', string $iv = null)
    {
        $this->_iv = $iv . ((strlen($iv) < 8) ? str_repeat(chr(0), 8 - strlen($iv)) : '');

        $this->_td = mcrypt_module_open(MCRYPT_BLOWFISH, '', $mode, '');

        if (is_null($iv)) {
            $this->_iv = mcrypt_create_iv(8, MCRYPT_RAND);
        }

        switch (strtolower($mode)) {
            case 'ecb':
                $this->_iv_required = false;
                break;

            case 'cbc':
                $this->_iv_required = true;
                break;

            default:
                $this->_iv_required = true;
        }

        $this->setKey($key, $this->_iv);
    }

    /**
     * Encrypts a string.
     *
     * Value is padded with NUL characters prior to encryption. You may
     * need to trim or cast the type when you decrypt.
     *
     * @param  string $plainText
     * @return string|PEAR_Error
     */
    public function encrypt(string $plainText)
    {
        if (! is_string($plainText)) {
            return PEAR::raiseError('Input must be a string', 0);
        }

        return mcrypt_generic($this->_td, $plainText);
    }

    /**
     * Decrypts an encrypted string.
     *
     * The value was padded with NUL characters when encrypted. You may
     * need to trim the result or cast its type.
     *
     * @param  string $cipherText
     * @return string|PEAR_Error
     */
    public function decrypt(string $cipherText)
    {
        if (! is_string($cipherText)) {
            return PEAR::raiseError('Cipher text must be a string', 1);
        }

        return mdecrypt_generic($this->_td, $cipherText);
    }

    /**
     * Sets the secret key.
     *
     * The key must be non-zero, and less than or equal to
     * 56 characters (bytes) in length.
     *
     * If you are making use of the PHP mcrypt extension, you must call this
     * method before each encrypt() and decrypt() call.
     *
     * @param  string $key
     * @param  string $iv
     * @return bool|PEAR_Error
     */
    public function setKey(string $key, string $iv = null)
    {
        static $keyHash = null;

        if (! is_string($key)) {
            return PEAR::raiseError('Key must be a string', 2);
        }

        $len = strlen($key);

        if ($len > 56 || $len == 0) {
            return PEAR::raiseError('Key must be less than 56 characters (bytes) and non-zero. Supplied key length: ' . $len, 3);
        }

        if ($this->_iv_required) {
            if (strlen($iv) != 8) {
                return PEAR::raiseError('IV must be 8-character (byte) long. Supplied IV length: ' . strlen($iv), 7);
            }

            $this->_iv = $iv;
        }

        if (mcrypt_generic_init($this->_td, $key, $this->_iv) < 0) {
            return PEAR::raiseError('Unknown PHP MCrypt library error', 4);
        }

        return true;
    }
}
