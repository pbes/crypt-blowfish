<?php

/**
 * PHP version 7
 *
 * PHP implementation of the Blowfish algorithm in ECB mode.
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
class Ecb extends Php
{
    /**
     * Blowfish Constructor.
     *
     * Initializes the Crypt_Blowfish object, and sets the secret key.
     *
     * @param  string|null $key
     * @param  string|null $iv
     * @return void
     */
    public function __construct(string $key = null, string $iv = null)
    {
        $this->_iv_required = false;

        parent::__construct($key, $iv);
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

        if (empty($this->_P)) {
            return PEAR::raiseError('The key is not initialized.', 8);
        }

        $cipherText = '';
        $len = strlen($plainText);
        $plainText .= str_repeat(chr(0), (8 - ($len % 8)) % 8);

        for ($i = 0; $i < $len; $i += 8) {
            list(, $Xl, $Xr) = unpack('N2', substr($plainText, $i, 8));
            $this->_encipher($Xl, $Xr);
            $cipherText .= pack('N2', $Xl, $Xr);
        }

        return $cipherText;
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

        if (empty($this->_P)) {
            return PEAR::raiseError('The key is not initialized.', 8);
        }

        $plainText = '';
        $len = strlen($cipherText);
        $cipherText .= str_repeat(chr(0), (8 - ($len % 8)) % 8);

        for ($i = 0; $i < $len; $i += 8) {
            list(, $Xl, $Xr) = unpack('N2', substr($cipherText, $i, 8));
            $this->_decipher($Xl, $Xr);
            $plainText .= pack('N2', $Xl, $Xr);
        }

        return $plainText;
    }
}
