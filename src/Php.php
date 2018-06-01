<?php

/**
 * PHP version 7
 *
 * Crypt_Blowfish allows for encryption and decryption on the fly using
 * the Blowfish algorithm. Crypt_Blowfish does not require the mcrypt
 * PHP extension, but uses it if available, otherwise it uses only PHP.
 * Crypt_Blowfish support encryption/decryption with or without a secret key.
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
class Php extends Blowfish
{
    /**
     * P-Array contains 18 32-bit subkeys.
     *
     * @var array
     */
    protected $_P = [];

    /**
     * Array of four S-Blocks each containing 256 32-bit entries.
     *
     * @var array
     */
    protected $_S = [];

    /**
     * Whether the IV is required.
     *
     * @var bool
     */
    protected $_iv_required = false;

    /**
     * Hash value of last used key.
     *
     * @var string
     */
    protected $_keyHash = null;

    /**
     * @return void
     */
    protected function _init()
    {
        $defaults = new Key();
        $this->_P = $defaults->P;
        $this->_S = $defaults->S;
    }

    /**
     * Workaround for XOR on certain systems.
     *
     * @param  int|float $l
     * @param  int|float $r
     * @return float
     */
    protected function _binxor($l, $r)
    {
        $x = (($l < 0) ? (float) ($l + 4294967296) : (float) $l) ^ (($r < 0) ? (float) ($r + 4294967296) : (float) $r);

        return (float) (($x < 0) ? $x + 4294967296 : $x);
    }

    /**
     * Enciphers a single 64-bit block.
     *
     * @param  int &$Xl
     * @param  int &$Xr
     * @return void
     */
    protected function _encipher(int &$Xl, int &$Xr)
    {
        if ($Xl < 0) {
            $Xl += 4294967296;
        }

        if ($Xr < 0) {
            $Xr += 4294967296;
        }

        for ($i = 0; $i < 16; $i++) {
            $temp = $Xl ^ $this->_P[$i];

            if ($temp < 0) {
                $temp += 4294967296;
            }

            $Xl = fmod((fmod($this->_S[0][($temp >> 24) & 255]
                      + $this->_S[1][($temp >> 16) & 255], 4294967296)
                      ^ $this->_S[2][($temp >> 8) & 255])
                      + $this->_S[3][$temp & 255], 4294967296) ^ $Xr;
            $Xr = $temp;
        }

        $Xr = $this->_binxor($Xl, $this->_P[16]);
        $Xl = $this->_binxor($temp, $this->_P[17]);
    }

    /**
     * Deciphers a single 64-bit block.
     *
     * @param int &$Xl
     * @param int &$Xr
     */
    protected function _decipher(int &$Xl, int &$Xr)
    {
        if ($Xl < 0) {
            $Xl += 4294967296;
        }

        if ($Xr < 0) {
            $Xr += 4294967296;
        }

        for ($i = 17; $i > 1; $i--) {
            $temp = $Xl ^ $this->_P[$i];

            if ($temp < 0) {
                $temp += 4294967296;
            }

            $Xl = fmod((fmod($this->_S[0][($temp >> 24) & 255]
                      + $this->_S[1][($temp >> 16) & 255], 4294967296)
                      ^ $this->_S[2][($temp >> 8) & 255])
                      + $this->_S[3][$temp & 255], 4294967296) ^ $Xr;
            $Xr = $temp;
        }

        $Xr = $this->_binxor($Xl, $this->_P[1]);
        $Xl = $this->_binxor($temp, $this->_P[0]);
    }

    /**
     * Crypt_Blowfish_PHP Constructor.
     *
     * Initializes the Crypt_Blowfish object, and sets
     * the secret key.
     *
     * @param string|null $key
     * @param string|null $iv
     */
    public function __construct(string $key = null, string $iv = null)
    {
        $this->_iv = $iv . ((strlen($iv) < $this->_iv_size) ? str_repeat(chr(0), $this->_iv_size - strlen($iv)) : '');

        if (! is_null($key)) {
            $this->setKey($key, $this->_iv);
        }
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
     * @param  string      $key
     * @param  string|null $iv
     * @return bool|PEAR_Error
     */
    public function setKey(string $key, string $iv = null)
    {
        if (! is_string($key)) {
            return PEAR::raiseError('Key must be a string', 2);
        }

        $len = strlen($key);

        if ($len > $this->_key_size || $len == 0) {
            return PEAR::raiseError('Key must be less than ' . $this->_key_size . ' characters (bytes) and non-zero. Supplied key length: ' . $len, 3);
        }

        if ($this->_iv_required) {
            if (strlen($iv) != $this->_iv_size) {
                return PEAR::raiseError('IV must be ' . $this->_iv_size . '-character (byte) long. Supplied IV length: ' . strlen($iv), 7);
            }

            $this->_iv = $iv;
        }

        if ($this->_keyHash == md5($key)) {
            return true;
        }

        $this->_init();

        $k = 0;
        $data = 0;
        $datal = 0;
        $datar = 0;

        for ($i = 0; $i < 18; $i++) {
            $data = 0;

            for ($j = 4; $j > 0; $j--) {
                $data = $data << 8 | ord($key{$k});
                $k = ($k+1) % $len;
            }

            $this->_P[$i] ^= $data;
        }

        for ($i = 0; $i <= 16; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_P[$i] = $datal;
            $this->_P[$i+1] = $datar;
        }

        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[0][$i] = $datal;
            $this->_S[0][$i+1] = $datar;
        }

        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[1][$i] = $datal;
            $this->_S[1][$i+1] = $datar;
        }

        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[2][$i] = $datal;
            $this->_S[2][$i+1] = $datar;
        }

        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[3][$i] = $datal;
            $this->_S[3][$i+1] = $datar;
        }

        $this->_keyHash = md5($key);

        return true;
    }
}
