# Crypt Blowfish

Fork of https://github.com/pear/Crypt_Blowfish and https://github.com/shimochi/Crypt_Blowfish

### Installation
```
$ composer require pbes/crypt-blowfish
```

### Usage
```php
<?php

require __DIR__ . '/../vendor/autoload.php';

$key = 'key';
$text = 'text';

$blowfish = \Crypt\Blowfish::factory('ecb', $key);
$encrypt = $blowfish->encrypt($text);
$decrypt = $blowfish->decrypt($encrypt);

```

### LICENSE
The Crypt Blowfish is open source software licensed under the BSD 2-Clause License.
