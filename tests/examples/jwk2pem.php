<?php

namespace Examples;

use Firebase\JWT\JWK;

require_once 'vendor/autoload.php';

define('Examples\DATA_DIR', dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data');

$alg = $argv[1] ?? null;
$item = $argv[2] ?? 0;

$set = json_decode(file_get_contents(DATA_DIR . DIRECTORY_SEPARATOR . 'ec-jwkset.json'), true);
$jwkKey = array_values(array_filter($set['keys'], static function ($value) use ($alg) {
    return $value['alg'] === $alg;
}))[$item] ?? null;

if (!$jwkKey) {
    throw new \Exception(sprintf('No key found for alg `%s`', $alg));
}

$key = JWK::parseKey($jwkKey);
echo $key->getKeyMaterial();
