<?php

namespace Examples;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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

if (!($privateKey = $jwkKey['files']['private'] ?? null) || !($privateContent = file_get_contents(DATA_DIR . DIRECTORY_SEPARATOR . $privateKey))) {
    throw new \Exception(sprintf('No private key found for alg `%s`', $alg));
}

if (!($publicKey = $jwkKey['files']['public'] ?? null) || !($publicContent = file_get_contents(DATA_DIR . DIRECTORY_SEPARATOR . $publicKey))) {
    throw new \Exception(sprintf('No public key found for alg `%s`', $alg));
}

$payload = ['foo' => 'bar'];

$jwt = JWT::encode($payload, $privateContent, $alg);
echo 'Encode:' . PHP_EOL . print_r($jwt, true) . PHP_EOL . PHP_EOL;

$decoded = JWT::decode($jwt, new Key($publicContent, $alg));
$decoded_array = (array)$decoded;
echo 'Decode:' . PHP_EOL . print_r($decoded_array, true) . PHP_EOL . PHP_EOL;
