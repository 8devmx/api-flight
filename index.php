<?php

require 'vendor/autoload.php';
$envPath = './';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();
$users = new Classes\Users;

Flight::route('GET /users', [$users, 'selectAll']);

Flight::route('GET /users/@id', [$users, 'selectOne']);

Flight::route('POST /auth', [$users, 'auth']);

Flight::route('POST /users', [$users, 'insert']);

Flight::route('PUT /users', [$users, 'update']);
Flight::route('DELETE /users', [$users, 'delete']);


Flight::start();
