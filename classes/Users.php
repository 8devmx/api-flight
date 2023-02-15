<?php

namespace Classes;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use flight;

class Users
{
  private $db;

  function __construct()
  {
    Flight::register(
      'db',
      'PDO',
      array('mysql:host=' . $_ENV["DB_HOST"] . ';dbname=' . $_ENV['DB_NAME'], $_ENV['DB_USER'], '')
    );
    $this->db = Flight::db();
  }
  function auth()
  {
    $db = Flight::db();
    $password = Flight::request()->data->password;
    $email = Flight::request()->data->email;
    $query = $db->prepare("SELECT * FROM usuarios where correo = :email and password = :password");
    $array = [
      "error" => "No se pudo validar su identidad por favor, intente de nuevo",
      "status" => "error"
    ];
    $query->execute([":email" => $email, ":password" => $password]);

    if ($query->rowCount() === 0) {
      Flight::halt(403, json_encode([
        "error" => "Not allowed",
        "status" => "error"
      ]));
    }
    $user =  $query->fetch();
    $now = strtotime("now");
    $key = $_ENV['JWT_SECRET_KEY'];
    $payload = [
      'exp' => $now + 3600,
      'data' => $user['id']
    ];

    $jwt = JWT::encode($payload, $key, 'HS256');
    $array = ["token" => $jwt];

    Flight::json($array);
  }
  function selectAll($page)
  {
    if (!isset($page)) {
      $page =  1;
    }

    $query = $this->db->prepare("SELECT * FROM usuarios");
    $query->execute();
    $total = $query->rowCount();
    $total_per_page = 10;
    $pages =  ceil($total / $total_per_page);
    if ($total < 1) {
      Flight::halt(204, json_encode([
        "error" => "No hay contenido para mostrar",
        "status" => "error"
      ]));
    }
    if ($page > $pages || $page < 1) {
      Flight::halt(400, json_encode([
        "error" => "Petición incorrecta",
        "status" => "error"
      ]));
    }
    $start_record = ($page - 1) * $total_per_page;
    $query2 = $this->db->prepare("SELECT * FROM usuarios LIMIT $start_record, $total_per_page");
    $query2->execute();
    $data = $query2->fetchAll();

    $array = [];
    foreach ($data as $row) {
      $array[] = [
        "id" => $row['id'],
        "name" => $row['nombre'],
        "email" => $row['correo'],
        "phone" => $row['telefono'],
        "status" => $row['status'],
        "rol" => $row['rol_id'],
      ];
    }


    Flight::json([
      "total_rows" => $total,
      "page" => $page,
      "total_pages" => $pages,
      "rows" => $array
    ]);
  }

  function selectOne($id)
  {
    $query = $this->db->prepare("SELECT * FROM usuarios WHERE id = :id");
    $query->execute([":id" => $id]);
    $data = $query->fetch();

    $array = [
      "id" => $data['id'],
      "name" => $data['nombre'],
      "email" => $data['correo'],
      "phone" => $data['telefono'],
      "status" => $data['status'],
      "rol" => $data['rol_id'],
    ];

    Flight::json($array);
  }
  function insert()
  {
    if (!$this->validateToken()) {
      Flight::halt(403, json_encode([
        "error" => 'Unauthorized',
        "status" => 'error'
      ]));
    }
    $db = Flight::db();
    $name = Flight::request()->data->name;
    $phone = Flight::request()->data->phone;
    $password = Flight::request()->data->password;
    $email = Flight::request()->data->email;

    $query = $db->prepare("INSERT INTO usuarios (correo, password, telefono, nombre) VALUES (:email, :password,:phone, :name)");


    $array = [
      "error" => "Hubo un error al agregar los regitros, por favor intenta más tarde",
      "status" => "error"
    ];

    if ($query->execute([":email" => $email, ":password" => $password, ":phone" => $phone, ":name" => $name])) {
      $array = [
        "data" => [

          "id" => $db->lastInsertId(),
          "name" => $name,
          "password" => $password,
          "email" => $email,
          "phone" => $phone,
        ],
        "status" => "success"
      ];
    }

    Flight::json($array);
  }
  function update()
  {
    if (!$this->validateToken()) {
      Flight::halt(403, json_encode([
        "error" => 'Unauthorized',
        "status" => 'error'
      ]));
    }
    $db = Flight::db();
    $id = Flight::request()->data->id;
    $name = Flight::request()->data->name;
    $phone = Flight::request()->data->phone;
    $password = Flight::request()->data->password;
    $email = Flight::request()->data->email;

    $query = $db->prepare("UPDATE usuarios SET correo = :email, password = :password, telefono = :phone, nombre = :name WHERE id = :id");


    $array = [
      "error" => "Hubo un error al agregar los regitros, por favor intenta más tarde",
      "status" => "error"
    ];

    if ($query->execute([":email" => $email, ":password" => $password, ":phone" => $phone, ":name" => $name, ":id" => $id])) {
      $array = [
        "data" => [

          "id" => $id,
          "name" => $name,
          "password" => $password,
          "email" => $email,
          "phone" => $phone,
        ],
        "status" => "success"
      ];
    }

    Flight::json($array);
  }
  function delete()
  {
    if (!$this->validateToken()) {
      Flight::halt(403, json_encode([
        "error" => 'Unauthorized',
        "status" => 'error'
      ]));
    }
    $db = Flight::db();
    $id = Flight::request()->data->id;

    $query = $db->prepare("DELETE from usuarios WHERE id = :id");


    $array = [
      "error" => "Hubo un error al agregar los regitros, por favor intenta más tarde",
      "status" => "error"
    ];

    if ($query->execute([":id" => $id])) {
      $array = [
        "data" => [
          "id" => $id
        ],
        "status" => "success"
      ];
    }

    Flight::json($array);
  }
  function getToken()
  {
    $headers = apache_request_headers();
    if (!isset($headers["Authorization"])) {
      Flight::halt(403, json_encode([
        "error" => 'Unauthenticated request',
        "status" => 'error'
      ]));
    }
    $authorization = $headers["Authorization"];
    $authorizationArray = explode(" ", $authorization);
    $token = $authorizationArray[1];
    $key = $_ENV['JWT_SECRET_KEY'];
    try {
      return JWT::decode($token, new Key($key, 'HS256'));
    } catch (\Throwable $th) {
      Flight::halt(403, json_encode([
        "error" => $th->getMessage(),
        "status" => 'error'
      ]));
    }
  }

  function validateToken()
  {
    $info = $this->getToken();
    $db = Flight::db();
    $query = $db->prepare("SELECT * FROM usuarios WHERE id = :id");
    $query->execute([":id" => $info->data]);
    $rows = $query->fetchColumn();
    return $rows;
  }
}
