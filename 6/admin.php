<?php

  require('connection.php');

  $haveAdmin = 0;
  if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])){
    $qu = $db->prepare("SELECT id FROM users WHERE role = 'admin' and login = ? and password = ?");
    $qu->execute([$_SERVER['PHP_AUTH_USER'], md5($_SERVER['PHP_AUTH_PW'])]);
    $haveAdmin = $qu->rowCount();
  }

  if (!$haveAdmin) {
    header('HTTP/1.1 401 Unanthorized');
    header('WWW-Authenticate: Basic realm="My site"');
    print('<h1>401 Требуется авторизация</h1>');
    
    exit();
  }
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="libs/bootstrap-4.0.0-dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="./style2.css">
    <script src="./libs/js/jquery-3.4.1.min.js"></script>
    <title>Задание 6 (админка)</title>
</head>
<body class="admin">

  <header>
    <div><a href="#data">Информация</a></div>
    <div><a href="#analize">Статистика</a></div>
</header>

  <table id="data">
    <thead>
      <tr>
        <th>id</th>
        <th>ФИО</th>
        <th>Телефон</th>
        <th>Почта</th>
        <th>День рождения</th>
        <th>Пол</th>
        <th>Биография</th>
        <th>ЯП</th>
        <th></th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      <?php
        $dbFD = $db->query("SELECT * FROM form_data ORDER BY id DESC");
        while($row = $dbFD->fetch(PDO::FETCH_ASSOC)){
          echo '<tr data-id='.$row['id'].'>
                  <td>'.$row['id'].'</td>
                  <td>'.$row['fio'].'</td>
                  <td>'.$row['phone'].'</td>
                  <td>'.$row['email'].'</td>
                  <td>'.date("d.m.Y", $row['birthday']).'</td>
                  <td>'.(($row['gender'] == "male") ? "Мужской" : "Женский").'</td>
                  <td class="wb">'.$row['biography'].'</td>
                  <td>';
          $dbl = $db->prepare("SELECT * FROM form_data_lang fd
                                LEFT JOIN languages l ON l.id = fd.id_lang
                                WHERE id_form = ?");
          $dbl->execute([$row['id']]);
          while($row1 = $dbl->fetch(PDO::FETCH_ASSOC)){
            echo $row1['name'].'<br>';
          }
          echo '</td>
                <td><a href="./index.php?uid='.$row['user_id'].'" target="_blank">Редактировать</a></td>
                <td><button class="remove">Удалить</button></td>
                <td colspan="10" class="form_del hid">Форма удалена</td>
              </tr>';
        }
      ?>


    </tbody>
  </table>

  <table class="analize" id="analize">
    <thead>
      <tr>
        <th>ЯП</th>
        <th>Кол-во пользователей</th>
      </tr>
    </thead>
    <tbody>
      <?php
        $qu = $db->query("SELECT l.id, l.name, COUNT(id_form) as count FROM languages l 
                            LEFT JOIN form_data_lang fd ON fd.id_lang = l.id
                            GROUP by l.id");
        while($row = $qu->fetch(PDO::FETCH_ASSOC)){
          echo '<tr>
                  <td>'.$row['name'].'</td>
                  <td>'.$row['count'].'</td>
                </tr>';
        }
      ?>
    </tbody>
  </table>

  <script src="./core.js"></script>
</body>
</html>
