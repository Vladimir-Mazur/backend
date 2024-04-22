<!DOCTYPE html>
  <html lang="ru">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <link rel="stylesheet" href="libs/bootstrap-4.0.0-dist/css/bootstrap.min.css">
      <link rel="stylesheet" href="style.css">
      <script src="libs/jquery-3.4.1.min.js"></script>
      <title>Задание 8</title>
  </head>
  <body>
<?php
  header('Content-Type: text/html; charset=UTF-8');

  if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    if (!empty($_GET['save'])) {
      print('<div class="message">Спасибо, данные сохранены.</div>');
    }
    include('form.php');
    exit();
  }

  function errp($error){
    print("<div class='messageError'>$error</div>");
    exit();
  }

  function val_empty($val, $name, $o = 0){
    if(empty($val)){
      if($o == 0){
        errp("Заполните поле $name.<br/>");
      }
      if($o == 1){
        errp("Выберите $name.<br/>");
      }
      if($o == 2){
        errp("ознакомьтесь с контрактом<br/>");
      }
      exit();
    }
  }

  $errors = '';
  $fio = (isset($_POST['fio']) ? $_POST['fio'] : '');
  $phone = (isset($_POST['phone']) ? $_POST['phone'] : '');
  $email = (isset($_POST['email']) ? $_POST['email'] : '');
  $birthday = (isset($_POST['birthday']) ? strtotime($_POST['birthday']) : '');
  $gender = (isset($_POST['gender']) ? $_POST['gender'] : '');
  $like_lang = (isset($_POST['like_lang']) ? $_POST['like_lang'] : '');
  $biography = (isset($_POST['biography']) ? $_POST['biography'] : '');
  $oznakomlen = (isset($_POST['oznakomlen']) ? $_POST['oznakomlen'] : '');

  $phone = preg_replace('/\D/', '', $phone);
  
  $like_lang_s = ($like_lang != '') ? implode(", ", $like_lang) : [];
  
  val_empty($fio, "имя");
  val_empty($phone, "телефон");
  val_empty($email, "email");
  val_empty($birthday, "дата");
  val_empty($gender, "пол", 1);
  val_empty($like_lang, "языки", 1);
  val_empty($biography, "биографию");
  val_empty($oznakomlen, "ознакомлен", 2);
  if(empty($fio)){
    print('пустое поле фио');
  }

  if(strlen($fio) > 255){
    $errors = 'Длина поля "ФИО" > 255 символов';
  }
  elseif(count(explode(" ", $fio)) < 2){
    $errors = 'Неверный формат ФИО';
  } 
  elseif(strlen($phone) != 11){
    $errors = 'Неверное значение поля "Телефон"';
  }
  elseif(strlen($email) > 255){
    $errors = 'Длина поля "email" > 255 символов';
  }
  elseif(!preg_match('/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/', $email)){
    $errors = 'Неверное значение поля "email"';
  }
  elseif(!is_numeric($birthday) || strtotime("now") < $birthday){
    $errors = 'Укажите корректно дату';
  }
  elseif($gender != "male" && $gender != "female"){
    $errors = 'Укажите пол';
  }
  elseif(count($like_lang) == 0){
    $errors = 'Укажите языки';
  }

  if ($errors != '') {
    errp($errors);
  }

  $db = new PDO('mysql:host=localhost;dbname=u67402', 'u67402', '2593797',
     [PDO::ATTR_PERSISTENT => true, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
  
  $inQuery = implode(',', array_fill(0, count($like_lang), '?'));
  
  try {
    $dbLangs = $db->prepare("SELECT id, name FROM languages WHERE name IN ($inQuery)");
    foreach ($like_lang as $key => $value) {
      $dbLangs->bindValue(($key+1), $value);
    }
    $dbLangs->execute();
    $languages = $dbLangs->fetchAll(PDO::FETCH_ASSOC);
  }
  catch(PDOException $e){
    print('Error : ' . $e->getMessage());
    exit();
  }

  echo $dbLangs->rowCount().'**'.count($like_lang);
  
  if($dbLangs->rowCount() != count($like_lang)){
    $errors = 'Неверно выбраны языки';
  }
  elseif(strlen($biography) > 65535){
    $errors = 'Длина поля "Биография" > 65 535 символов';
  }

  if ($errors != '') {
    errp($errors);
  }

  try {
    $stmt = $db->prepare("INSERT INTO form_data (fio, phone, email, birthday, gender, biography) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$fio, $phone, $email, $birthday, $gender, $biography]);
    $fid = $db->lastInsertId();
    $stmt1 = $db->prepare("INSERT INTO form_data_lang (id_form, id_lang) VALUES (?, ?)");
    foreach($languages as $row){
        $stmt1->execute([$fid, $row['id']]);
    }
  }
  catch(PDOException $e){
    print('Error : ' . $e->getMessage());
    exit();
  }
  header('Location: ?save=1');
