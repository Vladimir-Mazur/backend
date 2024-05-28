<?php
  header('Content-Type: text/html; charset=UTF-8');
  
  function del_cook($cook, $del_val = 0){
    setcookie($cook.'_error', '', time() - 30 * 24 * 60 * 60);
  }
  
  $db;

  function conn(){
    global $db;
    include('connection.php');
  }

  if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    $fio = (!empty($_COOKIE['fio_error']) ? $_COOKIE['fio_error'] : '');
    $phone = (!empty($_COOKIE['phone_error']) ? $_COOKIE['phone_error'] : '');
    $email = (!empty($_COOKIE['email_error']) ? $_COOKIE['email_error'] : '');
    $birthday = (!empty($_COOKIE['birthday_error']) ? $_COOKIE['birthday_error'] : '');
    $gender = (!empty($_COOKIE['gender_error']) ? $_COOKIE['gender_error'] : '');
    $like_lang = (!empty($_COOKIE['like_lang_error']) ? $_COOKIE['like_lang_error'] : '');
    $biography = (!empty($_COOKIE['biography_error']) ? $_COOKIE['biography_error'] : '');
    $oznakomlen = (!empty($_COOKIE['oznakomlen_error']) ? $_COOKIE['oznakomlen_error'] : '');

    $errors = array();
    $messages = array();
    $values = array();
    
    function val_empty($enName, $val){
      global $errors, $values, $messages;

      $errors[$enName] = !empty($_COOKIE[$enName.'_error']);
      $messages[$enName] = "<div class='messageError'>$val</div>";
      $values[$enName] = empty($_COOKIE[$enName.'_value']) ? '' : $_COOKIE[$enName.'_value'];
      del_cook($enName);
      return;
    }
    
    if (!empty($_COOKIE['save'])) {
      setcookie('save', '', 100000);
      $messages['success'] = '<div class="message">Спасибо, данные сохранены.</div>';
    }
       
    val_empty('fio', $fio);
    val_empty('phone', $phone);
    val_empty('email', $email);
    val_empty('birthday', $birthday);
    val_empty('gender', $gender);
    val_empty('like_lang', $like_lang);
    val_empty('biography', $biography);
    val_empty('oznakomlen', $oznakomlen);

    $like_langsa = explode(',', $values['like_lang']);

    include('form.php');
  }
  else{ //POST
    $fio = (!empty($_POST['fio']) ? $_POST['fio'] : '');
    $phone = (!empty($_POST['phone']) ? $_POST['phone'] : '');
    $email = (!empty($_POST['email']) ? $_POST['email'] : '');
    $birthday = (!empty($_POST['birthday']) ? $_POST['birthday'] : '');
    $gender = (!empty($_POST['gender']) ? $_POST['gender'] : '');
    $like_lang = (!empty($_POST['like_lang']) ? $_POST['like_lang'] : '');
    $biography = (!empty($_POST['biography']) ? $_POST['biography'] : '');
    $oznakomlen = (!empty($_POST['oznakomlen']) ? $_POST['oznakomlen'] : '');
    $error = false;

    $phone1 = preg_replace('/\D/', '', $phone);

    function val_empty($cook, $comment, $usl){
      global $error;
      $res = false;
      $setVal = $_POST[$cook];
      if ($usl) {
        setcookie($cook.'_error', $comment, time() + 24 * 60 * 60);
        $error = true;
        $res = true;
      }
      
      if($cook == 'like_lang'){
        global $like_lang;
        $setVal = ($like_lang != '') ? implode(",", $like_lang) : '';
      }
      
      setcookie($cook.'_value', $setVal, time() + 30 * 24 * 60 * 60);
      return $res;
    }
    
    if(!val_empty('fio', 'Заполните поле', empty($fio))){
      if(!val_empty('fio', 'Длина поля > 255 символов', strlen($fio) > 255)){
        val_empty('fio', 'Поле не соответствует требованиям: <i>Фамилия Имя (Отчество)</i>, кириллицей', !preg_match('/^([а-яёА-ЯЁ]+-?[а-яёА-ЯЁ]+)( [а-яёА-ЯЁ]+-?[а-яёА-ЯЁ]+){1,2}$/Diu', $fio));
      }
    }
    if(!val_empty('phone', 'Заполните поле', empty($phone))){
      if(!val_empty('phone', 'Длина поля некорректна', strlen($phone) != 11)){
        val_empty('phone', 'Поле должен содержать только цифры', ($phone != $phone1));
      }
    }
    if(!val_empty('email', 'Заполните поле', empty($email))){
      if(!val_empty('email', 'Длина поля > 255 символов', strlen($email) > 255)){
        val_empty('email', 'Поле не соответствует требованию example@mail.ru', !preg_match('/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/', $email));
      }
    }
    if(!val_empty('birthday', "Выберите дату рождения", empty($birthday))){
      val_empty('birthday', "Неверно введена дата рождения, дата больше настоящей", (strtotime("now") < strtotime($birthday)));
    }
    val_empty('gender', "Выберите пол", (empty($gender) || !preg_match('/^(male|female)$/', $gender)));
    if(!val_empty('like_lang', "Выберите хотя бы один язык", empty($like_lang))){
      conn();
      try {
        $inQuery = implode(',', array_fill(0, count($like_lang), '?'));
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
      
      val_empty('like_lang', 'Неверно выбраны языки', $dbLangs->rowCount() != count($like_lang));
    }
    if(!val_empty('biography', 'Заполните поле', empty($biography))){
      val_empty('biography', 'Длина текста > 65 535 символов', strlen($biography) > 65535);
    }
    val_empty('oznakomlen', "Ознакомьтесь с контрактом", empty($oznakomlen));
    
    if ($error) {
      header('Location: index.php');
      exit();
    }
    else {
      del_cook('fio');
      del_cook('phone');
      del_cook('email');
      del_cook('birthday');
      del_cook('gender');
      del_cook('like_lang');
      del_cook('biography');
      del_cook('oznakomlen');
    }
    
    try {
      $stmt = $db->prepare("INSERT INTO form_data (fio, phone, email, birthday, gender, biography) VALUES (?, ?, ?, ?, ?, ?)");
      $stmt->execute([$fio, $phone, $email, strtotime($birthday), $gender, $biography]);
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
    setcookie('fio_value', $fio, time() + 24 * 60 * 60 * 365);
    setcookie('phone_value', $phone, time() + 24 * 60 * 60 * 365);
    setcookie('email_value', $email, time() + 24 * 60 * 60 * 365);
    setcookie('birthday_value', $birthday, time() + 24 * 60 * 60 * 365);
    setcookie('gender_value', $gender, time() + 24 * 60 * 60 * 365);
    setcookie('like_value', $like, time() + 24 * 60 * 60 * 365);
    setcookie('biography_value', $biography, time() + 24 * 60 * 60 * 365);
    setcookie('oznakomlen_value', $oznakomlen, time() + 24 * 60 * 60 * 365);
    setcookie('save', '1');
    header('Location: index.php');
  }
?>