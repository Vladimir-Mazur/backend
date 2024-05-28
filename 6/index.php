<?php
  header('Content-Type: text/html; charset=UTF-8');
  session_start();
  if(strpos($_SERVER['REQUEST_URI'], 'index.php') === false){
    header('Location: index.php');
    exit();
  }

  $log = !empty($_SESSION['login']);
  $adminLog = !empty($_SERVER['PHP_AUTH_USER']);
  $uid = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : '';
  $getUid = isset($_GET['uid']) ? strip_tags($_GET['uid']) : '';

  if($adminLog){
    if(preg_match('/^[0-9]+$/', $getUid)){
      $uid = $getUid;
      $log = true;
    }
  }
  
  function del_cook($cook, $vals = 0){
    setcookie($cook.'_error', '', 100000);
    if($vals) setcookie($cook.'_value', '', 100000);
  }

  $db;
  function conn(){
    global $db;
    include('connection.php');
  }

  if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    if(($adminLog && !empty($getUid)) || !$adminLog){
      $cookAdmin = (!empty($_COOKIE['admin_value']) ? $_COOKIE['admin_value'] : '');
      if($cookAdmin == '1'){
        del_cook('fio', 1);
        del_cook('phone', 1);
        del_cook('email', 1);
        del_cook('birthday', 1);
        del_cook('gender', 1);
        del_cook('like_lang', 1);
        del_cook('biography', 1);
        del_cook('oznakomlen', 1);
        del_cook('admin', 1);
      }
    }

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
    $error = true;
    
    function setVal($enName, $param){
      global $values;
      $values[$enName] = empty($param) ? '' : strip_tags($param);
    }

    function val_empty($enName, $val){
      global $errors, $messages, $error, $values;
      if($error) 
        $error = empty($_COOKIE[$enName.'_error']);

      $errors[$enName] = !empty($_COOKIE[$enName.'_error']);
      $messages[$enName] = "<div class='messageError'>$val</div>";
      $values[$enName] = empty($_COOKIE[$enName.'_value']) ? '' : strip_tags($_COOKIE[$enName.'_value']);
      del_cook($enName);
      return;
    }

    if (!empty($_COOKIE['save'])) {
      setcookie('save', '', 100000);
      setcookie('login', '', 100000);
      setcookie('password', '', 100000);
      $messages['success'] = 'Спасибо, результаты сохранены.';
      if (!empty($_COOKIE['password'])) {
        $messages['info'] = sprintf('Вы можете <a href="login.php">войти</a> с логином <strong>%s</strong>
          и паролем <strong>%s</strong> для изменения данных.',
          strip_tags($_COOKIE['login']),
          strip_tags($_COOKIE['password']));
      }
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
    
    if ($error && $log) {

      conn();
      try {
        $dbFD = $db->prepare("SELECT * FROM form_data WHERE user_id = ?");
        $dbFD->execute([$uid]);
        $fet = $dbFD->fetchAll(PDO::FETCH_ASSOC)[0];
        $form_id = $fet['id'];
        $_SESSION['form_id'] = $form_id;
        $dbL = $db->prepare("SELECT l.name FROM form_data_lang f
                              LEFT JOIN languages l ON l.id = f.id_lang
                              WHERE f.id_form = ?");
        $dbL->execute([$form_id]);
        $like_langsa = [];
        foreach($dbL->fetchAll(PDO::FETCH_ASSOC) as $item){
          $like_langsa[] = $item['name'];
        }
        setVal('fio', $fet['fio']);
        setVal('phone', $fet['phone']);
        setVal('email', $fet['email']);
        setVal('birthday', date("Y-m-d", $fet['birthday']));
        setVal('gender', $fet['gender']);
        setVal('like_lang', $like_lang);
        setVal('biography', $fet['biography']);
        setVal('oznakomlen', $fet['oznakomlen']);
      }
      catch(PDOException $e){
        print('Error : ' . $e->getMessage());
        exit();
      }
    }
    
    include('form.php');
  }
  else {
    $fio = (!empty($_POST['fio']) ? $_POST['fio'] : '');
    $phone = (!empty($_POST['phone']) ? $_POST['phone'] : '');
    $email = (!empty($_POST['email']) ? $_POST['email'] : '');
    $birthday = (!empty($_POST['birthday']) ? $_POST['birthday'] : '');
    $gender = (!empty($_POST['gender']) ? $_POST['gender'] : '');
    $like_lang = (!empty($_POST['like_lang']) ? $_POST['like_lang'] : '');
    $biography = (!empty($_POST['biography']) ? $_POST['biography'] : '');
    $oznakomlen = (!empty($_POST['oznakomlen']) ? $_POST['oznakomlen'] : '');

    if(isset($_POST['logout_form'])){
      if($adminLog && empty($_SESSION['login'])){
        header('Location: admin.php');
      }
      else{
        del_cook('fio', 1);
        del_cook('phone', 1);
        del_cook('email', 1);
        del_cook('birthday', 1);
        del_cook('gender', 1);
        del_cook('like_lang', 1);
        del_cook('biography', 1);
        del_cook('oznakomlen', 1);
        session_destroy();
        header('Location: index.php'.(($getUid != NULL) ? '?uid='.$uid : ''));
      }
      exit();
    }

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
      header('Location: index.php'.(($getUid != NULL) ? '?uid='.$uid : ''));
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
    if ($log) {
      $stmt = $db->prepare("UPDATE form_data SET fio = ?, phone = ?, email = ?, birthday = ?, gender = ?, biography = ? WHERE user_id = ?");
      $stmt->execute([$fio, $phone, $email, strtotime($birthday), $gender, $biography, $uid]);

      $stmt = $db->prepare("DELETE FROM form_data_lang WHERE id_form = ?");
      $stmt->execute([$_SESSION['form_id']]);

      $stmt1 = $db->prepare("INSERT INTO form_data_lang (id_form, id_lang) VALUES (?, ?)");
      foreach($languages as $row){
          $stmt1->execute([$_SESSION['form_id'], $row['id']]);
      }
      if($adminLog) 
        setcookie('admin_value', '1', time() + 30 * 24 * 60 * 60);
    }
    else {
      $login = substr(uniqid(), 0, 4).rand(10, 100);
      $password = rand(100, 1000).substr(uniqid(), 4, 10);
      setcookie('login', $login);
      setcookie('password', $password);
      $mpassword = md5($password);
      try {
        $stmt = $db->prepare("INSERT INTO users (login, password) VALUES (?, ?)");
        $stmt->execute([$login, $mpassword]);
        $user_id = $db->lastInsertId();

        $stmt = $db->prepare("INSERT INTO form_data (user_id, fio, phone, email, birthday, gender, biography) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$user_id, $fio, $phone, $email, strtotime($birthday), $gender, $biography]);
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
    }
    setcookie('save', '1');
    header('Location: index.php'.(($getUid != NULL) ? '?uid='.$uid : ''));
  }
?>