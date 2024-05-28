<?php
  header('Content-Type: text/html; charset=UTF-8');
  session_start();
  if (!empty($_SESSION['login'])) {
    header('Location: ./');
    exit();
  }


  $error = '';

  if ($_SERVER['REQUEST_METHOD'] == 'GET') {

  }
  else{
    require('connection.php');
    $login = $_POST['login'];
    $password = md5($_POST['password']);
    try {
      $stmt = $db->prepare("SELECT id FROM users WHERE login = ? and password = ?");
      $stmt->execute([$login, $password]);
      $its = $stmt->rowCount();
      if($its){
        $uid = $stmt->fetchAll(PDO::FETCH_ASSOC)[0]['id'];
        $_SESSION['login'] = $_POST['login'];
        $_SESSION['user_id'] = $uid;
        header('Location: ./');
      }
      else{
        $error = 'Неверный логин или пароль';
      }
    }
    catch(PDOException $e){
      print('Error : ' . $e->getMessage());
      exit();
    }
  }
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="libs/bootstrap-4.0.0-dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="style.css">
    <script src="libs/jquery-3.4.1.min.js"></script>
    <title>Задание 5</title>
</head>
<body>
  <div class="pform pformAuth">
    <form action="" method="post">
      <div class="message" style="color: red;"><?php echo $error; ?></div>
      <h3>Авторизация</h3>
        <div>
          <input class="w100" type="text" name="login" placeholder="Логин">
        </div>
        <div>
          <input class="w100" type="text" name="password" placeholder="Пароль">
        </div>
        <button type="submit">Войти</button>
    </form>
  </div>
</body>
</html>