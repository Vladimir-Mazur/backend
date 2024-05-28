<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="libs/bootstrap-4.0.0-dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="style.css">
    <title>Задание 6</title>
</head>
<body>
<div class="pform">
    <form action="" method="post">
        <h3>Форма</h3>
        <?php 
            if($log) echo '<button type="submit" class="logout_form" name="logout_form">Выйти</button>'; 
            else echo '<a href="login.php" class="login_form" name="logout_form">Войти</a>';
        ?>
        <div class="message"><?php if(isset($messages['success'])) echo $messages['success']; ?></div>
        <div class="message message_info"><?php if(isset($messages['info'])) echo $messages['info']; ?></div>
        <div>
            <input class="w100 <?php echo ($errors['fio'] != NULL) ? 'borred' : ''; ?>" value="<?php echo $values['fio']; ?>" type="text" name="fio" placeholder="ФИО">
            <div class="errpodinp"><?php echo $messages['fio']?></div>
        </div>
        <div>
            <input class="w100 <?php echo ($errors['phone'] != NULL) ? 'borred' : ''; ?>" value="<?php echo $values['phone']; ?>" type="tel" name="phone" placeholder="Телефон">
            <div class="errpodinp"><?php echo $messages['phone']?></div>
        </div>
        <div>
            <input class="w100 <?php echo ($errors['email'] != NULL) ? 'borred' : ''; ?>" value="<?php echo $values['email']; ?>" type="email" name="email" placeholder="email">
            <div class="errpodinp"><?php echo $messages['email']?></div>
        </div>
        <div>
            <input class="w100 <?php echo ($errors['birthday'] != NULL) ? 'borred' : ''; ?>" value="<?php if(strtotime($values['birthday']) > 100000) echo $values['birthday']; ?>" type="date" name="birthday">
            <div class="errpodinp"><?php echo $messages['birthday']?></div>
        </div>
        <div class="ent">
            <div>Пол:</div>
            <label>
                <input type="radio" name="gender" value="male" <?php if($values['gender'] == 'male') echo 'checked'; ?>>
                <span class="<?php echo ($errors['gender'] != NULL) ? 'colred' : ''; ?>">Мужской</span>
            </label>
            <br>
            <label>
                <input type="radio" name="gender" value="female" <?php if($values['gender'] == 'female') echo 'checked'; ?>>
                <span class="<?php echo ($errors['gender'] != NULL) ? 'colred' : ''; ?>">Женский</span>
            </label>
            <div class="errpodinp"><?php echo $messages['gender']?></div>
        </div>
        <div class="ent">
            <select class="w100 <?php echo ($errors['like_lang'] != NULL) ? 'borred' : ''; ?>" name="like_lang[]" id="like_lang" multiple="multiple">
                <option disabled selected>Любимый язык программирования</option>
                <option value="Pascal" <?php echo (in_array('Pascal', $like_langsa)) ? 'selected' : ''; ?>>Pascal</option>
                <option value="C" <?php echo (in_array('C', $like_langsa)) ? 'selected' : ''; ?>>C</option>
                <option value="C++" <?php echo (in_array('C++', $like_langsa)) ? 'selected' : ''; ?>>C++</option>
                <option value="JavaScript" <?php echo (in_array('JavaScript', $like_langsa)) ? 'selected' : ''; ?>>JavaScript</option>
                <option value="PHP" <?php echo (in_array('PHP', $like_langsa)) ? 'selected' : ''; ?>>PHP</option>
                <option value="Python" <?php echo (in_array('Python', $like_langsa)) ? 'selected' : ''; ?>>Python</option>
                <option value="Java" <?php echo (in_array('Java', $like_langsa)) ? 'selected' : ''; ?>>Java</option>
                <option value="Haskel" <?php echo (in_array('Haskel', $like_langsa)) ? 'selected' : ''; ?>>Haskel</option>
                <option value="Clojure" <?php echo (in_array('Clojure', $like_langsa)) ? 'selected' : ''; ?>>Clojure</option>
                <option value="Prolog" <?php echo (in_array('Prolog', $like_langsa)) ? 'selected' : ''; ?>>Prolog</option>
                <option value="Scala" <?php echo (in_array('Scala', $like_langsa)) ? 'selected' : ''; ?>>Scala</option>
            </select>
            <div class="errpodinp"><?php echo $messages['like_lang']?></div>
        </div>
        <div>
            <textarea name="biography" placeholder="Биография" class="<?php echo ($errors['biography'] != NULL) ? 'borred' : ''; ?>"><?php echo $values['biography']; ?></textarea>
            <div class="errpodinp"><?php echo $messages['biography']?></div>
        </div>
        <div>
            <input type="checkbox" name="oznakomlen" id="oznakomlen" <?php echo ($values['oznakomlen'] != NULL) ? 'checked' : ''; ?>>
            <label for="oznakomlen" class="<?php echo ($errors['oznakomlen'] != NULL) ? 'colred' : ''; ?>">С контрактом ознакомлен (а)</label>
            <div class="errpodinp"><?php echo $messages['oznakomlen']?></div>
        </div>
        <?php
            if($log) echo '<button type="submit" class="editBut">Изменить</button>';
            else echo '<button type="submit">Отправить</button>';
        ?>
    </form>
</div>
<script>
    document.addEventListener("DOMContentLoaded", function(){
        setTimeout(function(){
            let el = document.querySelector('input[name=gender][checked]');
            if(el != null)
                el.click();
        }, 200)
    });
</script>
</body>
</html>