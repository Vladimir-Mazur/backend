<?php
    require('connection.php');

    function res($status, $val){
        exit(json_encode(array('status' => $status, 'value' => $val), JSON_UNESCAPED_UNICODE));
    }

    if($_SERVER['PHP_AUTH_USER'] == NULL) res('error', "Вы не авторизованы");

    $id = checkInput($_POST['id']);
    if(!preg_match('/^[0-9]+$/', $id)) res('error', "Введите id");

    
    $dbf = $db->prepare("SELECT * FROM form_data WHERE id = ?");
    $dbf->execute([$id]);
    if($dbf->rowCount() != 0){
        $dbdel = $db->prepare("DELETE FROM form_data WHERE id = ?");
        $dbdel->execute([$id]);
        $dbdel = $db->prepare("DELETE FROM form_data_lang WHERE id_form = ?");
        ($dbdel->execute([$id])) ? res('success', "Форма удалена") : res('error', "Ошибка удаления");
    }
    else{
        res('error', "Форма не найдена");
    }
?>