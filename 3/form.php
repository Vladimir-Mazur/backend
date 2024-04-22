  <div class="pform">
    <form action="" method="post">
        <h3>Форма</h3>
        <div>
            <input class="w100" type="text" name="fio" placeholder="ФИО">
        </div>
        <div>
            <input class="w100" type="tel" name="phone" placeholder="Телефон">
        </div>
        <div>
            <input class="w100" type="email" name="email" placeholder="email">
        </div>
        <div>
            <input class="w100" type="date" name="birthday">
        </div>
        <div class="ent">
            <div>Пол:</div>
            <label>
                <input type="radio" name="gender" value="male">
                Мужской
            </label>
            <br>
            <label>
                <input type="radio" name="gender" value="female">
                Женский
            </label>
        </div>
        <div class="ent">
            <select class="w100" name="like_lang[]" id="like_lang" multiple="multiple">
                <option disabled selected>Любимый язык программирования</option>
                <option value="Pascal">Pascal</option>
                <option value="C">C</option>
                <option value="C++">C++</option>
                <option value="JavaScript">JavaScript</option>
                <option value="PHP">PHP</option>
                <option value="Python">Python</option>
                <option value="Java">Java</option>
                <option value="Haskel">Haskel</option>
                <option value="Clojure">Clojure</option>
                <option value="Prolog">Prolog</option>
                <option value="Scala">Scala</option>
            </select>
        </div>
        <div>
            <textarea name="biography" placeholder="Биография"></textarea>
        </div>
        <div>
            <input type="checkbox" name="oznakomlen" id="oznakomlen">
            <label for="oznakomlen">С контрактом ознакомлен (а)</label>
        </div>
        <button type="submit">Отправить</button>
    </form>
  </div>
</body>
</html>