$('.remove').on('click', function(){
    let pr = this.parentNode.parentNode,
        prId = pr.getAttribute('data-id');
    console.log(prId)
    if(confirm("Удалить данные формы id = " + prId + "?")){
        $.ajax({
            type: "POST",
            url: './removeForm.php',
            data: {'id': prId},
            success: function(e){
                res = JSON.parse(e);
                if((res.status == "success")){
                    $(pr).find('td:not(.form_del)').remove();
                    $(pr).find('.form_del').removeClass('hid');
                    setTimeout(function(){
                        $(pr).animate({opacity: 0}, 300, function() {
                            setTimeout(() => $(pr).remove(), 300);
                        });
                    }, 1500);
                }
                else{
                    alert(res.value);
                }
            },
            error: function(){
                alert('Ошибка');
            }
        });
    }
});