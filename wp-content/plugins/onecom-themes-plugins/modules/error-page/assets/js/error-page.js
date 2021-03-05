(function ($) {
    $("#onecom_ep_enable").click(function () {
        $(this).find('.oc-failed')
        {
            $('.oc-failed').removeClass("oc-failed");
        }
        var data = {
            action: 'onecom-error-pages',
            type: $(this).prop("checked") ? 'enable' : 'disable'
        };
        $('.components-spinner').css("display", "inline-block");
        $.post(ajaxurl, data, function (res) {
            $('.components-spinner').css("display", "none");
            if (res.status === 'success') {
                $('#onecom-error-preview').toggleClass("onecom-error-extended");
                $('#onecom-status-message').slideUp();
            } else {
                $('#onecom-status-message').text(res.message);
                $('#onecom-status-message').slideDown();
                failButton();
            }
        })
    });

    function failButton() {
        if ($("#onecom_ep_enable").prop("checked")) {
            $('.oc_cb_slider').addClass("oc-failed");
            $("#onecom_ep_enable").prop("checked", false);
        } else {
            $('.oc_cb_slider').addClass("oc-success");
            $("#onecom_ep_enable").prop("checked", true);
        }
    }
})(jQuery);