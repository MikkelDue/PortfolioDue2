jQuery(document).ready(function () {
    jQuery('#pc_enable').change(function () {
        ocSetVCState();
    });
    jQuery('#oc_ttl_save').click(function(){
        if (oc_validate_ttl()){
            oc_update_ttl();    
        }
    });
    jQuery('#cdn_enable').change(function (){
        ocSetCdnState();
    });
});

function oc_toggle_state(element) {
    var current_icon = element.attr('src');
    var new_icon = element.attr('data-alt-image');
    element.attr({
        'src': new_icon,
        'data-alt-image': current_icon
    });
}

function ocSetVCState() {
    jQuery('#oc_pc_switch_spinner').removeClass('success').addClass('is_active');
    var vc_state = jQuery('#pc_enable').prop('checked') ? '1' : '0';
    jQuery.post(ajaxurl, {
        action: 'oc_set_vc_state',
        vc_state: vc_state,
        vc_ttl: jQuery('#oc_vcache_ttl').val() || '2592000'
    }, function (response) {
        jQuery('#oc_pc_switch_spinner').removeClass('is_active').addClass('success');
        if (response.status === 'success') {
            oc_toggle_pSection();
            oc_trigger_log({
                actionType: 'wppremium_click_feature',
                isPremium: 'true',
                feature: 'PERFORMANCE_CACHE',
                featureAction: (vc_state == '1') ? 'enable_vcache' : 'disable_vcache'
            });
        }else{
            jQuery('#oc_um_overlay').show();
            ocSetModalData({
                isPremium: 'true',
                feature: 'PERFORMANCE_CACHE',
                featureAction: (vc_state == '1') ? 'enable_vcache' : 'disable_vcache'
            });
            jQuery('#pc_enable').prop('checked', false);
        }
    })
}

function oc_toggle_pSection() {
    if (jQuery('#pc_enable').prop('checked')) {
        jQuery('#oc-performance-icon').hide();
        jQuery('#oc-performance-icon-active').show();
        if (!jQuery('#oc_vcache_ttl').val()){
            jQuery('#oc_vcache_ttl').val('2592000');
        }
        jQuery('#pc_enable_settings').show();
    } else {
        jQuery('#oc-performance-icon').show();
        jQuery('#oc-performance-icon-active').hide();
        jQuery('#pc_enable_settings').hide();
    }
}

function oc_validate_ttl(){
    var element = jQuery('#oc_vcache_ttl');
    var ttl_value = element.val();
    var pattern = /^\d+$/;
    if (pattern.test(ttl_value)){
        element.removeClass('oc_error');
        return true;
    }else{
        element.addClass('oc_error');
        return false;
    }
}

function oc_update_ttl(){
    jQuery('#oc_ttl_spinner').removeClass('success').addClass('is_active');
    jQuery.post(ajaxurl, {
        action: 'oc_set_vc_ttl',
        vc_ttl: jQuery('#oc_vcache_ttl').val() || '2592000'
    }, function(response){
        jQuery('#oc_ttl_spinner').removeClass('is_active');
        if (response.status === 'success'){
            jQuery('#oc_ttl_spinner').addClass('success');
        }
        if ( ! jQuery('#oc_vcache_ttl').val().trim()){
            jQuery('#oc_vcache_ttl').val('2592000');
        }
    });
}

function ocSetCdnState(){
    jQuery('#oc_cdn_switch_spinner').removeClass('success').addClass('is_active');
    var cdn_state = jQuery('#cdn_enable').prop('checked') ? '1' : '0';
    jQuery.post(ajaxurl, {
        action: 'oc_set_cdn_state',
        cdn_state : cdn_state,
    }, function(response){
        jQuery('#oc_cdn_switch_spinner').removeClass('is_active');
        if (response.status === 'success'){
            jQuery('#oc_cdn_switch_spinner').addClass('success');
            oc_change_cdn_icon();
            oc_trigger_log({
                actionType: 'wppremium_click_feature',
                isPremium: 'true',
                feature: 'CDN',
                featureAction: (cdn_state == '1') ? 'enable_cdn' : 'disable_cdn'
            });
        }else{
            jQuery('#oc_um_overlay').show();
            ocSetModalData({
                isPremium: 'true',
                feature: 'CDN',
                featureAction: (cdn_state == '1') ? 'enable_cdn' : 'disable_cdn'
            });
            jQuery('#cdn_enable').prop('checked', false);
        }        
    });    
}

function oc_change_cdn_icon(){
    if (jQuery('#cdn_enable').prop('checked')) {
        jQuery('#oc-cdn-icon-active').show();
        jQuery('#oc-cdn-icon').hide();
    } else {
        jQuery('#oc-cdn-icon').show();
        jQuery('#oc-cdn-icon-active').hide();        
    }
}