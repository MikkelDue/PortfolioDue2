<?php
/**
 * @Version 2.1
 **/
if(!defined('OC_ACTIVATE_STR')){
    define('OC_ACTIVATE_STR','activate');
}
if(!defined('OC_DEACTIVATE_STR')){
    define('OC_DEACTIVATE_STR','deactivate');
}
if(!defined('OC_DM_NAME')){
    define('OC_DM_NAME','ONECOM_DOMAIN_NAME');
}
if(!defined('ONECOM')){
    define('ONECOM','one.com');
}
if(!defined('AUTHOR')){
    define('AUTHOR','Author');
}
if(!defined('OCPUSHSTATS')){
    define('OCPUSHSTATS','OCPushStats');
}
if(!defined('THEME')){
    define('THEME','theme');
}
if(!defined('THEMESPAGE')){
    define('THEMESPAGE','themes_page');
}
if(!defined('UPDATE')){
    define('UPDATE','update');
}
/**
 * WordPress action to trigger after activating the theme
 **/
add_action( 'after_switch_theme', 'onecom_activate_theme_stats' );
/**
 * WordPress action to trigger after deactivating the theme
 **/
add_action( 'switch_theme', 'onecom_deactivate_theme_stats', 10, 3 );
/**
 * Function after activating the theme
 **/
if( ! function_exists( 'onecom_activate_theme_stats' ) ) {
    function onecom_activate_theme_stats() {

        $theme = wp_get_theme();


        if( ONECOM !== strtolower( $theme->display( AUTHOR, FALSE ) ) ) {
            return false;
        }
        $url=(isset($_SERVER['HTTP_REFERER'])?parse_url( $_SERVER['HTTP_REFERER'], PHP_URL_QUERY ):'');


        if(!empty($url) && $url=='step=theme'){
            $referrer='install_wizard';
        }else{

            $referrer=THEMESPAGE
;
        }
        (class_exists(OCPUSHSTATS)?\OCPushStats::push_stats_event_themes_and_plugins('activate',THEME,$theme->stylesheet,"$referrer"):'');
    }
}
/**
 * Function after dectivating the theme
 **/
if( ! function_exists( 'onecom_deactivate_theme_stats' ) ) {
    function onecom_deactivate_theme_stats( $new_name, $new_theme, $old_theme ) {
        @$new_name; @$new_theme;
        if( ONECOM !== strtolower( $old_theme->display( AUTHOR, FALSE ) ) ) {
            return false;
        }


        (class_exists(OCPUSHSTATS)?\OCPushStats::push_stats_event_themes_and_plugins('deactivate',THEME,$old_theme->stylesheet,THEMESPAGE):'');
    }
}


if(!function_exists('onecom_upgradation_check')) {
    function onecom_upgradation_check($upgrader_object, $options)
    {

        if ($options['action'] == UPDATE
 && $options['type'] == 'plugin' && isset($options['plugins'])) {

            if ($upgrader_object->skin->plugin_info['AuthorName'] !== ONECOM) {

                return;

            }

            (class_exists(OCPUSHSTATS) ? \OCPushStats::push_stats_event_themes_and_plugins(UPDATE, 'plugin', $upgrader_object->result['destination_name'], 'plugins_page') : '');


        } elseif ($options['action'] == UPDATE
 && $options['type'] == THEME && isset($options['themes'])) {

            if ($upgrader_object->skin->theme_info->get(AUTHOR) !== ONECOM) {

                return;

            }

            (class_exists(OCPUSHSTATS) ? \OCPushStats::push_stats_event_themes_and_plugins(UPDATE, THEME, $upgrader_object->result['destination_name'], THEMESPAGE) : '');


        }
    }
}
add_action( 'upgrader_process_complete', 'onecom_upgradation_check',10, 2);
