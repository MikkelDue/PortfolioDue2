<?php
/* Copyright 2019: one.com */
include_once 'inc/logger.php';
include_once 'inc/ocver.php';


if(! (class_exists('OTPHP\TOTP') && class_exists('ParagonIE\ConstantTime\Base32'))){
    require_once ( __DIR__.'/inc/lib/validator.php' );
}
if(! (class_exists('OCPushStats'))){
    require_once ( __DIR__.'/inc/lib/OCPushStats.php' );
}

final class OCVCaching extends VCachingOC {
    const defaultTTL = 2592000; //1 month
    const defaultEnable = 'true';
    const defaultPrefix = 'varnish_caching_';
    const pluginName = 'onecom-vcache';
    const textDomain = 'vcaching';
    const transient = '__onecom_allowed_package';
    const getOCParam = 'purge_varnish_cache';
    const pluginVersion = '0.2.9';
    const ocRulesVersion = 1.1;

    
    private $OCVer;
    private $logger;

    public $VCPATH;
    public $OCVCPATH;
    public $OCVCURI;
    public $state = 'false';

    public $cdn_url;
    public $blog_url;

    private $messages = array();

    public function __construct() {
        $this->OCVCPATH = dirname( __FILE__ );
        $this->OCVCURI = plugins_url( null, __FILE__ );
        $this->VCPATH = dirname( $this->OCVCPATH );

        $this->logger = new Onecom_Logger();
        $this->logger->setFileName( 'vcache' );
        
        $this->blog_url = get_option('home');
        $this->cdn_url = 'https://usercontent.one/wp/' . str_replace(['https://', 'http://'], '', $this->blog_url);

        add_action( 'init', array( $this, 'loadOCVer' ), 1 );
        add_action( 'admin_init', array( $this, 'runAdminSettings' ), 1 );
                
        add_action( 'admin_menu', array( $this, 'remove_parent_page' ), 100 );
        add_action( 'admin_menu', array( $this, 'add_menu_item' ) );

        add_action( 'admin_init', array( $this, 'options_page_fields' ) );
        add_action( 'plugins_loaded', array( $this, 'filter_purge_settings' ), 1 );

        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_resources' ) );
        add_action( 'admin_head', array( $this, 'onecom_vcache_icon_css' ));
        
        add_action('wp_ajax_oc_set_vc_state', array($this, 'oc_set_vc_state_cb'));
        add_action('wp_ajax_oc_set_vc_ttl', array($this, 'oc_set_vc_ttl_cb'));
        add_action('wp_ajax_oc_set_cdn_state', array($this, 'oc_cdn_state_cb'));
        add_action('template_redirect', array($this, 'oc_cdn_rewrites'));
        add_action('upgrader_process_complete', array($this, 'oc_upgrade_housekeeping'), 10, 2);
        add_action('plugins_loaded', array($this, 'oc_update_headers_htaccess'));
        add_action( 'switch_theme', [ $this, 'purge_theme_cache' ] );

        // remove purge requests from Oclick demo importer
        add_filter( 'vcaching_events', array( $this, 'vcaching_events_cb' ) );
        //intercept the list of urls, replace multiple urls with a single generic url
        add_filter( 'vcaching_purge_urls', array( $this, 'vcaching_purge_urls_cb' ) );

        register_activation_hook( $this->VCPATH . DIRECTORY_SEPARATOR . 'vcaching.php', array( $this, 'onActivatePlugin' ) );
        register_deactivation_hook( $this->VCPATH . DIRECTORY_SEPARATOR . 'vcaching.php', array( $this, 'onDeactivatePlugin' ) );
    }

    /**
    * Function to load ocver
    *
    */
    public function loadOCVer() {
        $this->OCVer = new OCVer( $is_plugin = true, self::pluginName, $duration = 13 );
        $is_admin = is_admin();
        $isVer = $this->OCVer->isVer( self::pluginName, $is_admin );
        if("false" == get_site_option(self::defaultPrefix . 'enable') || 'false' === $isVer ) {
            self::disableDefaultSettings();
        }
        else if('true' === $isVer) {
            self::setDefaultSettings();
            $this->state = 'true';
        }
    }

    /**
    * Function to run admin settings
    *
    */
    public function runAdminSettings() {
        if( 'false' !== $this->state ){
            return;
        }
        add_action( 'admin_bar_menu', array( $this, 'remove_toolbar_node' ), 999 );

        add_filter( 'post_row_actions', array( $this, 'remove_post_row_actions' ), 10, 2 );
        add_filter( 'page_row_actions', array( $this, 'remove_page_row_actions' ), 10, 2 );
    }

    /**
    * Function will execute after plugin activated
    *
    **/
    public function onActivatePlugin() {
        global $pagenow;
        if($pagenow==='plugins.php'){
            $referrer='plugins_page';
        }else{
            $referrer='install_wizard';
        }
        (class_exists('OCPushStats')?\OCPushStats::push_stats_event_themes_and_plugins('activate','plugin',self::pluginName,$referrer):'');
        self::setDefaultSettings();
    }

    /**
    * Function will execute after plugin deactivated
    *
    */
    public function onDeactivatePlugin() {
        (class_exists('OCPushStats')?\OCPushStats::push_stats_event_themes_and_plugins('deactivate','plugin',self::pluginName,'plugins_page'):'');
        self::disableDefaultSettings( $onDeactivate = true );
        self::purgeAll();
    }

    /**
     * Function to make some checks to ensure best usage
     **/
    private function runChecklist() {
        $this->oc_upgrade_housekeeping('activate');
        
        // If not exist, then return
        if(!in_array('vcaching/vcaching.php', (array)get_option('active_plugins'))){
            return true;
        }           
        
        $this->logger->wpAPISendLog( 'already_exists', self::pluginName, self::pluginName . 'DefaultWP Caching plugin already exists.', self::pluginVersion );
        add_action( 'admin_notices', array($this, 'duplicateWarning'));

        return false;
    }

    /**
     * Function to disable vcache promo/notice 
     *
     */
    private function disablePromoNotice() {
        $local_promo = get_site_option( 'onecom_local_promo' );
        if( ( isset( $local_promo[ 'xpromo' ] ) && $local_promo[ 'xpromo' ] == '18-jul-2018' ) ) {
            $local_promo[ 'show' ] = false;
            update_site_option( 'onecom_local_promo', $local_promo );
        }
    }

    /*
     * Show Admin notice
     */
    public function duplicateWarning(){

        $screen = get_current_screen();
        $warnScreens = array(
            'toplevel_page_onecom-vcache-plugin',
            'plugins',
            'options-general',
            'dashboard',
        );

        if(!in_array($screen->id, $warnScreens))
            return;

        $class = 'notice notice-warning is-dismissible';

        $dectLink = add_query_arg(
            array(
                'disable-old-varnish' => 1,
                '_wpnonce' => wp_create_nonce('disable-old-varnish')
            )
        );

        $dectLink  = wp_nonce_url($dectLink, 'plugin-deactivation');
        $message = __( 'To get the best out of One.com Performance Cache, kindly deactivate the existing "Varnish Caching" plugin.&nbsp;&nbsp;', self::textDomain );
        $message .= sprintf("<a href='%s' class='button'>%s</a>", ($dectLink), __('Deactivate'));
        printf( '<div class="%1$s"><p>%2$s</p></div>', esc_attr( $class ), $message );
    }

    /* Function to convert boolean to string
     *
     *
     */
    private function booleanCast( $value ) {
        if( ! is_string( $value ) ) {
            $value = ( 1 === $value || TRUE === $value ) ? 'true' : 'false';
        }
        if( '1' === $value ) {
            $value = 'true';
        }
        if( '0' === $value ) {
            $value = 'false';
        }
        return $value;
    }


    /**
    * Function to set default settings for one.com
    *
    **/
    private function setDefaultSettings() {
        // Enable by default
        $enable = $this->booleanCast( self::defaultEnable );
        $enabled = update_option( self::defaultPrefix . 'enable', $enable );
        $check = get_option( self::defaultPrefix . 'enable', $enable );
        if ( !($check === "true" || $check === true || $check === 1)) {
            return;
        }

        $this->logger->log( $message = self::pluginName.' plugin featureEnabled' );

        // Update the cookie name
        if( ! get_option( self::defaultPrefix . 'cookie' ) ) {
            $name = sha1(md5(uniqid()));
            update_option( self::defaultPrefix . 'cookie', $name );
        }
         
        // Set default TTL
        $ttl = self::defaultTTL;
        if( ! get_option( self::defaultPrefix . 'ttl' ) && ! is_bool( get_option( self::defaultPrefix . 'ttl' ) ) && get_option( self::defaultPrefix . 'ttl' ) != 0 ) {
            update_option( self::defaultPrefix . 'ttl', $ttl );
        } elseif( ! get_option( self::defaultPrefix . 'ttl' ) && is_bool( get_option( self::defaultPrefix . 'ttl' ) ) ){
            update_option( self::defaultPrefix . 'ttl', $ttl );
        }
        if( ! get_option( self::defaultPrefix . 'homepage_ttl' ) && ! is_bool( get_option( self::defaultPrefix . 'homepage_ttl' ) ) && get_option( self::defaultPrefix . 'homepage_ttl' ) != 0 ) {
            update_option( self::defaultPrefix . 'homepage_ttl', $ttl );
        } elseif( ! get_option( self::defaultPrefix . 'homepage_ttl' ) && is_bool( get_option( self::defaultPrefix . 'homepage_ttl' ) ) ){
            update_option( self::defaultPrefix . 'homepage_ttl', $ttl );
        }

        // Set default varnish IP
        $ip = getHostByName( getHostName() );
        update_option( self::defaultPrefix . 'ips', $ip ); 

        if( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            update_option( self::defaultPrefix . 'debug', true );
        }

        // Deactivate the old varnish caching plugin on user's consent.
        if( (isset($_REQUEST['disable-old-varnish']) && $_REQUEST['disable-old-varnish'] == 1)){
            deactivate_plugins('/vcaching/vcaching.php');
            self::runAdminSettings();
            add_action( 'admin_bar_menu', array( $this, 'remove_toolbar_node' ), 999 );
        }

        // Check and notify if varnish plugin already active.
        if( in_array( 'vcaching/vcaching.php', (array)get_option('active_plugins'))){
            add_action( 'admin_notices', array( $this, 'duplicateWarning' ) );
        }
    }

    /**
    * Function to disable varnish plugin
    *
    **/
    private function disableDefaultSettings( $onDeactivate = false ) {
        // Disable by default
        // $enable = $this->booleanCast( false );
        // $disabled = update_option( self::defaultPrefix . 'enable', $enable );
        $disabled = false;
        $action = ( TRUE === $onDeactivate ) ? 'disableManual' : 'featureDisabled';
        if( $disabled ) {
            $this->logger->log( $message = self::pluginName.' feature disabled '.$action );
//
            self::purgeAll();
        }
         // Intentionally commented the auto-turn-off on package downgrade
         // BECAUSE it is causing auto-ON
        delete_option( self::defaultPrefix . 'ttl' );
        delete_option( self::defaultPrefix . 'homepage_ttl' );
    }

    /**
    * Remove current menu item
    *
    */
    public function remove_parent_page() {
        remove_menu_page( 'vcaching-plugin' );
    }

    /**
    * Add menu item
    *
    */
    public function add_menu_item() {
        if (parent::check_if_purgeable()) {
            global $onecom_generic_menu_position;
            $position = ( function_exists('onecom_get_free_menu_position') && !empty($onecom_generic_menu_position) ) ? onecom_get_free_menu_position($onecom_generic_menu_position) : null;
            add_menu_page(__('Performance Cache', self::textDomain), __('Performance Cache&nbsp;', self::textDomain), 'manage_options', self::pluginName . '-plugin', array($this, 'settings_page'), 'dashicons-dashboard', $position );
        }
    }

    /**
    * Function to show settings page
    *
    */
    public function settings_page() {
        include_once $this->OCVCPATH . DIRECTORY_SEPARATOR . 'templates' . DIRECTORY_SEPARATOR . 'page-settings.php';
    }

    /**
     * Fuction to show the turbo charge page
     */
    public function settings_page_turbocharge (){
        include_once $this->OCVCPATH . DIRECTORY_SEPARATOR . 'templates' . DIRECTORY_SEPARATOR . 'turbocharge-page-settings.php';
    }
    /**
    * Function to customize options fields
    *
    */
    public function options_page_fields() {
        add_settings_section(self::defaultPrefix . 'oc_options', null, null, self::defaultPrefix . 'oc_options');

        add_settings_field(self::defaultPrefix . "ttl", __("Cache TTL", self::textDomain) . '<span class="tooltip"><span class="dashicons dashicons-editor-help"></span><span>'.__( 'The time that website data is stored in the Varnish cache. After the TTL expires the data will be updated, 0 means no caching.', self::textDomain ).'</span></span>', array($this, self::defaultPrefix . "ttl_callback"), self::defaultPrefix . 'oc_options', self::defaultPrefix . 'oc_options');

        if(isset($_POST['option_page']) && $_POST['option_page'] == self::defaultPrefix . 'oc_options') {
            register_setting(self::defaultPrefix . 'oc_options', self::defaultPrefix . "enable");
            register_setting( self::defaultPrefix . 'oc_options', self::defaultPrefix . "ttl");
           
            $ttl = $_POST[ self::defaultPrefix . 'ttl' ];
            $is_update = update_option( self::defaultPrefix . "homepage_ttl", $ttl ); //overriding homepage TTL
        }

        self::disablePromoNotice();
    }

    /**
    * Function enqueue resources
    *
    */
    public function enqueue_resources( $hook ) {
        $pages = [
            'toplevel_page_onecom-vcache-plugin'
        ];
        if (!in_array($hook, $pages)){
            return;
        }
        wp_register_style( 
            $handle = self::pluginName, 
            $src = $this->OCVCURI.'/assets/css/style.css', 
            $deps = null, 
            $ver = '0.1.24', 
            $media = 'all'
        );
        wp_register_script(
            $handle = self::pluginName, 
            $src = $this->OCVCURI.'/assets/js/scripts.js', 
            $deps = ['jquery'], 
            $ver = '0.1.24', 
            $media = 'all'
        );
        wp_enqueue_style( self::pluginName );
        wp_enqueue_script( self::pluginName );
        
        /* Google fonts */
        if( ! wp_style_is( 'onecom-wp-google-fonts', 'registered' ) ) {
            wp_register_style( 
                $handle = 'onecom-wp-google-fonts', 
                $src = '//fonts.googleapis.com/css?family=Open+Sans:300,400,600,700,800', 
                $deps = null, 
                $ver = null, 
                $media = 'all'
            );
        }
        wp_enqueue_style( 'onecom-wp-google-fonts' );
    }

    /* Function to enqueue style tag in admin head
     * */
    function onecom_vcache_icon_css(){
        echo "<style>.toplevel_page_onecom-vcache-plugin > .wp-menu-image{display:flex !important;align-items: center;justify-content: center;}.toplevel_page_onecom-vcache-plugin > .wp-menu-image:before{content:'';background-image:url('".$this->OCVCURI."/assets/images/performance-inactive-icon.svg');font-family: sans-serif !important;background-repeat: no-repeat;background-position: center center;background-size: 18px 18px;background-color:#fff;border-radius: 100px;padding:0 !important;width:18px;height: 18px;}.toplevel_page_onecom-vcache-plugin.current > .wp-menu-image:before{background-size: 16px 16px; background-image:url('".$this->OCVCURI."/assets/images/performance-active-icon.svg');}.ab-top-menu #wp-admin-bar-purge-all-varnish-cache .ab-icon:before,#wpadminbar>#wp-toolbar>#wp-admin-bar-root-default>#wp-admin-bar-onecom-wp .ab-item:before, .ab-top-menu #wp-admin-bar-onecom-staging .ab-item .ab-icon:before{top: 2px;}a.current.menu-top.toplevel_page_onecom-vcache-plugin.menu-top-last{word-spacing: 10px;}@media only screen and (max-width: 960px){.auto-fold #adminmenu a.menu-top.toplevel_page_onecom-vcache-plugin{height: 55px;}}</style>";
        return;
    }

    /**
    * Function to create enable field
    *
    */
    public function varnish_caching_enable_callback() {
        ?>
            <input type="checkbox" id="varnish_caching_enable" name="varnish_caching_enable" value="1" <?php checked( 'true', get_option( self::defaultPrefix . 'enable' ), true ); ?> />
            <label for="varnish_caching_enable"><?=__('Enable Performance Cache', self::textDomain)?></label>
        <?php
    }

    /**
    * Function to create TTL field
    *
    */
    public function varnish_caching_ttl_callback() {
        ?>
            <input type="number" name="varnish_caching_ttl" id="varnish_caching_ttl" value="<?php echo get_option(self::defaultPrefix . 'ttl'); ?>" /> 
            <p class="description"><?=__('Time to live in seconds in Varnish cache', self::textDomain)?></p>
        <?php
    }

    /**
    * Function to purge all
    *
    */
    private function purgeAll() {
        $pregex = '.*';
        $purgemethod = 'regex';
        $path = '/';
        $schema = 'http://';

        $ip = get_option( self::defaultPrefix . 'ips' );

        $purgeme = $schema . $ip . $path . $pregex;

        $headers = array(
            'host' => $_SERVER['SERVER_NAME'], 
            'X-VC-Purge-Method' => $purgemethod, 
            'X-VC-Purge-Host' => $_SERVER['SERVER_NAME']
        );
        $response = wp_remote_request( 
            $purgeme, 
            array(
                'method' => 'PURGE', 
                'headers' => $headers, 
                "sslverify" => false
            )
        );
        if ($response instanceof WP_Error) {
            error_log("Cannot purge: ".$purgeme);
        } else {
            //error_log("Purged: ".json_encode($response));
        }
    }

    /**
    * Function to change purge settings
    *
    */
    public function filter_purge_settings() {
        add_filter( 'ocvc_purge_notices', array( $this, 'ocvc_purge_notices_callback' ), 10, 2 );
        add_filter( 'ocvc_purge_url', array( $this, 'ocvc_purge_url_callback' ), 1, 3 );
        add_filter( 'ocvc_purge_headers', array( $this, 'ocvc_purge_headers_callback' ), 1, 2 );
        add_filter( 'ocvc_permalink_notice', array( $this, 'ocvc_permalink_notice_callback' ) );
        add_filter( 'vcaching_purge_urls', array( $this, 'vcaching_purge_urls_callback' ), 10, 2 );

        add_action( 'admin_notices', array( $this, 'oc_vc_notice' ) );
    }

    /**
    * Function to filter the purge request response
    *
    * @param object $response //request response object
    * @param string $url // url trying to purge
    */
    public function ocvc_purge_notices_callback( $response, $url ) {

        $response = wp_remote_retrieve_body( $response );
        
        $find = array(
            '404 Key not found' => sprintf( __( 'It seems that %s is already purged. There is no resource in the cache to purge.', self::textDomain ), $url ),
            'Error 200 Purged' => sprintf( __( '%s is purged successfully.', self::textDomain ), $url ),
        );

        foreach ( $find as $key => $message ) {
            if( strpos( $response, $key ) !== false ) {
                array_push( $this->messages, $message );
            }   
        }
        

    }

    /**
    * Function to add notice
    *
    */
    public function oc_vc_notice() {
        if( empty( $this->messages ) && empty( $_SESSION['ocvcaching_purge_note'] ) ) return;
        ?>
            <div class="notice notice-warning">
                <ul>
                    <?php
                        if( ! empty( $this->messages ) ) {
                            foreach ( $this->messages as $key => $message ) {
                                if( $key > 0 )
                                    break;
                                ?>
                                    <li><?php echo $message; ?></li>
                                <?php 
                            }
                        }
                        elseif( ! empty( $_SESSION['ocvcaching_purge_note'] ) ) {
                            foreach ( $_SESSION['ocvcaching_purge_note'] as $key => $message ) {
                                if( $key > 0 )
                                    break;
                                ?>
                                    <li><?php echo $message; ?></li>
                                <?php 
                            }
                            
                        }
                    ?>
                </ul>
            </div>
        <?php
    }

    /**
    * Function to change purge URL
    *
    * @param string $url //URL to be purge
    * @param string $path //Path of URL
    * @param string $prefex //Regex if any
    * @return string $purgeme //URL to be purge
    */
    public function ocvc_purge_url_callback( $url, $path, $pregex ) {
        $p = parse_url($url);

        $scheme = (isset($p['scheme']) ? $p['scheme'] : '');
        $host = (isset($p['host']) ? $p['host'] : '');
        $purgeme = $scheme . '://' . $host . $path . $pregex;
        
        return $purgeme;
    }

    /**
    * Function to change purge request headers
    *
    * @param string $url //URL to be purge
    * @param array $headers //Headers for the request
    * @return array $headers //New headers
    */
    public function ocvc_purge_headers_callback( $url, $headers ) {
        $p = parse_url($url);
        if (isset($p['query']) && ($p['query'] == 'vc-regex')) {
            $purgemethod = 'regex';
        } else {
            $purgemethod = 'exact';
        }
        $headers[ 'X-VC-Purge-Host' ] = $_SERVER[ 'SERVER_NAME' ];
        $headers[ 'host' ] = $_SERVER[ 'SERVER_NAME' ];
        $headers[ 'X-VC-Purge-Method' ] = $purgemethod;
        return $headers;
    }

    /**
    * Function to change permalink message
    *
    */
    public function ocvc_permalink_notice_callback( $message ) {
        $message = __( 'A custom URL or permalink structure is required for the Performance Cache plugin to work correctly. Please go to the <a href="options-permalink.php">Permalinks Options Page</a> to configure them.', self::textDomain );
        return '<div class="notice notice-warning"><p>'.$message.'</p></div>';
    }

    /**
    * Function to notify customer about auto deactivate plugin 
    * [Not in use]
    */
    public function notifyCustomer() {
        $toEmail = get_option('admin_email');

        $message_id = time() .'-' . md5($toEmail) . '@' . $_SERVER['SERVER_NAME'];
        $header = array(
            "MIME-Version: 1.0",
            "Content-type: text/html; charset: utf8",
            "X-Mailer: PHP/" . PHP_VERSION,
            "X-Priority: 1 (Highest)",
            "Importance: High",
            "Date: ".date("r"),
            "Message-Id: <".$message_id.">"
        );

        $message  = __( "Hello, We've deactivated the One.com Varnish plugin from ".home_url(), self::textDomain );
        $subject = __( "Deactivated the One.com Varnish plugin", self::textDomain );

        $is_mailed = wp_mail( $toEmail, $subject, $message, implode( "\r\n", $header ) );
        if( is_wp_error( $is_mailed ) )  {
            error_log("ERROR mail: ".$is_mailed->get_error_message());
        } else {
            error_log("Mail sent");
        }
    }

    /**
    * Function to deactivate self
    * [Not in use]
    */
    public function deactivateSelf() {
        deactivate_plugins( dirname( plugin_basename( $this->OCVCPATH ) ) . DIRECTORY_SEPARATOR . 'vcaching.php' );
        //header('Location: '.$_SERVER['REQUEST_URI']);
    }

    /**
    * Function to to remove menu item from admin menu bar
    *
    */
    public function remove_toolbar_node( $wp_admin_bar ) {
        // replace 'updraft_admin_node' with your node id
        $wp_admin_bar->remove_node('purge-all-varnish-cache');
    }

    /**
    * Function to to remove purge cache from post
    *
    */
    public function remove_post_row_actions($actions, $post) {
        if( isset( $actions[ 'vcaching_purge_post' ] ) ) {
            unset( $actions[ 'vcaching_purge_post' ] );
        }
        return $actions;
    }

    /**
    * Function to to remove purge cache from page
    *
    */
    public function remove_page_row_actions($actions, $post) {
        if( isset( $actions[ 'vcaching_purge_page' ] ) ) {
            unset( $actions[ 'vcaching_purge_page' ] );
        }
        return $actions;
    }

    /**
    * Function to set purge single post/page URL
    *
    * @param array $array // array of urls
    * @param number $post_id //POST ID
    */
    public function vcaching_purge_urls_callback( $array, $post_id ) {
        $url = get_permalink( $post_id );
        array_unshift( $array, $url );
        return $array;
    }

    /**
     * Function vcaching_events_cb
     * Callback function for vcaching_events WP filter
     * This function checks if the registered events are to be returned, judging from request payload.
     * e.g. the events are nulled for request actions like "heartbeat" and  "ocdi_import_demo_data"
     * @param $events, an array of events on which caching is hooked.
     * @return array
     */
    function vcaching_events_cb( $events ) {

        $no_post_action = ! isset($_REQUEST['action']);
        $action_not_watched = isset( $_REQUEST['action'] ) && ($_REQUEST['action'] === 'ocdi_import_demo_data' || $_REQUEST['action'] === 'heartbeat');

        if ($no_post_action || $action_not_watched) {
            return [];
        } else {
            return $events;
        }
    }

    /**
     * Function vcaching_purge_urls_cb
     * Callback function for vcaching_purge_urls WP filters
     * This function removes all the urls that are to be purged and returns single url that purges entire cache.
     * @param $urls, an array of urls that were originally to be purged.
     * @return array
     */
    function vcaching_purge_urls_cb( $urls ) {
        $site_url = trailingslashit( get_site_url() );
        $purgeUrl = $site_url . '.*';
        $urls     = array( $purgeUrl );
        return $urls;
    }
    
    /**
     * Function oc_set_vc_state_cb()
     * Enable/disable vcaching. Used as AJAX callback
     * @since v0.1.24
     * @param null
     * @return null
     */
    public function oc_set_vc_state_cb(){
        $state = intval($_POST['vc_state']) === 0 ? "false" : "true";        

        // check eligibility if Performance Cache is being enabled. If it is being disabled, allow to continue
        if ($state == "true"){
            $event_action='enable';
            $res = $this->oc_check_pc_activation($state);
            if ( $res['status'] !== 'success'){
                wp_send_json($res);
                return;
            }
        }else{
            $event_action='disable';
        }

        if (get_site_option(self::defaultPrefix . 'enable') == $state){
            $result_status = true;
        }else{
            $result_status = update_site_option(self::defaultPrefix . 'enable', $state);    
        }        
        $result_ttl = $this->oc_set_vc_ttl_cb(false);
        $response = [];
        if ($result_ttl && $result_status ){
            $response = [
                'status' => 'success',
                'message' => __('Performance cache settings updated')
            ];
            (class_exists('OCPushStats')?\OCPushStats::push_stats_performance_cache("$event_action",'setting','cache','performance_cache'):'');
        }else{
            $response = [
                'status' => 'error',
                'message' => __('Something went wrong!')
            ];
        }
        wp_send_json($response);
    }

    public function oc_set_vc_ttl_cb($echo){
        if ($echo === ''){
            $echo = true;
        }
        $ttl_value = intval(trim($_POST['vc_ttl']));
        $ttl =  $ttl_value === 0 ? 2592000 : $ttl_value ;
        if ( (get_site_option('varnish_caching_ttl') == $ttl) && (get_site_option('varnish_caching_homepage_ttl') == $ttl) ){
            $result = true;
        }else{                       
            $result = update_site_option('varnish_caching_ttl', $ttl);  
            update_site_option('varnish_caching_homepage_ttl', $ttl);
            (class_exists('OCPushStats')?\OCPushStats::push_stats_performance_cache('update','setting','ttl','performance_cache'):'');
        }        
        $response = [];
        if ($result){
            $response = [
                'status' => 'success',
                'message' => __('TTL updated')
            ];
        }else{
            $response = [
                'status' => 'error',
                'message' => __('Something went wrong!')
            ];
        }
        if ($echo){
            wp_send_json($response);
        }else{
            return $result;
        }        
    }

    public function oc_cdn_state_cb(){
        $state = intval($_POST['cdn_state']) === 0 ? "false" : "true";
        if ($state == "true"){
            $event_action='enable';
            $res = $this->oc_check_pc_activation($state);
            if ($res['status'] !== 'success'){
                wp_send_json($res);
                return;
            }
        }else{
            $event_action='disable';
        }
        if (get_option('oc_cdn_enabled') == $state){
            $result = true;
        }else{
            $result = update_option('oc_cdn_enabled', $state);    
        }
        $response = [];
        if ($result){
            $response = [
                'status' => 'success',
                'message' => __('CDN state updated')
            ];
        (class_exists('OCPushStats')?\OCPushStats::push_stats_performance_cache("$event_action",'setting','cdn','performance_cache'):'');
        }else{
            $response = [
                'status' => 'error',
                'message' => __('Something went wrong!')
            ];
        }

        wp_send_json($response);
    }

    /**
     * Function oc_cdn_rewrites
     * Intercept the html being sent to browser, replace the eligible urls with the CDN version
     * @since v0.1.24
     * @param null
     * @return null
     */
    public function oc_cdn_rewrites(){
        $cdn_state = get_option('oc_cdn_enabled');
        if ($cdn_state != "true"){
            return;
        }
        ob_start(array($this, 'rewrite'));
    }
    /**
     * Function rewrite
     * Rewrite assets url, replace native ones with the CDN version if the url meets rewrite conditions.
     * @since v0.1.24
     * @param array $html, the html source of the page, provided by ob_start
     * @return string modified html source
     */
    public function rewrite($html){
        $url = get_option('home');        
        $directories = 'wp-content';
        $pattern = '#(?<=[(\"\'])' . $url . '/(?:((?:'.$directories.')[^\"\')]+)|([^/\"\']+\.[^/\"\')]+))(?=[\"\')])#';
        $updated_html = preg_replace_callback($pattern, [$this, 'rewrite_asset_url'], $html);
        return $updated_html;
        $filtered_url = str_replace(['http://', 'https://'], '', $url);
        $filtered_url = rtrim($filtered_url, '/');
        $edited_html = str_replace($url, 'https://usercontent.one/wp/'.$filtered_url, $html);
        return $edited_html;
    }

    /**
     * Function rewrite_asset_url
     * Returns the url that is to be modified to point to CDN. 
     * This function acts as a callback to preg_replace_callback called in rewrite()
     * @since v0.1.24
     * @param array $asset, first element in the array will have the url we are interested in.
     * @return string modified single url
     */
    protected function rewrite_asset_url($asset) {
        /** 
        * Set conditions to rewrite urls. 
        * To maintain consistency, write conditions in a way that if they yield positive value, 
        * the url should not be modified
        */
        $preview_condition = ( is_admin_bar_showing() && array_key_exists('preview', $_GET) && $_GET['preview'] == 'true' );
        $path_condition = ( (strpos($asset[0], 'wp-content') === false) );
        $extension_condition = ( (strpos($asset[0], '.php') !== false) );
        $existing_live = get_option('onecom_staging_existing_live');
        $staging_condition = (!empty( $existing_live) && isset($existing_live->directoryName));
        $css_condition = ((strpos($asset[0], '.css') !== false ));
        $template_path_condition = ( (strpos($asset[0], 'plugins') !== false ) && (strpos($asset[0], 'assets/templates') !== false ));
        
        if ( $preview_condition || $path_condition || $extension_condition || $staging_condition || $css_condition || $template_path_condition)
        {
            return $asset[0];
        }
        
        $blog_url = $this->relative_url($this->blog_url);
        // both http and https urls are to be replaced
        $subst_urls = [
            'http:'.$blog_url,
            'https:'.$blog_url,
        ];

        // is it a protocol independent URL?
        if (strpos($asset[0], '//') === 0) {
            return str_replace($blog_url, $this->cdn_url, $asset[0]);
        }

        // check if not a relative path
        if (strpos($asset[0], $blog_url) !== 0) {
            return str_replace($subst_urls, $this->cdn_url, $asset[0]);
        }

        // relative URL
        return $this->cdn_url . $asset[0];
    }
    /**
     * Function relative_url
     * Check if given string is a relative url
     * @since v0.1.24
     * @param string $url
     * @return string
     */
    protected function relative_url($url) {
        return substr($url, strpos($url, '//'));
    }
    
    /**
     * Function oc_upgrade_housekeeping
     * Perform actions after plugin is upgraded or activated
     * @since v0.1.24
     * @param $upgrade_data - data passed by WP hooks, used only in case of activation
     * @return void
     */
    public function oc_upgrade_housekeeping($upgrade_data = null, $options = null){

        // exit if this plugin is not being upgraded
        if ( $options && isset($options['pugins']) && !in_array('onecom-vcache/vcaching.php', $options['plugins'])){
            return;
        }

        $existing_version_db = trim(get_site_option('onecom_plugin_version_vcache'));
        $current_version = trim(self::pluginVersion);

        //exit if plugin version is same in plugin and DB. If plugin is activated, bypass this condition
        if( ($existing_version_db == $current_version) && ($upgrade_data !== 'activate')){
            return;
        }
        // update plugin version in DB
        update_site_option('onecom_plugin_version_vcache', $current_version);

        //
        (class_exists('OCPushStats')?\OCPushStats::push_stats_event_themes_and_plugins('update','plugin',self::pluginName,'plugins_page'):'');



        // update plugin options, turn on Performance tools by default if subscription is eligible, else return
        $result = oc_set_premi_flag(true);
        if($result['data'] == null && $result['success'] != 1 ){
            return;
        }        
        else if ( ! oc_pm_features('pcache', $result['data']) ){
            return;  
        }
        
        // if current subscription is eligible for Performance Cache, enable the plugins
        if (get_site_option(self::defaultPrefix . 'enable') == ''){
            update_site_option(self::defaultPrefix . 'enable', "true");
        }
        
        if (get_site_option('oc_cdn_enabled') == ''){
            update_site_option('oc_cdn_enabled', "true");
        }        
        
        //set TTL for varnish caching, default for 1 month in seconds
        if (get_site_option('varnish_caching_ttl') == ''){
            update_site_option('varnish_caching_ttl', '2592000');
        }        
        if (get_site_option('varnish_caching_homepage_ttl') == ''){
            update_site_option('varnish_caching_homepage_ttl', '2592000');
        }
        
    }

    /**
     * Function oc_check_pc_activation
     * Check if operation should be allowed or not.
     * This function checks the features provided with the subscription package.
     * @since v0.1.24
     * @param $state - the state of switch, either true or false. True => enable the features, False => disable the features
     * @return void
     */
    public function oc_check_pc_activation($state, $data = 'pcache'){
        if ($state == 'true'){
            $result = oc_set_premi_flag(true);
            if($result['data'] == null && $result['success'] != 1 ){
                $response = [
                    'status' => '',
                    'msg' => __("Some error occurred, please reload the page and try again.", "validator").' ['.$result['error'].']'
                ];
            }
            else if (oc_pm_features($data, $result['data'])){
                $response = [
                    'status' => 'success',
                    'sender' => 'verification'
                ];                
            } else{
                $response = [
                    'status' => 'failed',
                    'sender' => 'verification'
                ];                
            }
            return $response;
        }
    }

    function oc_update_headers_htaccess(){

        // exit if not logged in or not admin
        $user = wp_get_current_user();
        if ( (!isset($user->roles)) || (! in_array( 'administrator', (array) $user->roles )) ) {
            return;
        }       

        // exit for some of the common conditions
        if ( defined( 'XMLRPC_REQUEST' ) || defined( 'DOING_AJAX' ) || defined( 'IFRAME_REQUEST' ) || wp_is_json_request() ){
            return;
        }

        // check if CDN is enabled 
        $cdn_enabled = get_site_option('oc_cdn_enabled');       
        if ( $cdn_enabled != 'true'){
            return;
        }
        // check if rules version is saved. If saved, do we need to updated them?
        $rules_version = get_site_option('oc_rules_version');
        if ($rules_version && (version_compare($rules_version, self::ocRulesVersion, '=') )){
            return;
        }

        $file = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . '.htaccess'; 
        $rules = '# One.com response headers BEGIN'
        . PHP_EOL 
        .'<IfModule mod_headers.c>
    <FilesMatch "\.(ttf|ttc|otf|eot|woff|woff2|css|js|png|jpg|jpeg|svg|pdf)$">
        Header set Access-Control-Allow-Origin "*"
    </FilesMatch>
</IfModule>' .PHP_EOL . '# One.com response headers END';
        
        if ( file_exists($file) ){
            $contents = @file_get_contents($file);
            // if file exists but rules not found, add them         
            if ( strpos($contents, '# One.com response headers BEGIN') === false){
                @file_put_contents($file, PHP_EOL . $rules, FILE_APPEND);
            }elseif( version_compare($rules_version, self::ocRulesVersion, '!=') ){  //if file exists, rules are present but existing rules need to be updated
                //replace content between our BEGIN and END markers
                $content_array = preg_split('/\r\n|\r|\n/', $contents);
                $start = array_search('# One.com response headers BEGIN', $content_array);
                $end = array_search('# One.com response headers END', $content_array);
                $length = ($end - $start) + 1;
                array_splice($content_array, $start, $length, preg_split('/\r\n|\r|\n/', $rules));
                @file_put_contents($file, implode(PHP_EOL, $content_array));                
            }   
        }else{
            @file_put_contents($file, $rules);          
        }
        //finally, if file was changed, update the self::ocRulesVersion as oc_rules_version in options for future reference
        update_site_option('oc_rules_version', self::ocRulesVersion);
    }
    function purge_theme_cache() {
        wp_remote_request($this->blog_url, ['method' => 'PURGE']);

    }
}
$OCVCaching = new OCVCaching();