<?php
    $pc_checked = '';
    $performance_icon = $this->OCVCURI.'/assets/images/performance@2x.svg';
    $performance_icon_2x = $this->OCVCURI.'/assets/images/performance-active@2x.svg 2x';
    $performance_icon_active = $this->OCVCURI.'/assets/images/performance-active@2x.svg';
    $performance_icon_2x_active = $this->OCVCURI.'/assets/images/performance-active@2x.svg 2x';
    
    $varnish_caching = get_site_option(self::defaultPrefix . 'enable');    
    $varnish_caching_ttl = get_site_option('varnish_caching_ttl');
    
    if ($varnish_caching == "true"){
        $pc_checked = 'checked';
    }      
    
    $cdn_enabled = get_site_option('oc_cdn_enabled');

    $cdn_icon = $this->OCVCURI.'/assets/images/cdn.png';
    $cdn_icon_2x = $this->OCVCURI.'/assets/images/cdn@2x.png 2x';    
    $cdn_icon_active = $this->OCVCURI.'/assets/images/cdn-active@1x.png';
    $cdn_icon_2x_active = $this->OCVCURI.'/assets/images/cdn-active@2x.png 2x';
    
?>
<div id="onestaging-clonepage-wrapper">
    <!-- Page Header -->
    <div class="wrap onecom-staging-wrap">
        <div class="onecom-notifier"></div>
        <h2 class="one-logo">
            <div class="textleft">
                <span><?php _e('One.com performance tools', self::textDomain)?></span>
            </div>
            <div class="textright">
                <img src="<?php echo $this->OCVCURI.'/assets/images/one.com-logo@2x.svg' ?>" alt="one.com"
                    srcset="<?php echo $this->OCVCURI.'/assets/images/one.com-logo@2x.svg 2x' ?>" />
            </div>
        </h2>
        <div class="wrap_inner inner one_wrap">
            <div class="one-card one-card-performance">
                <div class="one-card-inline-block one-card-align-left onecom-staging-logo">
                    <img id="oc-performance-icon" width="130" height="130" src="<?php echo $performance_icon ?>" alt="one.com"
                        srcset="<?php echo $performance_icon_2x;?>" style="display: <?php echo $pc_checked === ''? 'inline':'none'?>;"/>
                        <img id="oc-performance-icon-active" src="<?php echo $performance_icon_active ?>" alt="one.com"
                        srcset="<?php echo $performance_icon_2x_active;?>" style="display: <?php echo $pc_checked === 'checked'? 'inline':'none'?>;"/>
                </div>
                <div class="one-card-inline-block one-card-align-left one-card-staging-content">
                    <div id="staging-create" class="one-card-staging-create card-1">
                        <div class="one-card-staging-create-info">
                            <h3 class="no-top-margin">
                                <?php _e('One.com Performance Cache improves your website\'s performance', self::textDomain);?>
                            </h3>
                            <?php _e('With One.com Performance Cache enabled your website loads a lot faster. We save a cached copy of your website on a Varnish server, that will then be served to your next visitors. <br/>This is especially useful if you have a lot of visitors. It may also help to improve your SEO ranking. If you would like to learn more, please read our help article: <a href="https://help.one.com/hc/en-us/articles/360000080458" target="_blank">How to use the One.com Performance Cache for WordPress</a>.', self::textDomain );?><br><br>
                            <label for="pc_enable" class="oc-label">
                                <span class="oc_cb_switch">
                                    <input type="checkbox" id="pc_enable" data-target="pc_enable_settings" name="show"
                                        value=1 <?php echo $pc_checked; ?> />
                                    <span class="oc_cb_slider" data-target="oc-performance-icon"
                                        data-target-input="pc_enable"></span>
                                </span>
                                <?php echo __("Enable Performance Cache", self::textDomain); ?>
                            </label><span id="oc_pc_switch_spinner" class="oc_cb_spinner spinner"></span> 
                            <div id="pc_enable_settings" style="display:<?php echo $pc_checked === 'checked'? 'block' : 'none'?>;">
                                <?php 
                                    // Get premium features
                                    $features = (array) oc_set_premi_flag(true);
                                    if(isset($features['data'])){$features = $features['data'];}
                                    
                                    // check if premium feature available, just in time.
                                    if($this->OCVer->isVer() && in_array("PERFORMANCE_CACHE", $features) ) : ?>
                                        <form method="post" action="options.php">
                                            <label class="oc_vcache_ttl_label"><?php _e('Cache TTL', self::textDomain)?></label><span class="tooltip"><span class="dashicons dashicons-editor-help"></span><span><?php echo __( 'The time that website data is stored in the Varnish cache. After the TTL expires the data will be updated, 0 means no caching.', self::textDomain )?></span></span>
                                            <div class="oc-input-wrap">
                                            <input type="text" name="oc_vcache_ttl" class="oc_vcache_ttl" id="oc_vcache_ttl" value="<?php echo $varnish_caching_ttl?>"/>
                                            <button type="button" id="oc_ttl_save" class="one-button btn button_1 oc_vcache_btn no-right-margin"><?php _e('Save', self::textDomain)?></button>
                                            <span id="oc_ttl_spinner" class="oc_cb_spinner spinner"></span>
                                            <p class="oc_vcache_decription"><?php _e('Time to live in seconds in Varnish cache', self::textDomain)?></p>
                                            </div>
                                            </form>
                                        <?php else : ?>
                                        <?php onecom_premium_theme_admin_notice(); ?>
                                        <?php (function_exists( 'onecom_generic_log')? onecom_generic_log( "wp_premium_click", "pcache"):''); ?>

                                        <?php endif; ?>
                            </div>
                            <?php /* ?><a href="https://help.one.com/hc/en-us/articles/360000020617" class="help_link pc_block"
                                target="_blank"><?php _e('Need help?',self::textDomain );?></a>
                            <br><?php */ ?>
                        </div>
                    </div>
                </div>
            </div>
            <div class="one-card one-card-cdn">
                <div class="one-card-inline-block one-card-align-left onecom-staging-logo">
                    <img id="oc-cdn-icon" src="<?php echo $cdn_icon ?>" alt="one.com"
                        srcset="<?php echo $cdn_icon_2x;?>" style="display: <?php echo $cdn_enabled != 'true' ? 'inline' : 'none'?>" />
                        <img id="oc-cdn-icon-active" src="<?php echo $cdn_icon_active?>" alt="one.com"
                        srcset="<?php echo $cdn_icon_2x_active;?>" style="display: <?php echo $cdn_enabled == 'true' ? 'inline' : 'none'?>"/>

                </div>
                <div class="one-card-inline-block one-card-align-left one-card-staging-content">
                    <div id="staging-create" class="one-card-staging-create card-1">
                        <div class="one-card-staging-create-info">
                            <h3 class="no-top-margin">
                                <?php _e('Speed up your website with fast content delivery network.', self::textDomain);?>
                            </h3>
                            <?php _e('A content delivery network is a system of distributed servers that deliver pages and other web content to a user, <br/>based on the geographic locations of the user, the origin of the webpage and the content delivery server. <br>This is especially useful if you have a lot of visitors spread across the globe.', self::textDomain );?><br><br>
                            <label for="cdn_enable" class="oc-label">
                                <span class="oc_cb_switch">
                                    <input type="checkbox" class="" id="cdn_enable" name="show" value=1
                                        <?php echo $cdn_enabled == 'true' ? 'checked' : ''?> />
                                    <span class="oc_cb_slider" data-target="oc-cdn-icon"></span>
                                </span>
                                <?php echo __("Enable CDN", self::textDomain); ?>
                            </label><span id="oc_cdn_switch_spinner" class="oc_cb_spinner spinner"></span>
                            <?php /* ?><br><br>
                            <a href="https://help.one.com/hc/en-us/articles/360000020617" class="help_link"
                                target="_blank"><?php _e('Need help?',self::textDomain );?></a>
                            <br><?php */ ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div id="onecom-staging-error-wrapper">
            <div id="onecom-staging-error-details"></div>
        </div>
    </div>
    <div class="clear"></div>
</div>