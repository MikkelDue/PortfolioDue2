<div class="wrap onecom-staging-wrap">
    <div class="onecom-notifier"></div>
    <h2 class="one-logo">
        <div class="textleft">
            <span>
                <?php _e( 'One Staging', OC_PLUGIN_DOMAIN ); ?>
                <?php if (isset($is_staging) && (bool) $is_staging === true): ?>
	                <span class="one-entry-flag one-entry-live" title="<?php _e( 'This is your Staging site.', OC_PLUGIN_DOMAIN ); ?>">STAGING</span>
                <?php endif; ?>
			</span>
        </div>
        <div class="textright topRightLogo">
            <img src="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg' ?>" alt="one.com" srcset="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg' ?>" />
        </div>
    </h2>