<div class="wrap">
    <div class="loading-overlay fullscreen-loader">
        <div class="loading-overlay-content">
            <div class="loader"></div>
        </div>
    </div>
    <div class="onecom-notifier"></div>
    <h2 class="one-logo ocsh-logo">
        <div class="textleft">
            <span id="ocsh-site-security">
                <?php _e( 'Health Monitor', OC_PLUGIN_DOMAIN ); ?> <span class="components-spinner"></span>
            </span>
            <p class="ocsh-page-desc">
				<?php echo __( 'Health Monitor lets you monitor the essential security checkpoints and fix them if needed.', OC_PLUGIN_DOMAIN ) ?>
            </p>
        </div>
        <div class="textright">
            <img src="<?php echo ONECOM_WP_URL . '/assets/images/one.com-logo@2x.svg' ?>" alt="one.com"
                 srcset="<?php echo ONECOM_WP_URL . '/assets/images/one.com-logo@2x.svg 2x' ?>"/>
        </div>
    </h2>
    <div class="inner one_wrap">
        <div class="wrap_inner">
            <ul class="hidden ocsh-scan-result">
                <li id='ocsh-updates' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'PHP version', OC_PLUGIN_DOMAIN ) ?></h4> <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-plugin-updates' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'Plugins', OC_PLUGIN_DOMAIN ) ?></h4> <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-theme-updates' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'Themes', OC_PLUGIN_DOMAIN ) ?></h4> <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-wp-updates' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'WordPress version', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-wp-org-comm' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'Connection to Wordpress.org', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-core-updates' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'WordPress core updates', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-ssl' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'SSL certificate', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-file-execution' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'File execution in uploads', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-file-permissions' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'WP file directory and files permissions', OC_PLUGIN_DOMAIN ) ?>
                    </h4> <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-db' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'Database security', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-file-edit' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'File editing from admin', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-usernames' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'Insecure usernames', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
                <li id='ocsh-discouraged-plugins' class='ocsh-bullet'>
                    <h4 class="ocsh-scan-title"><?php echo __( 'Using discouraged plugins', OC_PLUGIN_DOMAIN ) ?></h4>
                    <span></span>
                    <div class="osch-desc hidden"></div>
                </li>
            </ul>
            <ul id="ocsh-needs-attention" class="ocsh-scan-result">
				<?php
				$debug_result = oc_sh_check_debug_mode();
				if ( isset( $debug_result['status'] ) && $debug_result['status'] == OC_OPEN ): ?>
                    <li id="ocsh-err-reporting" class='ocsh-bullet'>
                        <h4 class="ocsh-scan-title"><?php echo __( 'Debug mode/Error reporting', OC_PLUGIN_DOMAIN ) ?></h4>
                        <span
                                class="ocsh-error"></span>
                        <div class="osch-desc hidden">
							<?php
							$guide_link = sprintf( "<a href='https://help.one.com/hc/%s/articles/115005593705-How-do-I-enable-error-messages-for-PHP-' target='_blank'>", onecom_generic_locale_link( '', get_locale(), 1 ) );

							$guide_link2 = sprintf( "<a href='https://help.one.com/hc/%s/articles/115005594045-How-do-I-enable-debugging-in-WordPress-' target='_blank'>", onecom_generic_locale_link( '', get_locale(), 1 ) );

							echo sprintf( __( 'You can disable PHP error reporting in the One.com control panel and WordPress debugging in the wp.config.php file. Check these two guides for more details on how to manage these settings: %sHow do I enable error messages for PHP?%s and %sHow do I enable debugging in WordPress?%s', OC_PLUGIN_DOMAIN ), $guide_link, "</a>", $guide_link2, "</a>" );
							?>
                        </div>
                    </li>
				<?php endif; ?>
            </ul>
            <div class="ocsh-separator hidden"></div>
            <ul id="ocsh-all-ok" class="ocsh-scan-result">
				<?php if ( isset( $debug_result['status'] ) && $debug_result['status'] == OC_RESOLVED ): ?>
                    <li id="ocsh-err-reporting" class='ocsh-bullet'>
                        <h4 class="ocsh-scan-title"><?php echo __( 'This is configured properly!', OC_PLUGIN_DOMAIN ) ?></h4>
                        <span class="ocsh-success"></span>
                        <div class="osch-desc hidden"><?php echo @$debug_result['desc'] ?></div>
                    </li>
				<?php endif; ?>
            </ul>
        </div>
	    <?php include __DIR__ . DIRECTORY_SEPARATOR . 'uploads-security.php';?>
    </div>
</div>