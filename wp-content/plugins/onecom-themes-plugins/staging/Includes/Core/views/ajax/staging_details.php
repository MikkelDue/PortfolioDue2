        <!--Staging entry box-->
        <div id="staging_entry">
            <div class="one-staging-details card-2">
                <div class="one-staging-site-info box">

                    <?php
                    if(!empty($clones)):
                        foreach ($clones as $key=>$clone): ?>
                            <div class="one-staging-entry staging-entry" id="entry_<?php echo $key; ?>" data-staging-id="<?php echo $key; ?>">
                                <div class="entry-name">

                                    <?php if($cloneExists): ?>
                                        <h3><?php _e( 'Your staging site', OC_PLUGIN_DOMAIN ); ?></h3>
                                    <?php else: ?>
                                        <h3><?php _e( 'Staging site broken', OC_PLUGIN_DOMAIN ); ?></h3>
                                    <?php endif; ?>

                                    <?php if($cloneExists): ?>
                                       <div class="entry-link stg_info">
                                            <p>
                                            <span><?php _e( 'Staging Frontend:', OC_PLUGIN_DOMAIN ); ?> <a href="<?php echo $clone['url']; ?>" target="_blank"><?php echo $clone['url']; ?></a></span>
                                            <br><span><?php _e( 'Staging Backend:', OC_PLUGIN_DOMAIN ); ?> <a href="<?php echo trailingslashit($clone['url']); ?>wp-login.php" target="_blank"><?php echo trailingslashit($clone['url']); ?>wp-login.php</a></span>
                                            </p>
                                       </div>
                                    <?php else: ?>
                                        <div>
                                            <p><?php _e('We have detected that your staging site is broken due to missing database table(s) and/or directory(s).', OC_PLUGIN_DOMAIN ); ?><br>
                                               <?php _e('Click on "Rebuild Staging" to regenerate your staging site.', OC_PLUGIN_DOMAIN ); ?></p>
                                        </div>
                                    <?php endif; ?>

                                </div>
                            </div>
                        <?php break;
                        endforeach;
                    endif;
                    ?>
                </div>
            </div>

            <div class="one-staging-actions card-3">
	            <?php if(isset($cloneExists) && $cloneExists): ?>
                    <p><?php _e( 'The staging website is a copy of your live website, where you can test new plugins and themes without affecting your live website.', OC_PLUGIN_DOMAIN ); ?> <br>
                        <?php _e( 'Only one staging version can be created for each website. When you rebuild a staging website, any existing staging site will be replaced with a new snapshot of your live website.', OC_PLUGIN_DOMAIN ); ?><br>
                        <?php _e( 'The login details for the staging backend are the same as for the live website.', OC_PLUGIN_DOMAIN ); ?><br><br>

                        <?php _e( 'Caution: Rebuilding will overwrite all files and the database of your existing staging website.', OC_PLUGIN_DOMAIN ); ?>
                    </p>
	            <?php endif; ?>
                <a href="<?php echo onecom_generic_locale_link( $request = 'staging_guide', get_locale() ); ?>" target="_blank" class="help_link"><?php _e( 'Need help?', OC_PLUGIN_DOMAIN ); ?></a>
                <br><br>
                <?php 
                echo $rebuild_btn = '<button class="one-button btn button_1 one-button-update-staging" data-staging-id="" data-dialog-id="staging-update-confirmation" data-title="'.__( 'Are you sure?', OC_PLUGIN_DOMAIN ).'" data-width="450" data-height="195">'. __( 'Rebuild Staging', OC_PLUGIN_DOMAIN ).'</button>';

                //echo apply_filters('oc_staging_button_rebuild', $rebuild_btn);
                
                $delete_btn = '<a href="javascript:;" class="staging-trash one-button-delete-staging"  title="'. __("Delete Staging", "onecom-wp").'" data-title="'.__( 'Are you sure?', OC_PLUGIN_DOMAIN ).'" data-dialog-id="staging-delete" data-width="450" data-height="155"><span class="dashicons dashicons-trash"></span> '.__("Delete Staging", "onecom-wp").'</a>';
                
                echo apply_filters('oc_staging_button_delete', $delete_btn, __("Premium feature", "onecom-wp"), 'stg');
                ?>
            </div>
        </div>