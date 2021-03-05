<div class="wrap">
	<div class="loading-overlay">
		<div class="loading-overlay-content">
			<div class="loader"></div>
		</div>
	</div><!-- loader -->
	<div class="onecom-notifier"></div>

	<h2 class="one-logo"> 
		<div class="textleft">
			<span>
				<?php _e( 'Discouraged plugins', OC_PLUGIN_DOMAIN ); ?>
			</span>
		</div>
		<div class="textright">
			<img src="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg' ?>" alt="one.com" srcset="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg 2x' ?>" />
		</div>
	</h2>

	<div class="wrap_inner inner one_wrap">
		<div class="nav-tab-wrapper">
			<a href="<?php echo admin_url( 'admin.php?page=onecom-wp-plugins' ); ?>" class="nav-tab"><?php _e( 'One.com plugins', OC_PLUGIN_DOMAIN ); ?></a>
		    <a href="<?php echo admin_url( 'admin.php?page=onecom-wp-recommended-plugins' ); ?>" class="nav-tab"><?php _e( 'Recommended plugins', OC_PLUGIN_DOMAIN ); ?></a>
		    <a href="<?php echo admin_url( 'admin.php?page=onecom-wp-discouraged-plugins' ); ?>" class="nav-tab nav-tab-active"><?php _e( 'Discouraged plugins', OC_PLUGIN_DOMAIN ); ?></a>

		</div>
		<?php 
			$plugins = onecom_fetch_plugins( $recommended = false, $discouraged = true );
		
			if( ! is_wp_error( $plugins ) && ! empty( $plugins ) ) :
				foreach ( $plugins as $key => $plugin ) :
					if( ! is_dir( WP_PLUGIN_DIR . '/' . $plugin->slug ) ) {
						unset( $plugins[ $key ] );
						continue;
					}
					$plugin_infos = get_plugins( '/'.$plugin->slug );
					$plugin_activated = false;
					if( ! empty( $plugin_infos ) ) {
						foreach ( $plugin_infos as $file => $info ) :
							$is_inactivate = is_plugin_inactive( $plugin->slug.'/'.$file );
							if ( !$is_inactivate ) {
								$plugin_activated = true;
								$plugins[ $key ]->file = $file;
							}
						endforeach;
					}
					if( !$plugin_activated ) {
						unset( $plugins[ $key ] );
					}
				endforeach;
			endif;
		?>
		<div id="discouraged" class="tab active-tab">
			<div class="tab-description">
				<?php if( empty( $plugins ) ) : ?>
					<?php _e( 'You are doing great! None of your installed plugins, are on our list of discouraged plugins.', OC_PLUGIN_DOMAIN ); ?>
				<?php else : ?>
					<?php _e ( 'Your WordPress site should work the best possible way. We checked the plugins on your website, and listed those we don\'t recommended you to use.', OC_PLUGIN_DOMAIN ); ?><br/><?php _e ( 'There are also some suggestions for alternative plugins to use instead.', OC_PLUGIN_DOMAIN ); ?>
				<?php endif; ?>
				<div class="discouraged-list-button-wrapper">
					<a href="<?php echo onecom_generic_locale_link( $request = 'discouraged_guide', get_locale() ) ?>" target="_blank"><?php _e( 'View full list of discouraged plugins', OC_PLUGIN_DOMAIN ); ?></a>
				</div>
			</div>
			<div class="plugin-browser widefat">
				<?php if( ! is_wp_error( $plugins ) ) : ?>
					<?php foreach ( $plugins as $key => $plugin ) : ?>
						<div class="one-plugin-card">
							<div class="plugin-card-top">
								<h3>
									<span class="discouraged-plugin-name">
										<?php echo esc_html( $plugin->name ); ?> 
									</span>
									<span class="discouraged-plugin-action">
										<form method="post" action="">
											<input type="hidden" name="plugin" value="<?php echo $plugin->slug.'/'.$plugin->file; ?>" />
											<input type="hidden" name="action" value="deactivate_plugin" />
											<input type="submit" name="one-deactivate-plugin" value="<?php _e( 'Deactivate', OC_PLUGIN_DOMAIN ); ?>" class="button button-primary one-deactivate-plugin" />
										</form>
									</span>
								</h3>
								<div class="column-description">
									<?php echo esc_html( $plugin->reason ); ?>
								</div>
                            </div>
						</div><!-- -->
					<?php endforeach; ?>
				<?php else : ?>
						<strong><?php echo $plugins->get_error_message(); ?></strong>
				<?php endif; ?>
			</div> <!-- plugin-browser -->
		</div> <!-- tab -->

	</div> <!-- wrap_inner -->
</div> <!-- wrap -->
<div id="one-confirmation" class="hide" data-yes_string="<?php _e( 'Yes, deactivate plugin', OC_PLUGIN_DOMAIN ); ?>" data-no_string="<?php _e( 'Not right now', OC_PLUGIN_DOMAIN ); ?>">
	<div class="plugin-card-top">
		<strong><?php _e( 'Are you sure that you want to deactivate this plugin?', OC_PLUGIN_DOMAIN ); ?></strong>
		<div class="discouraged-list-button-wrapper" style="display: none">
			<?php _e( 'Deactivating a plugin can break functionality on your website.', OC_PLUGIN_DOMAIN ); ?>
		</div>
	</div>
	<span class="dashicons dashicons-no-alt discouraged-modal-close"></span>
</div>