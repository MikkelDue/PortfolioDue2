<div class="wrap">
	<div class="loading-overlay fullscreen-loader">
		<div class="loading-overlay-content">
			<div class="loader"></div>
		</div>
	</div><!-- loader -->
	<div class="onecom-notifier"></div>

	<h2 class="one-logo"> 
		<div class="textleft">
			<span>
				<?php _e( 'Plugins that bring the One.com experience and services to WordPress.', OC_PLUGIN_DOMAIN ); ?>
			</span>
		</div>
		<div class="textright">
			<img src="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg' ?>" alt="one.com" srcset="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg 2x' ?>" />
		</div>
	</h2>

	<div class="wrap_inner inner one_wrap">
		<div class="nav-tab-wrapper">
			<a href="<?php echo network_admin_url( 'admin.php?page=onecom-wp-plugins' ); ?>" class="nav-tab nav-tab-active"><?php _e( 'One.com plugins', OC_PLUGIN_DOMAIN ); ?></a>
			<a href="<?php echo network_admin_url( 'admin.php?page=onecom-wp-recommended-plugins' ); ?>" class="nav-tab"><?php _e( 'Recommended plugins', OC_PLUGIN_DOMAIN ); ?></a>
			<a href="<?php echo network_admin_url( 'admin.php?page=onecom-wp-discouraged-plugins' ); ?>" class="nav-tab"><?php _e( 'Discouraged plugins', OC_PLUGIN_DOMAIN ); ?></a>

		</div>
		<div id="free" class="tab active-tab">



			<div class="plugin-browser widefat">

				<?php $plugins = onecom_fetch_plugins(); ?>

				<?php if( is_wp_error( $plugins ) ) : ?>
					<?php echo $plugins->get_error_message(); ?>
				<?php else : ?>
					<?php foreach( $plugins as $key => $plugin ) : ?>
						<?php
							$plugin_installed = $plugin_activated = false;
							if ( is_dir( WP_PLUGIN_DIR . '/' . $plugin->slug ) ) {
								$plugin_installed = true;

								$plugin_infos = get_plugins( '/'.$plugin->slug );
								if( ! empty( $plugin_infos ) ) {
									foreach ($plugin_infos as $file => $info) :
										$is_activate = is_plugin_active_for_network( $plugin->slug.'/'.$file );
										if ( $is_activate  ) {
											$plugin_activated = true;
										} else {
											$activateUrl = add_query_arg( array(
												'_wpnonce' => wp_create_nonce( 'activate-plugin_' . $plugin->slug.'/'.$file ),
												'action'   => 'activate',
												'plugin'   => $plugin->slug.'/'.$file,
											), network_admin_url( 'plugins.php' ) );
										}
									endforeach;
								}
							}
						?>
						<div class="one-plugin-card <?php echo ( count( $plugins )  == 1 ) ? 'single-plugin' : ''; ?> <?php echo ( $plugin_installed ) ? 'installed' : ''; ?>">
							<div class="plugin-card-top">
								<div class="name column-name">
									<h3>
										<?php echo $plugin->name; ?>
										<?php 
											$thumbnail_url = $plugin->thumbnail;
										?>
											<span class="plugin-icon-wrapper icon-available">
												<span class="plugin-icon-wrapper-inner"><img src="<?php echo $thumbnail_url; ?>" alt="<?php echo $plugin->name; ?>" /></span>
											</span>
									</h3>
								</div>
								<div class="action-links">
									<ul class="plugin-action-buttons">
										<li>
											<?php if( $plugin_installed && $plugin_activated ) : ?>
												<a class="installed-plugin button" href="javascript:void(0)" data-slug="<?php echo $plugin->slug; ?>" data-name="<?php echo $plugin->name ?>" disabled="true" ><?php _e( 'Active', OC_PLUGIN_DOMAIN ); ?></a>
											<?php elseif ( $plugin_installed && ( ! $plugin_activated ) ) : ?>
												<?php if( ( ! isset( $plugin->redirect ) ) || $plugin->redirect != '' ) : ?>
													<a class="activate-plugin activate-plugin-ajax button button-primary" href="javascript:void(0)" data-action="onecom_activate_plugin" data-redirect="<?php echo $plugin->redirect; ?>" data-slug="<?php echo $plugin->slug.'/'.$file; ?>" data-name="<?php echo $plugin->name ?>"><?php _e( 'Activate', OC_PLUGIN_DOMAIN ); ?></a>
												<?php else : ?>
													<a class="activate-plugin button button-primary" href="<?php echo $activateUrl ?>"><?php _e( 'Activate', OC_PLUGIN_DOMAIN ); ?></a>
												<?php endif; ?>
											<?php else : ?>
												<a class="install-now button" href="javascript:void(0)" data-slug="<?php echo $plugin->slug; ?>" data-name="<?php echo $plugin->name ?>" aria-label="Install <?php echo $plugin->name ?> now" data-action="onecom_install_plugin" data-redirect="<?php echo $plugin->redirect; ?>" data-plugin_type="<?php echo $plugin->type; ?>"><?php _e( 'Install now', OC_PLUGIN_DOMAIN ); ?></a>
											<?php endif; ?>
										</li>

									</ul>
								</div>
								<div class="desc column-description">
									<p><?php echo $plugin->description; ?></p>
								</div>
							</div>
						</div> <!-- one-plugin-card -->
					<?php endforeach; ?>
				<?php endif; ?>

			</div> <!-- plugin-browser -->
		</div> <!-- tab -->

	</div> <!-- wrap_inner -->
</div> <!-- wrap -->
<?php add_thickbox(); ?> 

<span class="dashicons dashicons-arrow-up-alt onecom-move-up"></span>