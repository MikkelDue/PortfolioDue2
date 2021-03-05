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
				<?php _e( 'Exclusive themes specially crafted for One.com customers.', OC_PLUGIN_DOMAIN ); ?>
			</span>
		</div>
		<div class="textright">
			<img src="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg' ?>" alt="One.com" srcset="<?php echo ONECOM_WP_URL.'/assets/images/one.com-logo@2x.svg 2x' ?>" />
		</div>
	</h2>
	
	<div class="wrap_inner inner one_wrap">
		
		<div id="free" class="active-tab">

			 <div class="theme-filters">		
				 	<div class="oc_select_wrapper">
					 	<span><?php echo __('All', OC_PLUGIN_DOMAIN)?></span>
						<select id="oc_theme_filter_select" class="oc_theme_filter_select">
							<option value="all" class="oc-active-filter"><?php _e( 'All', OC_PLUGIN_DOMAIN); ?></option>
							<option value="blogging" class="oc-active-filter"><?php _e( 'Blog', OC_PLUGIN_DOMAIN); ?></option>
							<option value="business-services"><?php _e( 'Business & Services', OC_PLUGIN_DOMAIN); ?></option>
							<option value="events"><?php _e( 'Events', OC_PLUGIN_DOMAIN); ?></option>
							<option value="family-recreation"><?php _e( 'Family & Recreation', OC_PLUGIN_DOMAIN); ?></option>
							<option value="food-hospitality"><?php _e( 'Food & Hospitality', OC_PLUGIN_DOMAIN); ?></option>
							<option value="music-art"><?php _e( 'Music & Art', OC_PLUGIN_DOMAIN); ?></option>
							<option value="online-shop"><?php _e( 'Online Shop', OC_PLUGIN_DOMAIN); ?></option>
							<option value="portfolio-cv"><?php _e( 'Portfolio & CV', OC_PLUGIN_DOMAIN); ?></option>
							<option value="premium"><?php _e( 'Premium', OC_PLUGIN_DOMAIN); ?></option>
						</select>
				 	</div>
				<ul id="oc_theme_filter" class="oc_theme_filter">
					<li data-filter-key="all" class="oc-active-filter"><?php _e( 'All', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="blogging"><?php _e( 'Blog', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="business-services"><?php _e( 'Business & Services', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="events"><?php _e( 'Events', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="family-recreation"><?php _e( 'Family & Recreation', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="food-hospitality"><?php _e( 'Food & Hospitality', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="music-art"><?php _e( 'Music & Art', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="online-shop"><?php _e( 'Online Shop', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="portfolio-cv"><?php _e( 'Portfolio & CV', OC_PLUGIN_DOMAIN); ?></li>
					<li data-filter-key="premium" class="oc-premium-filter"><em class="inline_icon" style="background:url('data:image/svg+xml;base64,PHN2ZyBzdHlsZT0iZmlsbDojOTUyNjVFOyIgd2lkdGg9IjkiIGhlaWdodD0iMTQiIHZpZXdCb3g9IjAgMCA5IDE0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik0xLjQ5IDBoNi4wMTdsLTIgNC44NzNMOSA0Ljg2NSAyLjE0MiAxNGwxLjYzLTYuNzIzTDAgNy4yNzR6IiBmaWxsLXJ1bGU9ImV2ZW5vZGQiLz48L3N2Zz4=');height: 13.5px;display: inline-block;vertical-align: -2px;background-repeat: no-repeat;width: 9px;"></em> <?php _e( 'Premium', OC_PLUGIN_DOMAIN); ?></li>
				</ul>				
				
			</div>  <!-- theme-filters -->

			<?php 
				$requsted_paged = ( isset( $_GET[ 'paged' ] ) ) ? ( int ) $_GET[ 'paged' ] : 1;
				global $theme_data; 
				$theme_data = onecom_fetch_themes( $page = $requsted_paged, $exclude_ilotheme = true );
				$config = onecom_themes_listing_config();

			?>

			<div class="theme-browser" data-total_themes="<?php echo $config[ 'total' ]; ?>" data-item_count="<?php echo $config[ 'item_count' ]; ?>">
				<?php 
					load_template( dirname( __FILE__ ) . '/theme-listing-loop.php' ); 
				?>
			</div> <!-- theme-browser -->

			<div class="loading-overlay theme-loader">
				<div class="loading-overlay-content">
					<div class="loader"></div>
				</div>
			</div><!-- loader -->
			
			<?php onecom_themes_listing_pagination( $config, $requsted_paged ); ?>

		</div> <!-- tab -->

	</div> <!-- wrap_inner -->
</div> <!-- wrap -->

<?php add_thickbox(); ?> 

<div id="thickbox_preview" style="display:none">
   <div id="preview_box">
       <div class="one-theme-listing-bar">
           <span class="dashicons dashicons-wordpress-alt"></span>
       </div>
       <div class="header_btn_bar">
           <div class="left-header">
               <a href="javascript:void(0)" class="close_btn"><?php _e( 'Back to themes', OC_PLUGIN_DOMAIN); ?></a>
               <div class="btn btn_arrow previous" data-demo-id=""><span class="dashicons dashicons-arrow-left-alt2"></span></div>
               <span data-theme-count="" data-active-demo-id="" class="theme-info hide"></span>
			   <div class="btn btn_arrow next" data-demo-id=""><span class="dashicons dashicons-arrow-right-alt2"></span></div>
			   
			   <?php echo apply_filters('oc_preview_install', '<a href="javascript:void(0)" class="btn button_1 preview-install-button" data-active-demo-id="">'.__( 'Install', OC_PLUGIN_DOMAIN).'</a>', '', 'ptheme'); ?>
           </div>
           <div class="right-header">
               <div class="btn button_2 current" id="desktop"> <span class="dashicons dashicons-desktop"></span> <?php _e( 'Desktop', OC_PLUGIN_DOMAIN); ?></div>
               <div class="btn button_2" id="mobile"> <span class="dashicons dashicons-smartphone"></span> <?php _e( 'Mobile', OC_PLUGIN_DOMAIN); ?></div>
         </div>
       </div>
       
       <span class="divider_shadow" > </span>

       <div class="preview-container">
             <div class="desktop-content text-center preview">
                 <iframe src='#' title="Preview"></iframe>
             </div>
       </div>
   </div>
</div>   

<span class="dashicons dashicons-arrow-up-alt onecom-move-up"></span>