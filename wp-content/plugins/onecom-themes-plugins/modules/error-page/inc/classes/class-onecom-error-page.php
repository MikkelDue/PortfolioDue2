<?php

class Onecom_Error_Page {
	private $error_class_path = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'fatal-error-handler.php';
	private $local_class_path = ONECOM_WP_PATH . 'modules' . DIRECTORY_SEPARATOR . 'error-page' . DIRECTORY_SEPARATOR . 'inc' . DIRECTORY_SEPARATOR . 'classes' . DIRECTORY_SEPARATOR . 'fatal-error-handler.php';

	public function __construct() {
		if ( ! defined( 'OC_TEXTDOMAIN' ) ) {
			define( 'OC_TEXTDOMAIN', OC_PLUGIN_DOMAIN );
		}
		add_action( 'admin_menu', [ $this, 'menu_pages' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
		add_action( 'wp_ajax_onecom-error-pages', [ $this, 'configure_feature' ] );
	}

	public function menu_pages() {
		add_submenu_page(
			OC_TEXTDOMAIN,
			__( 'Error page', OC_TEXTDOMAIN ),
            '<span id="onecom_errorpage">'.__( 'Error page', OC_TEXTDOMAIN ).'</span>',
			'manage_options',
			'onecom-wp-error-page',
			[ $this, 'error_page_callback' ]
		);
	}

	public function enqueue_scripts( $hook_suffix ) {
		if ( $hook_suffix !== '_page_onecom-wp-error-page' ) {
			return;
		}
		$extenstion = '';
		wp_enqueue_script( 'onecom-error-page', ONECOM_WP_URL . '/modules/error-page/assets/js/error-page' . $extenstion . '.js', [ 'jquery' ], null, true );
		wp_enqueue_style( 'onecom-error-page-css', ONECOM_WP_URL . '/modules/error-page/assets/css/error-page' . $extenstion . '.css', null );
	}

	public function error_page_callback() {
		$checked = ( file_exists( $this->error_class_path ) && $this->is_onecom_plugin() ) ? 'checked' : ''
		?>
        <div class="wrap">
            <h2 class="one-logo">
                <div class="textleft"><span><?php echo __( "Error page", OC_TEXTDOMAIN ); ?></span></div>
                <div class="textright">
                    <img src="<?php echo ONECOM_WP_URL . '/assets/images/one.com-logo@2x.svg' ?>" alt="one.com"
                         srcset="<?php echo ONECOM_WP_URL . '/assets/images/one.com-logo@2x.svg 2x' ?>"/>
                </div>
            </h2>
            <div class="wrap_inner inner one_wrap oc_card">
                <div class="card-right">
                    <div id="onecom-error-preview"
                         class="<?php echo ( $checked != '' ) ? 'onecom-error-extended' : '' ?>"></div>
                </div>
                <div class="card-left">
                    <form class="onecom_ep_form">
                        <div class="fieldset">
                            <label for="onecom_ep_enable">
                        <span class="oc_cb_switch">
                            <input type="checkbox" class="" id="onecom_ep_enable" <?php echo $checked ?> name="show"
                                   value=1/>
                            <span class="oc_cb_slider"></span>
                        </span> <?php echo __( "Enable tips on error page:", "onecom-wp" ); ?>
                            </label><span class="components-spinner"></span>
                            <p class="oc_desc indent" id="onecom-status-message"></p>
                            <p class="oc_desc indent"><?php echo __( "Display useful information if there is a problem on your site. This information will be visible only to the admin users.", "onecom-wp" ); ?></p>
                        </div>
                        <span class="oc_gap"></span>
                    </form>
                </div>
            </div>
        </div>
	<?php }

	public function configure_feature() {
		$action = filter_var( $_POST['type'], FILTER_SANITIZE_STRING );
		//check if there is an existing file, owned by one.com. If no, bail out
		if ( ! $this->is_onecom_plugin() ) {
			wp_send_json( [
				'status'  => 'failed',
				'message' => __( 'Failed to save settings. Please reload the page and try again.' )
			] );

			return;
		}
		if ( $action === 'enable' ) {
			$response = $this->enable_feature();
		} else {
			$response = $this->disable_feature();
		}
		wp_send_json( $response );
	}

	public function enable_feature() {

		if ( file_exists( $this->error_class_path ) && ( ! $this->is_onecom_plugin() ) ) {
			return [
				'status'  => 'failed',
				'message' => __( 'An error handler is already present!', OC_TEXTDOMAIN )
			];
		}

		if ( copy( $this->local_class_path, $this->error_class_path ) ) {
			$response = [
				'status'  => 'success',
				'message' => __( 'Error page enabled', OC_TEXTDOMAIN )
			];
		} else {
			$response = [
				'status'  => 'failed',
				'message' => __( 'Error page could not be enabled', OC_TEXTDOMAIN )
			];
		}

		return $response;
	}

	public function disable_feature() {
		if ( ! file_exists( $this->error_class_path ) ) {
			return [
				'status'  => 'failed',
				'message' => __( 'No active error pages found', OC_TEXTDOMAIN )
			];
		}
		if ( unlink( $this->error_class_path ) ) {
			$response = [
				'status'  => 'success',
				'message' => __( 'Error page disabled', OC_TEXTDOMAIN )
			];
		} else {
			$response = [
				'status'  => 'failed',
				'message' => __( 'Error page could not be disabled', OC_TEXTDOMAIN )
			];
		}

		wp_send_json( $response );
	}

	public function is_onecom_plugin() {
		if ( ! file_exists( $this->error_class_path ) ) {
			return true;
		}
		$data = get_plugin_data( $this->error_class_path );
		if ( isset( $data['AuthorName'] ) && ( $data['AuthorName'] === 'one.com' ) ) {
			return true;
		}

		return false;
	}
}