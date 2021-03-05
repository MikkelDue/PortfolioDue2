<?php

class OneCom_File_Security {
	private $ht_file;
	public $text_domain = OC_PLUGIN_DOMAIN;

	public function __construct() {
		add_action( 'wp_ajax_oc_save_ht', array( $this, 'oc_save_ht_cb' ) );
		$uploads       = wp_upload_dir();
		$this->ht_file = $uploads['basedir'] . DIRECTORY_SEPARATOR . '.htaccess';
	}

	public function get_default_file_types() {

		$default_file_types = [
			'js',
			'php',
			'phtml',
			'php3',
			'php4',
			'php5',
			'pl',
			'py',
			'jsp',
			'asp',
			'html',
			'htm',
			'shtml',
			'sh',
			'cgi',
			'suspected'
		];
		$file_extensions    = $this->get_htaccess_extensions();
		$extensions_merged  = array_unique( array_merge( $default_file_types, $file_extensions ) );
		sort( $extensions_merged );

		return $extensions_merged;
	}

	public function get_htaccess() {
		if ( ! file_exists( $this->ht_file ) ) {
			return false;
		}

		return trim( file_get_contents( $this->ht_file ) );
	}

	private function get_file_pattern() {
		$ht_content = $this->get_htaccess();
		if ( ! $ht_content ) {
			return false;
		}
		$exploded_file_content = explode( "\n", $ht_content );
		if ( ! $exploded_file_content ) {
			return false;
		}
		$start_string = '<FilesMatch "\.(';
		$files_string = '';
		foreach ( $exploded_file_content as $line ) {
			if ( strpos( $line, '<FilesMatch "\.(' ) === 0 ) {
				$files_string = str_replace( [ '<FilesMatch "\.(', ')$">' ], '', $line );
			}
		}

		return $files_string;
	}

	public function get_htaccess_extensions() {

		$files_string = $this->get_file_pattern();
		if ( ! $files_string ) {
			return [];
		}
		$file_extensions = explode( '|', $files_string );

		return $file_extensions;
	}

	public function oc_save_ht_cb() {
		check_ajax_referer( HT_NONCE_STRING );
		$content      = base64_decode( $_POST['content'] );
		$file_content = '';
		if ( $_POST['manual_edit'] === 'true' ) {
			$file_content = $content;
		} else {
			$file_string           = implode( '|', $_POST['extensions'] );
			$original_file_string  = $this->get_file_pattern();
			$original_file_content = base64_decode( $_POST['original_file_content'] );
			$file_content          = str_replace( $original_file_string, $file_string, $original_file_content );
			$file_content_array    = explode( "\n", $file_content );
			$vc_index              = array_search( '# Block javascript except for visualcomposer (VC) plugin', $file_content_array );
			if ($vc_index){
				for ( $i = $vc_index; $i < ( $vc_index + 4 ); $i ++ ) {
					if ( strpos( $file_content_array[ $i ], '#' ) !== 0 ) {
						$file_content_array[ $i ] = '# ' . $file_content_array[ $i ];
					}
				}
			}

			$file_content = implode( "\n", $file_content_array );
		}
		if ( ! is_writeable( $this->ht_file ) ) {
			$file_path = str_replace(ABSPATH, '', $this->ht_file);
			wp_send_json( [
				'status'           => 'write_error',
				'new_file_content' => base64_encode( $file_content ),
				'message'          => sprintf( __( 'The htaccess file could not be updated. Please paste the above code manually in the file %s', OC_PLUGIN_DOMAIN )
					, '<br/><code class="oc-filename">'.$file_path.'</code>' )
			] );

			return;
		}
		if ( file_put_contents( $this->ht_file, $file_content ) ) {
			wp_send_json( [
				'status'           => 'success',
				'new_file_content' => base64_encode( $file_content ),
				'message'          => __( 'Changes saved.', OC_PLUGIN_DOMAIN )
			] );
		} else {
			echo - 1;
			wp_die();
		}
	}

	public function check_js_block() {
		$file_content_arr = explode( "\n", $this->get_htaccess() );
		$js_string        = 'RewriteRule ^(.*\.js)$ - [F,L]';

		return in_array( $js_string, $file_content_arr );
	}
}