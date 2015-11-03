<?php

if (!function_exists( 'is_admin' ) ) {
    header( 'Status: 403 Forbidden' );
    header( 'HTTP/1.1 403 Forbidden' );
    exit();
}

if (!class_exists("Pareto_Security_Settings") ) :

class Pareto_Security_Settings {

	public static $default_settings = 
		array( 	
			  	'perm_ban_ips' => '0',
				'set_open_basedir' => '0'
				);
	var $pagehook, $page_id, $settings_field, $options, $set_open_basedir, $ban_ips;
	
	function __construct() {	
		$this->page_id = 'pareto_security_settings';
		// This is the get_options slug used in the database to store our plugin option values.
		$this->settings_field = 'pareto_security_settings_options';
		$this->options = get_option( $this->settings_field );

		if ( $_SERVER[ 'REQUEST_METHOD' ] == 'POST' ) {
			foreach( $_POST as $key => $val ) {
					if ( is_array( $val ) ) {
						if ( isset( $_POST[ "pareto_security_settings_options" ]["set_open_basedir" ] ) &&
							 ( ( strlen( $_POST[ "pareto_security_settings_options" ]["set_open_basedir" ] ) > 1 ) ) ) {
							     $_POST[ "pareto_security_settings_options" ]["set_open_basedir" ] = 0;
						}
						if ( isset( $_POST[ "pareto_security_settings_options" ]["perm_ban_ips" ] ) &&
							 ( ( strlen( $_POST[ "pareto_security_settings_options" ]["perm_ban_ips" ] ) > 1 ) ) ) {
							   $_POST[ "pareto_security_settings_options" ]["perm_ban_ips" ] = 0;
						}

					}
			}
		}

		$this->ban_ips = isset( $this->options[ 'perm_ban_ips' ] ) ? $this->options[ 'perm_ban_ips' ]:0;
		$this->set_open_basedir = isset( $this->options[ 'set_open_basedir' ] ) ? $this->options[ 'set_open_basedir' ]:0;
		
		if ( ( false !== ( bool )defined( 'WP_ADMIN' ) &&
			   false !== WP_ADMIN ) &&
			   false !== ( bool)is_admin() ) {
			   if ( false !== strpos( $_SERVER[ 'REQUEST_URI' ], 'options' ) ) add_action( 'admin_init', array( $this,'admin_init' ), 20 );
			   add_action( 'admin_menu', array( $this, 'admin_menu' ), 20 );
		}
	}
	
	function admin_init() {
		register_setting( $this->settings_field, $this->settings_field, array($this, 'sanitize_theme_options' ) );
		add_option( $this->settings_field, Pareto_Security_Settings::$default_settings );
	}

	function admin_menu() {
		if ( ! current_user_can( 'update_plugins' ) )
			return;
	
		// Add a new submenu to the standard Settings panel
		$this->pagehook = $page =  add_options_page(	
			__( 'Pareto Security Settings', 'pareto_security_settings' ), __( 'Pareto Security Settings', 'pareto_security_settings' ), 
			'administrator', $this->page_id, array($this,'render' ) );
		
		// Executed on-load. Add all metaboxes.
		add_action( 'load-' . $this->pagehook, array( $this, 'metaboxes' ) );

		// Include js, css, or header *only* for our settings page
		add_action("admin_print_scripts-$page", array($this, 'js_includes' ) );
//		add_action("admin_print_styles-$page", array($this, 'css_includes' ) );
		add_action("admin_head-$page", array($this, 'admin_head' ) );
	}

	function admin_head() { ?>
		<style>
		.settings_page_pareto_security_settings label { display:inline-block; width: 150px; }
		</style>

	<?php }

     
	function js_includes() {
		// Needed to allow metabox layout and close functionality.
		wp_enqueue_script( 'postbox' );
	}


	/*
		Sanitize our plugin settings array as needed.
	*/	
	function sanitize_theme_options($options) {
		$options['pareto_security_settings_text'] = stripcslashes($options['pareto_security_settings_text']);
		return $options;
	}


	/*
		Settings access functions.
		
	*/
	protected function get_field_name( $name ) {
		return sprintf( '%s[%s]', $this->settings_field, $name );
	}

	protected function get_field_id( $id ) {
		return sprintf( '%s[%s]', $this->settings_field, $id );
	}

	protected function get_field_value( $key ) {
		return $this->options[$key];
	}
	
   function cleanRequestInput( $input ) {
      if ( function_exists( 'filter_var' ) && defined( 'FILTER_SANITIZE_STRING' ) ) {
            if ( false !== ( bool )filter_var( $input, FILTER_SANITIZE_STRING ) ) {
			return $input;
            } else return 0;		
	    }
    }
	
	/*
		Render settings page.
		
	*/
	
	function render() {
		global $wp_meta_boxes;

		$title = __( 'Pareto Security Settings', 'pareto_security_settings' );
		?>
		<div class="wrap">   
			<h2><?php echo esc_html( $title ); ?></h2>
		
			<form method="post" action="options.php">
				<p>
				<input type="submit" class="button button-primary" name="save_options" value="<?php esc_attr_e( 'Save Options' ); ?>" />
				</p>
                
                <div class="metabox-holder">
                    <div class="postbox-container" style="width: 99%;">
                    <?php 
						// Render metaboxes
                        settings_fields($this->settings_field); 
                        do_meta_boxes( $this->pagehook, 'main', null );
                      	if ( isset( $wp_meta_boxes[$this->pagehook]['column2'] ) )
 							do_meta_boxes( $this->pagehook, 'column2', null );
                    ?>
                    </div>
                </div>

				<p>
				<input type="submit" class="button button-primary" name="save_options" value="<?php esc_attr_e( 'Save Options' ); ?>" />
				</p>
			</form>
		</div>
        
        <!-- Needed to allow metabox layout and close functionality. -->
		<script type="text/javascript">
			//<![CDATA[
			jQuery(document).ready( function ($) {
				// close postboxes that should be closed
				$('.if-js-closed').removeClass('if-js-closed').addClass('closed');
				// postboxes setup
				postboxes.add_postbox_toggles('<?php echo $this->pagehook; ?>');
			});
			//]]>
		</script>
	<?php }
	
	
	function metaboxes() {

		add_meta_box( 'pareto-security-settings-version', __( 'Information', 'pareto_security_settings' ), array( $this, 'info_box' ), $this->pagehook, 'main', 'high' );
		add_meta_box( 'pareto-security-settings-conditions', __( 'Custom Settings', 'pareto_security_settings' ), array( $this, 'condition_box' ), $this->pagehook, 'main' );
		add_meta_box( 'pareto-security-settings-donations', __( 'Donations', 'pareto_security_settings' ), array( $this, 'donations_box' ), $this->pagehook, 'main' );

	}

	function info_box() {
		?>
		<p><strong><?php _e( 'Version:', 'pareto_security_settings' ); ?></strong> <?php echo PARETO_VERSION; ?> <?php echo '&middot;'; ?> <strong><?php _e( 'Released:', 'pareto_security_settings' ); ?></strong> <?php echo PARETO_RELEASE_DATE; ?></p>
		<?php
	}
	function donations_box() {
		?>
		<p><strong>BTC:1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX</p>
		<?php
	}
	
	function condition_box() {
		if ( ( false !== ( bool )defined( 'WP_ADMIN' ) && false !== WP_ADMIN ) && ( false !== ( bool)is_admin() ) ) {
	?>
		<p>        
			<h4>Permanently Ban IP Addresses:</h4>
			This will allow Pareto Security to automatically add IP addresses from attacks to your .htaccess file.
			<br />
			<input type="checkbox" name="<?php echo $this->get_field_name( 'perm_ban_ips' ); ?>" id="<?php echo $this->get_field_id( 'perm_ban_ips' ); ?>" value="<?php echo isset( $this->options['perm_ban_ips'] ) ? 1 : 0; ?>" <?php echo isset( $this->options['perm_ban_ips'] ) ? checked : ''; ?> /> 
			<label for="<?php echo $this->get_field_id( 'perm_ban_ips' ); ?>"><?php _e( 'Permanently ban IPs', 'pareto_security_settings' ); ?></label>
			<br />
			<?php /* ?>
			<h4>Restricts PHP's open_basedir() function to your root directory:</h4>
			If you do not know what this is, then leave it unchecked
			<br />
			<input type="checkbox" name="<?php echo $this->get_field_name( 'set_open_basedir' ); ?>" id="<?php echo $this->get_field_id( 'set_open_basedir' ); ?>" value="<?php echo isset( $this->options['set_open_basedir'] ) ? 1 : 0;?>" <?php echo isset($this->options['set_open_basedir']) ? 'checked' : '';?> />
			<label for="<?php echo $this->get_field_id( 'set_open_basedir' ); ?>"><?php _e( 'Set open_basedir', 'pareto_security_settings' ); ?></label>
			<?php */ ?>
		</p>
	<?php }
	}


	function do_settings_box() {
		if ( ( false !== ( bool )defined( 'WP_ADMIN' ) && false !== WP_ADMIN ) && ( false !== ( bool)is_admin() ) ) {
			do_settings_sections( 'pareto_settings_page' );
		}
	}

} // end class
endif;
?>
