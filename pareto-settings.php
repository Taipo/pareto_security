<?php
if ( false === function_exists( 'is_admin' ) ) {
	header( 'Status: 403 Forbidden' );
	header( 'HTTP/1.1 403 Forbidden' );
	exit();
}
define( 'PARETO_VERSION', '1.4.0' );
define( 'PARETO_RELEASE_DATE', date_i18n( 'F j, Y', '1491793015' ) );
define( 'PARETO_DIR', plugin_dir_path( __FILE__ ) );
define( 'PARETO_URL', plugin_dir_url( __FILE__ ) );
if ( !class_exists( "pareto_settings" ) ) :

class pareto_settings {

public static $default_settings = array( 'advanced_mode' => 0 );
var $pagehook, $page_id, $settings_field, $options, $advmode;

function __construct() {
	$this->page_id = 'pareto_security_settings';
	// This is the get_options slug used in the database to store our plugin option values.
	$this->settings_field = 'pareto_security_settings_options';
	$this->options = get_option( $this->settings_field );

	if ( $_SERVER[ 'REQUEST_METHOD' ] == 'POST' ) {
		foreach( $_POST as $key => $val ) {
			if ( is_array( $val ) ) {
				if ( isset( $_POST[ $this->settings_field ]["advanced_mode" ] ) &&
					 ( ( strlen( $_POST[ $this->settings_field ]["advanced_mode" ] ) > 1 ) ) ) {
					   $_POST[ $this->settings_field ]["advanced_mode" ] = 0;
				}
			}
		}
	}
	
	$this->advmode = ( false !== is_array( $this->options ) && array_key_exists( 'advanced_mode', $this->options ) ) ? 1 : 0;

	if ( ( false !== ( bool )defined( 'WP_ADMIN' ) && false !== WP_ADMIN ) && false !== ( bool)is_admin() ) {
		if ( false !== strpos( $_SERVER[ 'REQUEST_URI' ], 'options' ) ) add_action( 'admin_init', array( $this,'admin_init' ), 20 );
		add_action( 'admin_menu', array( $this, 'admin_menu' ), 20 );
	}
}
function admin_init() {
	register_setting( $this->settings_field, $this->settings_field, array( $this, 'sanitize_theme_options' ) );
	add_option( $this->settings_field, pareto_settings::$default_settings );
}

function admin_menu() {
	if ( ! current_user_can( 'update_plugins' ) )
		return;

	// Add a new submenu to the standard Settings panel
	$this->pagehook = $page =  add_options_page( __( 'Pareto Security Settings', 'pareto_security_settings' ), __( 'Pareto Security Settings', 'pareto_security_settings' ), 'administrator', $this->page_id, array( $this,'render' ) );

	// Executed on-load. Add all metaboxes.
	add_action( 'load-' . $this->pagehook, array( $this, 'metaboxes' ) );

	// Include js, css, or header *only* for our settings page
	add_action( "admin_print_scripts-$page", array( $this, 'js_includes' ) );
//		add_action( "admin_print_styles-$page", array( $this, 'css_includes' ) );
	add_action( "admin_head-$page", array( $this, 'admin_head' ) );
}

function admin_head() { ?>
	<style>
	.settings_page_pareto_security_settings label { display:inline-block; width: 400px; }
	</style>

<?php }


function js_includes() {
	// Needed to allow metabox layout and close functionality.
	wp_enqueue_script( 'postbox' );
}


/*
	Sanitize our plugin settings array as needed.
*/
function sanitize_theme_options( $options ) {
	if ( is_array( $options ) ) {
		if ( array_key_exists( 'pareto_security_settings_text', $options ) ) $options[ 'pareto_security_settings_text' ] = stripcslashes( $options[ 'pareto_security_settings_text' ] );
		if ( array_key_exists( 'advanced_mode', $options ) ) $options[ 'advanced_mode' ] = ( int ) $options[ 'advanced_mode' ];
		return $options;
	}
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
	<p><strong><a href=BTC:1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX>BTC:1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX</a></p>
	<?php
}

function condition_box() {
	if ( ( false !== ( bool )defined( 'WP_ADMIN' ) && false !== WP_ADMIN ) && ( false !== ( bool)is_admin() ) ) {
	$mode = ( false === ( bool ) $this->advmode ) ? 'Standard' : 'Advanced';
?>
	<p>
		<b>Status:</b> Currently Pareto Security is running in <i><?php echo $mode; ?> mode</i>.<br /><br />
		<b>Set Advanced Mode:</b><br />
		<ul>
			<li>• Permanently ban IP addresses ( if .htaccess is configured correctly )</li>
			<li>• Filter out non-standard browser user-agents</li>
			<li>• Only allow GET | POST | HEAD requests</li>
			<li>• Advanced _POST filtering</li>
		</ul>
		<input type="checkbox" name="<?php echo $this->get_field_name( 'advanced_mode' ); ?>" id="<?php echo $this->get_field_id( 'advanced_mode' ); ?>" value="<?php echo isset( $this->options['advanced_mode'] ) ? 1 : 0; ?>" <?php echo isset( $this->options['advanced_mode'] ) ? 'checked' : ''; ?> />
		<label for="<?php echo $this->get_field_id( 'advanced_mode' ); ?>"><?php _e( '<b>Set Advanced Mode</b> (Warning: Only use if you know the risks)', 'pareto_security_settings' ); ?></label>
		<br /><br />
		<input type="submit" class="button button-primary" name="save_options" value="<?php esc_attr_e( 'Save Options' ); ?>" />
		<br />
	</p>
<?php }
}


function do_settings_box() {
	if ( ( false !== ( bool )defined( 'WP_ADMIN' ) && false !== WP_ADMIN ) && ( false !== ( bool )is_admin() ) ) {
		do_settings_sections( 'pareto_settings_page' );
	}
}

} // end class
endif;
?>
