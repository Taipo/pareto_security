<?php
if ( class_exists( "pareto_functions" ) ) :
class pareto_settings extends pareto_functions {
	public static $default_settings = array( 'advanced_mode' => 0, 'ban_mode' => 0, 'spider_mode' => 0 );
	var $pagehook, $page_id, $settings_field, $options;
	public $_ban_mode = 0;
	
	function __construct() {
		if ( false === $this->is_wp( false ) ) {
			header( 'Status: 403 Forbidden' );
			header( 'HTTP/1.1 403 Forbidden' );
			exit();
		}
		$unix_time = 1495357295 + 43200;
		define( 'PARETO_VERSION', '1.6.3' );
		define( 'PARETO_RELEASE_DATE', date_i18n( 'F j, Y', $unix_time ) );
		define( 'PARETO_DIR', plugin_dir_path( __FILE__ ) );
		define( 'PARETO_URL', plugin_dir_url( __FILE__ ) );
		$this->page_id = 'pareto_security_settings';
		// This is the get_options slug used in the database to store our plugin option values.
		$this->settings_field = 'pareto_security_settings_options';
		$this->options = get_option( $this->settings_field );
	
		if ( $_SERVER[ 'REQUEST_METHOD' ] == 'POST' ) {
			foreach( $_POST as $key => $val ) {
				if ( is_array( $val ) ) {
					if ( isset( $_POST[ $this->settings_field ][ "ban_mode" ] ) &&
						 ( ( strlen( $_POST[ $this->settings_field ][ "ban_mode" ] ) > 1 ) ) ) {
						   $_POST[ $this->settings_field ][ "ban_mode" ] = 0;
					}
					if ( isset( $_POST[ $this->settings_field ][ "spider_mode" ] ) &&
						 ( ( strlen( $_POST[ $this->settings_field ][ "spider_mode" ] ) > 1 ) ) ) {
						   $_POST[ $this->settings_field ][ "spider_mode" ] = 0;
					}
					if ( isset( $_POST[ $this->settings_field ][ "advanced_mode" ] ) &&
						 ( ( strlen( $_POST[ $this->settings_field ][ "advanced_mode" ] ) > 1 ) ) ) {
						   $_POST[ $this->settings_field ][ "advanced_mode" ] = 0;
					}
				}
			}
		}
		if ( false !== is_array( $this->options ) ) {
			$this->_adv_mode =  ( array_key_exists( 'advanced_mode', $this->options ) ) ? 1 : 0;
			$this->_ban_mode = ( array_key_exists( 'ban_mode', $this->options ) ) ? 1 : 0;
			$this->_spider_mode = ( false !== ( bool ) $this->_adv_mode && array_key_exists( 'spider_mode', $this->options ) ) ? 1 : 0;
		}
		if ( false !== $this->is_wp( true ) ) {
			$this->_log_file = $this->logfile_name();
			add_action( 'admin_init', array( $this,'admin_init' ), 20 );
			add_action( 'admin_menu', array( $this, 'admin_menu' ), 20 );
			if ( !file_exists( PARETO_LOGS . ".htaccess" ) || !file_exists( PARETO_LOGS . $this->_log_file ) ) $this->create_fileset();
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
		$this->pagehook = $page =  add_options_page( __( 'Pareto Security Settings', 'pareto_security_settings' ), __( 'Pareto Security Dashboard', 'pareto_security_settings' ), 'administrator', $this->page_id, array( $this,'render' ) );
		add_action( 'load-' . $this->pagehook, array( $this, 'metaboxes' ) );
		add_action( "admin_print_scripts-$page", array( $this, 'js_includes' ) );
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
			if ( array_key_exists( 'advanced_mode', $options ) ) $options[ 'advanced_mode' ] = 1;
			if ( array_key_exists( 'ban_mode', $options ) ) $options[ 'ban_mode' ] = 1;
			if ( array_key_exists( 'spider_mode', $options ) ) $options[ 'spider_mode' ] = 1;
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
		return $this->options[ $key ];
	}
	function cleanRequestInput( $input ) {
	  if ( function_exists( 'filter_var' ) && defined( 'FILTER_SANITIZE_STRING' ) ) {
			if ( false !== ( bool )filter_var( $input, FILTER_SANITIZE_STRING ) ) {
			return $input;
			} else return false;
		}
	}
	/*
		Render settings page.
	
	*/
	function render() {
		global $wp_meta_boxes;
		$title = __( 'Pareto Security Dashboard', 'pareto_security_settings' );
		?>
		<div class="wrap">
			<table style="text-align: left;">
				<tr>
					<td><img src="<?php echo PARETO_URL; ?>img/icon-64x64.png"></td>
					<td><h1><?php echo esc_html( $title ); ?></h1></td>
				</tr>
			</table>
			<form method="post" action="options.php">
				<div class="metabox-holder">
					<div class="postbox-container" style="width: 99%;">
<?php
	// Render metaboxes
	settings_fields( $this->settings_field );
	do_meta_boxes( $this->pagehook, 'main', null );
	if ( isset( $wp_meta_boxes[ $this->pagehook ][ 'column2' ] ) )
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
		add_meta_box( 'pareto-security-settings-notes', __( 'Notes:', 'pareto_security_settings' ), array( $this, 'notes_box' ), $this->pagehook, 'main' );
		add_meta_box( 'pareto-security-settings-logs', __( 'Last 100 Attack Requests', 'pareto_security_settings' ), array( $this, 'logfile_box' ), $this->pagehook, 'main' );
		add_meta_box( 'pareto-security-settings-donations', __( 'Donations', 'pareto_security_settings' ), array( $this, 'donations_box' ), $this->pagehook, 'main' );
	}
	function info_box() {
?>
			<table style="text-align: left;">
				<tr>
					<td><strong><?php _e( 'Version:', 'pareto_security_settings' ); ?></strong> <?php echo PARETO_VERSION; ?> <?php echo '&middot;'; ?> <strong><?php _e( 'Released:', 'pareto_security_settings' ); ?></strong> <?php echo PARETO_RELEASE_DATE; ?> ( NZ Timezone )</td>
					<td><strong>Author:</strong> <a target="_blank" href="https://twitter.com/te_taipo">@te_taipo</a></td>
					<td><strong>Web:</strong> <a target="_blank" href="https://hokioisecurity.com">https://hokioisecurity.com</a></td>
					<td><strong>Email:</strong> hokioi-security@protonmail.ch</td>
				</tr>
			</table>
<?php
	}

	function donations_box() {
?>
		<p><strong><a href=BTC:1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX>BTC:1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX</a></strong></p>
<?php
	}
	function condition_box() {
?>
		<table style="text-align: left; background-color: #C9C9C9;">
			<tr>
				<td>
				<table style="width: 1050px;">
					<tr style="background-color:#5F607B">
					  <td style="width:110px"><b><font color="#FFFFF">&nbsp;<b>Standard Mode:</b></font></b></td>
					  <td style="width:100px"><b><font color="#FFFFF">&nbsp;<b>Advanced Mode:</b></font></b></td>
					</tr>
					<tr style="text-align: left; background-color: #E8E8E8;">
						<td style="width: 400px; vertical-align:top;">
							<dl>
								<dt>&nbsp;&nbsp;- <b>Standard Mode</b> is the recommended setting</dt>
								<dt>&nbsp;&nbsp;- Hard ban attempts to attack the webserver</dt>
								<dt>&nbsp;&nbsp;- Hard ban attempts to inject malicious code into the database</dt>
								<dt>&nbsp;&nbsp;- Hard ban injection attempts via browser user-agents</dt>
								<dt>&nbsp;&nbsp;- Does not filter User-Agent</dt>
								<dt>&nbsp;&nbsp;- Advanced POST Filtering is disabled</dt>
							</dl>
						 </td>
						<td style="width: 500px; vertical-align:top;">
							<table>
								<tr>
								  <td><input type="checkbox" name="<?php echo $this->get_field_name( 'advanced_mode' ); ?>" id="<?php echo $this->get_field_id( 'advanced_mode' ); ?>" value="<?php echo isset( $this->options[ 'advanced_mode' ] ) ? $this->options[ 'advanced_mode' ] : 0; ?>" <?php echo ( isset( $this->options[ 'advanced_mode' ] ) || false !== ( bool ) $this->_adv_mode ) ? 'checked' : ''; ?> /></td>
								  <td>
								<label for="<?php echo $this->get_field_id( 'advanced_mode' ); ?>"><?php _e( '<b>Set Advanced Mode</b> ( Use at your own risk )', 'pareto_security_settings' ); ?></label></td>
								</tr>
								<tr>
								  <td></td>
								  <td>- Hard ban attempts to attack the webserver</td>
								</tr>
								<tr>
								  <td></td>
								  <td>- Hard ban attempts to inject malicious code into the database</td>
								</tr>
								<tr>
								  <td></td>
								  <td>- Hard ban injection attempts via browser user-agents</td>
								</tr>
								<tr>
								<tr>
								  <td></td>
								  <td>- Advanced filtering of HTTP_HOST</td>
								</tr>
								<tr>
								  <td></td>
								  <td>- Soft Ban Bots</td>
								</tr>
								<tr>
								  <td></td>
								  <td>- Advanced POST Filtering</td>
								</tr>
								<tr>
								  <td><input type="checkbox" name="<?php echo $this->get_field_name( 'spider_mode' ); ?>" id="<?php echo $this->get_field_id( 'spider_mode' ); ?>" value="<?php echo isset( $this->options['spider_mode'] ) ? 1 : 0; ?>" <?php echo ( !isset( $this->options[ 'advanced_mode' ] ) )? "disabled=\"disabled\"":""; ?><?php echo ( isset( $this->options['spider_mode'] ) && isset( $this->options[ 'advanced_mode' ] ) && $this->options[ 'advanced_mode' ] == 1 )? 'checked' : ''; ?> /></td>
								  <td>- <label for="<?php echo $this->get_field_id( 'spider_mode' ); ?>"><?php _e( 'Hard ban of bots', 'pareto_security_settings' ); ?></label></td>
								</tr>
							</table>
						</td>
					</tr>
				</table>
				</td>
			</tr>
		</table>
		<br />
		<input type="submit" class="button button-primary" name="save_options" value="<?php esc_attr_e( 'Save Options' ); ?>" />
<?php }
	function notes_box () {
		$mode = ( false === ( bool ) $this->_adv_mode ) ? 'Standard' : 'Advanced';
?>   <ul>
		<li>+ Status: <i><?php echo $mode; ?> mode</i></li>
<?php if ( file_exists( $this->htapath() ) && $this->get_file_perms( $this->htapath(), true, true ) ) {	?>
		<li>+ Your <code>.htaccess</code> is configured correctly in <code><?php echo $this->get_dir(); ?></code></li>
		<li>+ <?php echo ( $this->_adv_mode ) ? 'Hard Ban' : 'Soft Ban'; ?>: IP address <?php echo ( $this->_adv_mode ) ? '<i>will</i>' : '<i>will not</i>'; ?> be added to the .htaccess file <?php echo ( $this->_adv_mode ) ? '' : 'except for instances of direct attacks'; ?></li>
<?php
		} else {
?>      <li>+ Your <code>.htaccess</code> file cannot be written to in <code><?php echo $this->get_dir(); ?></code> Pareto Security will still soft ban attack vectors.</li>
		  <li>+ Hard Ban: IP address will not be added to the .htaccess file</li>
<?php } ?>
			<li>+ Date-Time is set to NZ timezone</li>
	</ul>
<?php }
	function logfile_box () {
?>
		<table style="text-align: left; background-color: #C9C9C9;">
			<tr>
				<td>
				<table style="width: 1100px; text-align: left;">
					<tbody>
					  <tr style="background-color:#5F607B">
						<td style="width:90px"><b><font color="#FFFFF">Date-Time:</font></b></td>
						<td style="width:200px"><b><font color="#FFFFF">IP Address:</font></b></td>
						<td style="width:30px"><b><font color="#FFFFF">Type:</font></b></td>
						<td style="width:30px"><b><font color="#FFFFF">Req:</font></b></td>
						<td><b><font color="#FFFFF">Attack String:</font></b></td>
					  </tr>
					  <tr>
						<td></td>
						<td></td>
						<td></td>
						<td></td>
						<td></td>
					  </tr>
<?php
						if ( !file_exists( PARETO_LOGS . ".htaccess" ) ) $this->create_fileset();
						$mylogs = array();
						$mylogs = array_reverse( file( PARETO_LOGS . $this->_log_file ) );
						$i = 0;
						$trim = 110;
						while( $i <= 99 ) {
						  if ( isset( $mylogs[ $i ] ) ) {
							$row_colour = ( $i % 2 == 0 ) ? "#E8E8E8" : "#D0D0DE";
							$req_var = explode( ' ', $mylogs[ $i ] );
							if ( false !== ( bool ) $this->_banip || false !== ( bool ) $this->_adv_mode ) $row_colour = ( false === stripos( html_entity_decode( $req_var[ 4 ], ( ( version_compare( phpversion(), '5.4', '>=') ) ? ENT_HTML5 : ENT_QUOTES ), 'UTF-8' ), 'USER_AGENT:' ) && false !== stripos( $req_var[ 2 ], 'ban' ) ) ? "#F89E98" : $row_colour;
							$ip_addr = ( false !== $this->check_ip( $req_var[ 1 ] ) ) ? ' <a target="_blank" href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a' . $req_var[ 1 ] . '&run=networktools">[Blacklist]</a> <a target="_blank" href="https://www.whois.com/whois/' . $req_var[ 1 ] . '">[Whois]</a> ' . $req_var[ 1 ] : $req_var[ 1 ];
							$attack_string = str_replace( '%20', " ", preg_replace( "/[\n]/i", "", stripslashes( $req_var[ 4 ] ) ) );
							$attack_string = ( strlen( $attack_string ) > $trim ) ? substr( $attack_string, 0, $trim ) . "..." : $attack_string;
							echo "<tr style=\"background-color:" . $row_colour . "\">" .
								 "	<td style=\"vertical-align:top; width:90px; white-space: nowrap\">" . $req_var[ 0 ] . "</td>" .
								 "	<td style=\"vertical-align:top; width:200px; white-space: nowrap\">" . $ip_addr . "</td>" .
								 "	<td style=\"vertical-align:top; width:30px; white-space: nowrap\">" . $req_var[ 2 ] . "</td>" .
								 "	<td style=\"vertical-align:top; width:30px; white-space: nowrap\">" . $req_var[ 3 ] . "</td>" .
								 "	<td style=\"vertical-align:top; white-space: nowrap\"><code>" . $attack_string . "</code></td>" .
								 "</tr>";
						  } else break;
						$i++;
						}
?>
				</table>
				</code>
				</td>
			</tr>
		</table>
<?php
	}
	function do_settings_box() {
		if ( ( false !== ( bool )defined( 'WP_ADMIN' ) && false !== WP_ADMIN ) && ( false !== ( bool )is_admin() ) ) {
			do_settings_sections( 'pareto_settings_page' );
		}
	}
} // end class
endif;
?>