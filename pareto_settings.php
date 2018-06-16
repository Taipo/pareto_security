<?php
if ( class_exists( "pareto_functions" ) ):
    class pareto_settings extends pareto_functions {
        public static $default_settings = array( 'advanced_mode' => 0, 'ban_mode' => 0, 'hard_ban_mode' => 0, 'safe_list' => '', 'email_report' => 1, 'safe_list' => '' );
        var $pagehook, $page_id, $settings_field, $options, $log_list, $logs, $time_zone, $_textdomain = 'pareto_security_settings';
        public $_ban_mode = 0;
        private $prefix = 'pareto_settings';
        function __construct() {
            if ( false === $this->is_wp() ) {
                header( 'Status: 403 Forbidden' );
                header( 'HTTP/1.1 403 Forbidden' );
                exit();
            }
            $unix_time       = $this->updated( 1529109391, ( int ) get_option( 'gmt_offset' ) );
            $this->time_zone = date_default_timezone_get() . get_option( 'gmt_offset' );
            
            define( 'PARETO_VERSION', '2.1.0' );
            define( 'PARETO_RELEASE_DATE', date_i18n( 'F j, Y', $unix_time ) );
            define( 'PARETO_DIR', plugin_dir_path( __FILE__ ) );
            define( 'PARETO_URL', plugin_dir_url( __FILE__ ) );
            
            load_plugin_textdomain( $this->_textdomain );
            add_action( "admin_enqueue_scripts", array( $this, 'enqueue_scripts' ) );
            
            $this->kickoff();
        }
        function enqueue_scripts() {
            wp_enqueue_style( "{$this->prefix}_style", plugins_url( 'css/style.css', __FILE__ ) );
        }
        function kickoff() {
            $this->page_id        = $this->_textdomain;
            $this->timestamp      = ( false !== $this->is_wp() ) ? date_i18n( 'd-m-y,G:i', ( $this->updated( time(), ( int ) get_option( 'gmt_offset' ) ) ) ) : date( "d.m.y-G:i" );
            $this->settings_field = 'pareto_security_settings_options';
            $this->log_list       = 'pareto_security_log_list';
            
            $this->options = get_option( $this->settings_field );
            $this->logs    = get_option( $this->log_list );
            
            if ( empty( $this->options ) ) {
                update_option( $this->settings_field, array( // set defaults
                     'advanced_mode' => 0,
                     'hard_ban_mode' => 0,
                     'email_report' => 1,
                     'ban_mode' => 0 
                ) );
                $this->options = get_option( $this->settings_field );
            }
            
            $this->options[ 'ban_mode' ]      = ( false !== $this->check_settings( 'ban_mode' ) ) ? ( int ) $this->options[ 'ban_mode' ] : 0;
            $this->options[ 'email_report' ]  = ( false !== $this->check_settings( 'email_report' ) ) ? ( int ) $this->options[ 'email_report' ] : 0;
            $this->options[ 'advanced_mode' ] = ( false !== $this->check_settings( 'advanced_mode' ) ) ? ( int ) $this->options[ 'advanced_mode' ] : 0;
            $this->options[ 'hard_ban_mode' ] = ( false !== $this->check_settings( 'hard_ban_mode' ) ) ? ( int ) $this->options[ 'hard_ban_mode' ] : 0;
            
            if ( array_key_exists( 'safe_list', $this->options ) ) {
                $this->_domain_list = $this->get_field_value( $this->options, 'safe_list' );
                $this->options[ 'safe_list' ] = $this->_domain_list;
            }
            # only available to logged in Admins
            if ( false !== ( bool ) $this->is_wp( true, true ) ) {
                $this->define_plugin_settings();
                if ( $_SERVER[ 'REQUEST_METHOD' ] == 'POST' ) {
                    if ( isset( $_POST[ $this->settings_field ][ "safe_list" ] ) ) {
                        $_POST[ $this->settings_field ][ "safe_list" ] = $this->host_check( $_POST[ $this->settings_field ][ "safe_list" ] );
                    }
                    if ( isset( $_POST[ $this->settings_field ][ "ban_mode" ] ) )
                        $_POST[ $this->settings_field ][ "ban_mode" ] = ( int ) $_POST[ $this->settings_field ][ "ban_mode" ];
                    if ( isset( $_POST[ $this->settings_field ][ "advanced_mode" ] ) ) {
                        $_POST[ $this->settings_field ][ "advanced_mode" ] = ( int ) $_POST[ $this->settings_field ][ "advanced_mode" ];
                        if ( !isset( $_POST[ $this->settings_field ][ "safe_list" ] ) || empty( $_POST[ $this->settings_field ][ "safe_list" ] ) ) $_POST[ $this->settings_field ][ "safe_list" ] = $this->get_http_host();
                    }
                    if ( isset( $_POST[ $this->settings_field ][ "email_report" ] ) )
                        $_POST[ $this->settings_field ][ "email_report" ] = ( int ) $_POST[ $this->settings_field ][ "email_report" ];
                    if ( isset( $_POST[ $this->settings_field ][ "hard_ban_mode" ] ) )
                        $_POST[ $this->settings_field ][ "hard_ban_mode" ] = ( int ) $_POST[ $this->settings_field ][ "hard_ban_mode" ];
                }
                # clean up failed login hashes
                if ( $this->is_wp( false, true ) ) $this->iphash_db_cleanup();
                
                add_action( 'admin_init', array(
                     $this,
                    'admin_init' 
                ), 20 );
                add_action( 'admin_menu', array(
                     $this,
                    'admin_menu' 
                ), 20 );
            }
            
            $this->_adv_mode      = $this->get_field_value( $this->options, 'advanced_mode' );
            $this->_ban_mode      = $this->get_field_value( $this->options, 'ban_mode' );
            $this->_email_report  = $this->get_field_value( $this->options, 'email_report' );
            $this->_hard_ban_mode = ( false !== ( bool ) $this->_adv_mode ) ? $this->get_field_value( $this->options, 'hard_ban_mode' ) : 0;
            $this->update_logfile( $this->logs );

            update_option( $this->settings_field, array( // set defaults
                     'advanced_mode' => $this->_adv_mode,
                     'hard_ban_mode' => $this->_hard_ban_mode,
                     'email_report' => $this->_email_report,
                     'ban_mode' => $this->_ban_mode,
                     'safe_list' => ( isset( $this->_domain_list ) ? $this->_domain_list : '' )
            ) );            
        }
        function define_plugin_settings() {
            $basename = plugin_basename( __FILE__ );
            $prefix = is_network_admin() ? 'network_admin_' : '';
            add_filter( 'plugin_action_links', array( $this, 'add_plugin_action_links'), 10, 2);
            add_action( 'admin_menu', array( $this, 'add_to_admin_menu' ) );
        }
        function add_plugin_action_links( $links, $file ) {
            if ( strstr( $file, 'pareto-security/pareto_security.php' ) ) {
                $settings[ 'settings' ] = '<a href="'. esc_url( admin_url( "options-general.php?page=pareto_security_settings") ) . '">Settings</a>';
                array_unshift( $links, $settings[ 'settings' ] );
            }
            return $links;
        }
        function add_to_admin_menu(){
        
          $page_title = 'Pareto Security';
          $menu_title = 'Pareto Security';
          $capability = 'manage_options';
          $menu_slug  = $this->_textdomain;
          $function   = '';
          $icon_url   = plugins_url( 'pareto-security/img/icon16bw.png' );
          $position   = ( is_network_admin() ) ? 26 : 81;
        
          add_menu_page( $page_title,
                         $menu_title, 
                         $capability, 
                         $menu_slug, 
                         $function, 
                         $icon_url, 
                         $position );
        }
        function update_logfile( $logfile = array() ) {
            $install_log = str_replace( ' ', '%20', PARETO_RELEASE_DATE ) . " Safe " . str_replace( ' ', '%20', $_SERVER[ 'SERVER_ADDR' ] ) . " GET plugins.php Pareto%20Security%20Installed";
             if ( empty( $logfile ) ) {
                update_option( $this->log_list, array(
                     0 => $install_log ) );
                    $logfile = $install_log;
                    $this->logs = get_option( $this->log_list );
                    return;
            } elseif ( !empty( $logfile ) && false === ( bool ) $this->_adv_mode ) {
                $tmp_logfile = array();
                for( $x = 0; $x < count( $logfile ); $x++ ) {
                    if ( false !== strpos( strtolower( $logfile[ $x ] ), " low " ) ||
                         false !== strpos( strtolower( $logfile[ $x ] ), " safe " ) &&
                         $logfile[ $x ] != $install_log ) {
                         continue;
                    }
                    $tmp_logfile[] = $logfile[ $x ];
                }
                update_option( $this->log_list, $tmp_logfile );
                $this->logs = get_option( $this->log_list );
                return;
            } else {
                $this->logs = get_option( $this->log_list );
            }
            return;
        }
        function check_settings( $val ) {
            if ( !isset( $this->options[ $val ] ) || $this->options[ $val ] > 1 || $this->options[ $val ] < 0 ) {
                return false;
            } else
                return true;
        }
        function admin_init() {
            register_setting( $this->settings_field, $this->settings_field );
            register_setting( $this->log_list, $this->log_list );
            add_option( $this->settings_field, pareto_settings::$default_settings );
        }
        function admin_menu() {
            if ( !current_user_can( 'update_plugins' ) )
                return;
            // Add a new submenu to the standard Settings panel
            $this->pagehook = $page = add_options_page( __( 'Pareto Security Settings', $this->_textdomain ), __( 'Pareto Security Dashboard', $this->_textdomain ), 'administrator', $this->page_id, array( $this,'render' ) );

            add_action( 'load-' . $this->pagehook, array(
                 $this,
                'metaboxes' 
            ) );
            add_action( "admin_print_scripts-$page", array(
                 $this,
                'js_includes' 
            ) );
            add_action( "admin_head-$page", array(
                 $this,
                'admin_head' 
            ) );
        }
        function admin_head() {
?>
       <style>
        .settings_page_pareto_security_settings label { display:inline-block; width: 400px; }
        code{
            direction: ltr;
            text-align: left;
        }
        code {font-size:1.0em;
              margin: 0px; 
              padding:3px;
              background-color:transparent;
              color: #3E3E3E}        
        </style>
<?php
        }
        function js_includes() {
            // Needed to allow metabox layout and close functionality.
            wp_enqueue_script( 'postbox' );
        }
        /*
        Sanitize our plugin settings array as needed.
        */
        function sanitize_theme_options( $options ) {
            
            if ( is_array( $options ) ) {
                foreach ( $options as $key => $val ) {
                    if ( $key != 'safe_list' && false === $this->integ_prop( $val ) || $val > 1 ) {
                        $options[ $key ] = 0;
                    } elseif ( $val == 'safe_list' ) {
                        $options[ 'safe_list' ] = $this->cleanRequestInput( $val );
                    } else {
                        $options[ $key ] = ( int ) $val;
                    }
                }
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
        protected function get_field_value( $option, $key ) {
            return $option[ $key ];
        }
        function cleanRequestInput( $input ) {
            if ( function_exists( 'filter_var' ) && defined( 'FILTER_SANITIZE_STRING' ) ) {
                if ( false !== ( bool ) filter_var( $input, FILTER_SANITIZE_STRING ) ) {
                    return $input;
                } else
                    return false;
            }
        }
        /*
        Render settings page.
        
        */
        function render() {
            global $wp_meta_boxes;
            $title = esc_html( 'Pareto Security Dashboard', $this->_textdomain ); ?>
        <div class="wrap">
            <table style="text-align: left;">
                <tr>
                    <td><img src="<?php echo plugins_url( 'pareto-security/img/icon.png' ); ?>">
                    </td>
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
                postboxes.add_postbox_toggles('<?php
            echo $this->pagehook;
?>');
            });
            //]]>
        </script>
<?php
        }
        function metaboxes() {
            add_meta_box( 'pareto-security-settings-version', esc_html( 'Information', $this->_textdomain ), array(
                 $this,
                'info_box' 
            ), $this->pagehook, 'main', 'high' );
            add_meta_box( 'pareto-security-settings-notes', esc_html( 'Notes:', $this->_textdomain ), array(
                 $this,
                'notes_box' 
            ), $this->pagehook, 'main' );
            add_meta_box( 'pareto-security-settings-conditions', esc_html( 'Custom Settings', $this->_textdomain ), array(
                 $this,
                'condition_box' 
            ), $this->pagehook, 'main' );
            if ( false !== ( bool ) $this->_adv_mode )
                add_meta_box( 'pareto-security-settings-domainlist', esc_html( 'Domain Name Safe List:', $this->_textdomain ), array(
                     $this,
                    'safelist_box' 
                ), $this->pagehook, 'main' );
            add_meta_box( 'pareto-security-settings-save', esc_html( 'Save All Settings', $this->_textdomain ), array(
                 $this,
                'save_settings' 
            ), $this->pagehook, 'main' );
            add_meta_box( 'pareto-security-settings-logs', esc_html( 'Last 100 Incidents', $this->_textdomain ), array(
                 $this,
                'logfile_box' 
            ), $this->pagehook, 'main' );
            add_meta_box( 'pareto-security-settings-donations', esc_html( 'Donations', $this->_textdomain ), array(
                 $this,
                'donations_box' 
            ), $this->pagehook, 'main' );
        }
        
        function safelist_box() {
            if ( false === $this->_adv_mode ) return;
            $is_https  = ( ( array_key_exists( 'HTTPS', $_SERVER ) && "on" == @$_SERVER[ "HTTPS" ] ) || ( array_key_exists( 'HTTPS', getenv() ) && "on" == getenv( "HTTPS" ) ) ) ? true : false;
            $http      = ( false !== $is_https ) ? 'https://' : 'http://';
            $url       = str_replace( 'www.', '', $this->get_http_host() );
            $hsts_url  = 'https://hstspreload.org/?domain=' . $url;
            $hsts_link = '<a target="_blank" href="' . $hsts_url . '">' . $hsts_url . '</a>';
?>
           <table style="text-align: left;">
                <tr>
                    <td><b>Status:</b> ( <?php echo ( ( false === ( bool ) $this->_adv_mode ) ? esc_html( 'To enable, set to Advanced Mode above', $this->_textdomain ) : esc_html( 'Enabled', $this->_textdomain ) ); ?> )
                    <ol>
                        <li><?php echo esc_html( 'List every domain name associated with your website here (including subdomains).', $this->_textdomain ); ?></li>
                        <li><?php echo _e( 'One domain name per line: (i.e ' . $this->get_http_host() . ' - without <code>' . $http . '</code> scheme/protocol and double forward slashes)', $this->_textdomain ) ?></li>
                           <textarea <?php echo ( false === ( bool ) $this->_adv_mode ) ? esc_html( 'disabled', $this->_textdomain ) : ''; ?> name="<?php echo $this->get_field_name( 'safe_list', $this->_textdomain ); ?>" id="<?php echo $this->get_field_name( 'safe_list' ); ?>" rows="3" cols="30"><?php echo $this->options[ 'safe_list' ]; ?></textarea>
                        <?php if ( false !== $is_https ) ?><li><?php echo _e( 'Register your domain with Google Chromes preload list ' . $hsts_link, $this->_textdomain ); ?></li>
                   </ol></td>
                </tr>
            </table>
<?php } function save_settings() { ?>
           <table style="text-align: left;">
                <tr>
                    <td><label for="<?php echo $this->get_field_id( 'email_report' ); ?>" class="container"><?php echo _e( '<b>Email Notification:</b> Recieve notifications of High Severity attacks', $this->_textdomain ); ?>
                            <input type="checkbox" name="<?php echo $this->get_field_name( 'email_report' ); ?>" id="<?php echo $this->get_field_id( 'email_report' ); ?>" value="1" <?php if ( ( isset( $this->options[ 'email_report' ] ) && false !== ( bool ) $this->options[ 'email_report' ] ) ) { ?>checked<?php } ?> /><span class="checkmark"></span></label> 
                    </td>
                </tr>
                <tr>
                    <td><input type="submit" class="button button-primary" name="save_options" value="<?php esc_attr_e( 'Save Options', $this->_textdomain ); ?>" /></td>
                </tr>
            </table>
<?php
        }
        function info_box() {
?>
           <table style="text-align: left;">
                <tr>
                    <td><strong><?php echo esc_html( 'Version:', $this->_textdomain ); ?></strong> <?php echo PARETO_VERSION; ?> <?php echo '&middot;'; ?> <strong><?php esc_html( 'Released:', $this->_textdomain ); ?></strong><?php echo PARETO_RELEASE_DATE; ?> ( <?php echo $this->time_zone; ?> )</td>
                    <td><strong><?php echo esc_html( 'Author:', $this->_textdomain ); ?></strong> <a target="_blank" href="https://twitter.com/te_taipo">@te_taipo</a></td>
                    <td><strong><?php echo esc_html( 'Web:', $this->_textdomain ); ?></strong> <a target="_blank" href="https://hokioisecurity.com">https://hokioisecurity.com</a></td>
                    <td><strong><?php echo esc_html( 'Email:', $this->_textdomain ); ?></strong> pareto-security@hokioisecurity.com</td>
                </tr>
                <tr>
                    <td colspan=3><strong><?php echo esc_html( 'Rate This Plugin:', $this->_textdomain ); ?></strong> <a href="https://wordpress.org/support/plugin/pareto-security/reviews/" target="_blank"><?php echo esc_html( 'Rate this plugin 5 stars on WordPress.org', $this->_textdomain ); ?></a>
                    </td>
                </tr>
            </table>
<?php
        }
        
        function donations_box() {
?>
        <p><strong><?php echo esc_html( 'Bitcoin Address:', $this->_textdomain ); ?></strong> <?php echo esc_html( '1HnQtSEXZXvL6sfgXRZ8sAhVmtMtwXfSyf', $this->_textdomain ); ?></p>
        <p><strong><?php echo esc_html( 'ZCASH Address:', $this->_textdomain ); ?></strong> <?php echo esc_html( 't1Lnmn4r9jVxhjhTLix8sRfyoqqsJVbShQ1', $this->_textdomain ); ?></p>
        <p><strong><?php echo esc_html( 'Vericoin:', $this->_textdomain ); ?></strong> <?php echo esc_html( 'VRsjYZmjpYxXmhRxGzYcECfpNUksvBr25v', $this->_textdomain ); ?></p>
        <p><strong><?php echo esc_html( 'Ethereum:', $this->_textdomain ); ?></strong> <?php echo esc_html( '0xb9f7a75530ef6b4b21c721a81fe54c548492f9bf', $this->_textdomain ); ?></p>
        <p><strong><?php echo esc_html( 'Paypal Address:', $this->_textdomain ); ?></strong> <?php echo _e( 'pareto-security@protonmail.com', $this->_textdomain ); ?></p>
<?php
        }
        function condition_box() {
?>
<div class="divTopTable">
	<div class="divTableBody">
		<div class="divTopTableRow">
			<div class="divTopTableCell">
				<div class="divMainTable">
					<div class="divMainTableBody">
						<div class="divTableRow">
							<div class="divHeaders"><strong>&nbsp;<strong><?php echo esc_html( 'Standard Mode:', $this->_textdomain ); ?></strong></strong></div>
							<div class="divHeaders"><strong>&nbsp;<strong><?php echo esc_html( 'Advanced Mode:', $this->_textdomain ); ?></strong></strong></div>
						</div>
						<div class="divTableRow">
							<div class="divTableCell">
								<dl>
									<dt>&nbsp;&nbsp;- <strong><?php echo _e( 'Standard Mode</strong> is the <strong>Recommended Setting!!!</strong>', $this->_textdomain ); ?></dt>
									<dt>&nbsp;&nbsp;- <?php echo esc_html( 'Hard ban attempts to attack the webserver', $this->_textdomain ); ?></dt>
									<dt>&nbsp;&nbsp;- <?php echo esc_html( 'Hard ban attempts to inject malicious code into the database', $this->_textdomain ); ?></dt>
									<dt>&nbsp;&nbsp;- <?php echo esc_html( 'Hard ban injection attempts via browser user-agents', $this->_textdomain ); ?></dt>
									<dt>&nbsp;&nbsp;- <?php echo esc_html( 'Does not filter User-Agent', $this->_textdomain ); ?></dt>
									<dt>&nbsp;&nbsp;- <?php echo esc_html( 'Advanced POST Filtering is disabled', $this->_textdomain ); ?></dt>
								</dl>
							</div>
							<div class="divTableCell">
								<div class="divTable">
									<div class="divTableBody">
										<div class="divTableRow">
											<div class="divAdvancedMode"><input type="hidden" name="<?php echo $this->get_field_name( 'ban_mode' ); ?>" id="<?php echo $this->get_field_id( 'ban_mode' ); ?>" value="1" />
                                            <label class="container"><input type="checkbox" name="<?php echo $this->get_field_name( 'advanced_mode' ); ?>" id="<?php echo $this->get_field_id( 'advanced_mode' ); ?>" value="1"
                                            <?php
                                              if ( ( isset( $this->options[ 'advanced_mode' ] ) &&
                                                      false !== ( bool ) $this->options[ 'advanced_mode' ] ) ||
                                                      false !== ( bool ) $this->_adv_mode ||
                                                      false !== ( bool ) $this->_hard_ban_mode ) { ?>checked<?php } ?> />
                                            <span class="checkmark"></span></label>
                                            </div>
											<div class="divAdvancedMode"><label for="<?php echo $this->get_field_id( 'advanced_mode' ); ?>"><?php _e( '<b>Set Advanced Mode</b>', $this->_textdomain ); ?></label></div>
										</div>
										<div class="divTableRow">
											<div class="divAdvancedMode">&nbsp;</div>
											<div class="divAdvancedMode"><?php echo _e( 'Note: For detailed descriptions, <a target="_blank" href="https://hokioisecurity.com/?p=343">click here</a>', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Hard ban attempts to attack the webserver', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Hard ban attempts to inject malicious code into the database', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Hard ban injection attempts via browser user-agents', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Advanced filtering of HTTP_HOST', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Soft Ban Bots', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Advanced POST Filtering', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Domain Name Safe List', $this->_textdomain ); ?>
                                                <br><?php echo esc_html( '- Filter login attempts', $this->_textdomain ); ?>
                                            </div>
										</div>
										<div class="divTableRow">
											<div class="divAdvancedMode">
                                                <label class="container"><input type="checkbox" name="<?php echo $this->get_field_name( 'hard_ban_mode' ); ?>" id="<?php echo $this->get_field_id( 'hard_ban_mode' ); ?>" value="1"
                                  <?php if ( !isset( $this->options[ 'advanced_mode' ] ) || ( isset( $this->options[ 'advanced_mode' ] ) &&
                                              false === ( bool ) $this->options[ 'advanced_mode' ] ) || false === ( bool ) $this->_adv_mode ) { ?>disabled="disabled"<?php } ?>
                                              <?php if ( isset( $this->options[ 'hard_ban_mode' ] ) &&
                                                         isset( $this->options[ 'advanced_mode' ] ) &&
                                                         false !== ( bool ) $this->_hard_ban_mode ) { ?>checked<?php } ?> />
                                            <span class="checkmark"></span></label></div>
											<div class="divAdvancedMode">- <label for="<?php echo $this->get_field_id( 'hard_ban_mode' ); ?>"><?php _e( '<strong>Hard Ban Mode</strong>', $this->_textdomain ); ?></label></div>
										</div>
										<div class="divTableRow">
											<div class="divAdvancedMode">&nbsp;</div>
											<div class="divAdvancedMode">- Add Attackers IP to ban list
                                            <br>- XML-RPC Flood Protection</div>
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
<?php
        }
        function notes_box() {
            $mode     = ( false === ( bool ) $this->_adv_mode ) ? esc_html( 'Standard', $this->_textdomain ) : esc_html( 'Advanced', $this->_textdomain );
            $ban_type = ( false !== ( bool ) $this->_adv_mode && false !== ( bool ) $this->_hard_ban_mode ) ? esc_html( 'Low, Medium and High severity requests added to banned IP list', $this->_textdomain ) : esc_html( 'Medium and High severity requests added to banned IP list', $this->_textdomain ); ?>
    <ul>
        <li><?php echo esc_html( '+ Status:', $this->_textdomain ); ?> <i><?php echo $mode; ?> Mode</i></li>
        <li><?php echo esc_html( '+ Server:', $this->_textdomain ); ?> <?php echo ( strlen( $_SERVER[ "SERVER_SOFTWARE" ] ) > 14 ) ? trim( substr( $_SERVER[ "SERVER_SOFTWARE" ], 0, 14 ) ) . "..." : $_SERVER[ "SERVER_SOFTWARE" ]; ?></li>
        <?php
            if ( file_exists( $this->htapath() ) && $this->get_file_perms( $this->htapath(), true, true ) && false === $this->is_iis() ) {
        ?>
        <li><?php echo _e( '+ Your <code>.htaccess</code> is configured correctly in <code>' . $this->get_dir() . '</code>', $this->_textdomain ); ?></li>
        <li>+ <?php echo ( $this->_adv_mode ) ? esc_html( 'Hard Ban', $this->_textdomain ) : esc_html( 'Soft Ban', $this->_textdomain ); ?>: <?php echo $ban_type; ?></li>
        <?php } else { ?>
        <li><?php echo _e( '- Your <code>.htaccess</code> file cannot be written to in <code>' . $this->get_dir() . '</code> Pareto Security will still soft ban attack vectors.', $this->_textdomain ); ?></li>
        <li><?php echo esc_html( '- Hard Ban:', $this->_textdomain ); ?> <?php echo $ban_type; ?></li>
        <?php } ?>
        <li><?php echo ( ( version_compare( phpversion(), '5.4', '>=' ) ) ? _e( '+ ', $this->_textdomain ) : _e( '- ', $this->_textdomain ) ) . _e( 'Your server is running PHP version ' . substr( phpversion(), 0, 3 ), $this->_textdomain ); ?>
        <?php echo ( version_compare( phpversion(), '5.4', '>=' ) ) ? _e( ' &#x2713&#x2713&#x2713; ', $this->_textdomain ) : _e( ' <b>WARNING:</b> This version is insecure. Contact your webhost to upgrade to at least PHP 5.4', $this->_textdomain ); ?></li>
    </ul>
       <?php }
       function logfile_box() { ?>
       
       <table style="width: 100%; text-align: left; background-color: #C9C9C9;">
            <tr>
                <td>
                <table style="width: 100%; text-align: left;">
                    <tbody>
                      <tr style="background-color:#5F607B">
                        <td style="padding:0px 3px 3px 3px;width:100px;color:#FFFFFF"><b><?php echo esc_html( 'Date-Time:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:60px;color:#FFFFFF"><b><?php echo esc_html( 'Severity:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:120px;color:#FFFFFF"><b><?php echo esc_html( 'Source IP Address:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:50px;color:#FFFFFF"><b><?php echo esc_html( 'Req:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:100px;color:#FFFFFF"><b><?php echo esc_html( 'Filename:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;color:#FFFFFF"><b><?php echo esc_html( 'Vector:', $this->_textdomain ); ?></b></font></td>
                      </tr>
                      <tr>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td></td>
                      </tr>
<?php
        $mylogs     = array();
        $mylogs_fin = array();
        $mylogs     = $this->logs;
        $i          = 0;
        $text_color = "#e68735";
        
        while ( $i <= 99 ) {
            if ( isset( $mylogs[ $i ] ) ) {
                $row_colour = ( $i % 2 == 0 ) ? "#F3F3F3" : "#FFFFFF";
                $req_var    = explode( " ", $mylogs[ $i ] );
                if ( strtolower( $req_var[ 1 ] ) == "low" ) {
                    if ( false === ( bool ) $this->_adv_mode ) {
                        $i++;
                        continue;
                    }
                    $text_color = "#517ecf";
                } elseif ( $req_var[ 1 ] == "Medium" ) {
                    $text_color = "#e68735";
                } elseif ( empty( $req_var[ 1 ] ) ) {
                    $req_var[ 1 ] = "Medium";
                    $text_color   = "#e68735";
                } else
                    $text_color = "#c72b2c";
                if ( $req_var[ 1 ] == "Safe" ) $text_color = "#517ecf";
                $mylogs_fin[ $i ] = $mylogs[ $i ];
                $ip_addr = $req_var[ 2 ];
                if ( false === $this->is_server( $req_var[ 2 ] ) && $this->check_ip( $req_var[ 2 ] ) ) {
                    $ip_addr = ( false !== ( bool ) $this->check_ip( $req_var[ 2 ] ) ) ? ' <a target="_blank" href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a' . $req_var[ 2 ] . '&run=networktools">[Blacklist]</a>
                                                                                           <a target="_blank" href="https://www.whois.com/whois/' . $req_var[ 2 ] . '">' . $req_var[ 2 ] . '</a>' : 'Invalid IP';
                }
                if ( $req_var[ 1 ] == "Safe" ) {
                    $req_var[ 0 ] = str_replace( '%20', ' ', $req_var[ 0 ] );
                    $text_color   = "#517ecf";
                }
                $this_timestamp = $req_var[ 0 ];
                if ( $req_var[ 1 ] != "Safe" ) {
                    $this_timestamp = ( false !== strpos( $this_timestamp, 'AM' ) || false !== strpos( $this_timestamp, 'PM' ) ) ?
                                      ( false !== strpos( $this_timestamp, 'AM' ) ? substr( $this_timestamp, 0, strpos( $this_timestamp, 'AM' ) ) . ' AM' : substr( $this_timestamp, 0, strpos( $this_timestamp, 'PM' ) ) . ' PM' ) : $this_timestamp ;
                }
                $attack_string = str_replace( '%20', " ", preg_replace( "/[\n]/i", "", stripslashes( $req_var[ 5 ] ) ) );
                        echo "<tr style=\"font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;color:#3E3E3E;background-color:" . $row_colour . "\">" . "
                        <td style=\"padding:3px 3px 3px 3px;vertical-align:top;width:100px; white-space: nowrap\">" . $this_timestamp . "</td>" . "
                        <td style=\"padding:3px 3px 3px 3px; vertical-align:top;text-align:center; width:60px; white-space: nowrap; font-weight: bold; color:" . $text_color . "\">" . $req_var[ 1 ] . "</td>" . "
                        <td style=\"padding:3px 3px 3px 3px; vertical-align:top; width:120px; white-space: nowrap\">" . $ip_addr . "</td>" . "
                        <td style=\"padding:3px 3px 3px 3px; vertical-align:top; text-align:center; width:50px; white-space: nowrap\">" . $req_var[ 3 ] . "</td>" . "
                        <td style=\"padding:3px 3px 3px 3px; vertical-align:top; width:100px; white-space: nowrap\">" . $req_var[ 4 ] . "</td>" . "
                        <td style=\"padding:3px 3px 3px 3px; vertical-align:top;\"><code>" . $attack_string . "</code></td>" . "</tr>";
            } else
                break;
            $i++;
        }
?>
               </table>
                </td>
            </tr>
        </table>
<?php
        }
        function do_settings_box() {
            if ( ( false !== ( bool ) defined( 'WP_ADMIN' ) && false !== WP_ADMIN ) && ( false !== ( bool ) is_admin() ) ) {
                do_settings_sections( $this->_textdomain );
            }
        }        
    } // end class
else:
    // pareto_settings.php called directly
    require_once( 'pareto_functions.php' );
    $ParetoSecurity = new pareto_functions();
    $ParetoSecurity->send444();
endif;
?>
