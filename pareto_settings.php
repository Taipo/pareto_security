<?php
if ( class_exists( "pareto_functions" ) ):
    class pareto_settings extends pareto_functions {
        function __construct() {
            if ( false !== $this->is_wp() ) {
                $this->time_zone = date_default_timezone_get() . get_option( 'gmt_offset' );
                define( 'PARETO_DIR', plugin_dir_path( __FILE__ ) );
                define( 'PARETO_URL', plugin_dir_url( __FILE__ ) );
                
                load_plugin_textdomain( $this->_textdomain );
                // Register style sheet
                add_action( "admin_enqueue_scripts", array( $this, 'enqueue_scripts' ) );
                $this->kickoff();
            } else return;
        }
        function get_ver( $file ) {
            return filemtime( PARETO_DIR );
        }
        /**
         * Register style sheet.
         */
        function enqueue_scripts( $hook ) {
            if ( $hook != 'toplevel_page_pareto_security_settings' ) {
                    return;
            }
            wp_register_style( 'pareto-security', plugins_url( 'css/pareto_style.css' ) );
            wp_enqueue_style( "{$this->prefix}_style", plugins_url( 'css/pareto_style.css', __FILE__ ), NULL, $this->get_ver( 'css/pareto_style.css' ) );
            wp_enqueue_script( "{$this->prefix}_js", plugins_url( 'js/hokioi.js', __FILE__ ), NULL, $this->get_ver( 'js/hokioi.js' ) );
        }
        function kickoff() {
            $this->settings_field = 'pareto_security_settings_options';
            $this->options = get_option( $this->settings_field );
            if ( empty( $this->options ) ) {
                update_option( $this->settings_field, array( // set defaults
                     'advanced_mode' => 0,
                     'hard_ban_mode' => 0,
                     'email_report' => 0,
                     'ban_mode' => 0,
                     'admin_ip' => '',
                     'tor_block' => 0
                ) );
                $this->options = get_option( $this->settings_field );
            }
            
            $this->options[ 'ban_mode' ]      = ( false !== $this->check_settings( 'ban_mode' ) ) ? ( int ) $this->options[ 'ban_mode' ] : 0;
            $this->options[ 'email_report' ]  = ( false !== $this->check_settings( 'email_report' ) ) ? ( int ) $this->options[ 'email_report' ] : 0;
            $this->options[ 'advanced_mode' ] = ( false !== $this->check_settings( 'advanced_mode' ) ) ? ( int ) $this->options[ 'advanced_mode' ] : 0;
            $this->options[ 'hard_ban_mode' ] = ( false !== $this->check_settings( 'hard_ban_mode' ) ) ? ( int ) $this->options[ 'hard_ban_mode' ] : 0;
            $this->options[ 'tor_block' ]     = ( false !== $this->check_settings( 'tor_block' ) ) ? ( int ) $this->options[ 'tor_block' ] : 0;
            
            $this->_hard_ban_mode = $this->options[ 'hard_ban_mode' ];
            if ( array_key_exists( 'safe_list', $this->options ) ) {
                $this->_domain_list = $this->get_field_value( $this->options, 'safe_list' );
                $this->_domain_list = preg_replace( '/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F]/', '', $this->_domain_list ); // strip out any control characters but not new lines and carriage returns
                $this->_domain_list = preg_replace( "/[^\r\na-zA-Z0-9_\.\-]/i", '', $this->_domain_list ); // allow only alphanumeric and -_.
                $this->options[ 'safe_list' ] = $this->_domain_list;
            }
            
            $this->logs = get_option( PARETO_LOG_LIST );
            # only available to logged in Admins
            if ( false !== ( bool ) $this->is_wp( true, true ) ) {
                $this->define_plugin_settings();
                $this->page_id        = $this->_textdomain;
                $this->lockdown_status = $this->lockdown_mode( $this->logs ); //( bool ) $this->get_field_value( $this->lockdown, 'lockdown_mode' );
                
                if ( $this->cmpstr( $_SERVER[ 'REQUEST_METHOD' ], 'POST' ) ) {
                    # localise POST
                    $this_post = $_POST;
                    if ( isset( $this_post[ 'save_options' ] ) && $this->cmpstr( strtolower( $this_post[ 'save_options' ] ), 'save options' ) ) {
                        if ( isset( $this_post[ $this->settings_field ][ "safe_list" ] ) ) {
                            $this_post[ $this->settings_field ][ "safe_list" ] = $this->host_check( $this_post[ $this->settings_field ][ "safe_list" ] );
                        }
                        if ( isset( $this_post[ $this->settings_field ][ "ban_mode" ] ) )
                            $this_post[ $this->settings_field ][ "ban_mode" ] = ( int ) $this_post[ $this->settings_field ][ "ban_mode" ];
                        if ( isset( $this_post[ $this->settings_field ][ "advanced_mode" ] ) ) {
                            $this_post[ $this->settings_field ][ "advanced_mode" ] = ( int ) $this_post[ $this->settings_field ][ "advanced_mode" ];
                            if ( !isset( $this_post[ $this->settings_field ][ "safe_list" ] ) || empty( $this_post[ $this->settings_field ][ "safe_list" ] ) ) $this_post[ $this->settings_field ][ "safe_list" ] = $this->get_http_host();
                        } else $this_post[ $this->settings_field ][ "advanced_mode" ] = 0;
                        if ( isset( $this_post[ $this->settings_field ][ "email_report" ] ) )
                            $this_post[ $this->settings_field ][ "email_report" ] = ( int ) $this_post[ $this->settings_field ][ "email_report" ];
                        if ( isset( $this_post[ $this->settings_field ][ "hard_ban_mode" ] ) ) {
                            $this_post[ $this->settings_field ][ "hard_ban_mode" ] = ( int ) $this_post[ $this->settings_field ][ "hard_ban_mode" ];
                        } 
                        if ( isset( $this_post[ $this->settings_field ][ "tor_block" ] ) ) {
                            $this_post[ $this->settings_field ][ "tor_block" ] = ( int ) $this_post[ $this->settings_field ][ "tor_block" ];
                        } else $this_post[ $this->settings_field ][ "tor_block" ] = 0;
                    }
                    if ( isset( $this_post[ 'save_options' ] ) && $this->cmpstr( strtolower( $this_post[ 'save_options' ] ), 'x' ) ) {
                        # Do logs
                        $ulid = array();
                        foreach( $this_post as $key => $val ) {
                            if ( false !== strpos( $key, 'ulid' ) && false === strpos( $key, 'ulid_check_' ) ) $ulid[] = ( strlen( $key ) <= 8 && $this->cmpstr( 'ulid_', substr( $key, 0, 5 ) ) ) ? trim( substr( $key, 0, 8 ) ) : '';
                        }
                        $ulid_shorthash = array();
                        foreach ( $ulid as $key => $val ) {
                            if ( !empty( $val ) ) {
                                $this_val = 'ulid_check_' . substr( $this_post[ $val ], 0, 6 );
                                if ( isset( $this_post[ $this_val ] ) && $this->cmpstr( 'on', $this_post[ $this_val ] ) ) {
                                    $shahash = preg_replace( "/[^a-f0-9]/i", '', $this_post[ $val ] );
                                    $shahashlen = strlen( $shahash );
                                    $ulid_shorthash[ $this_val ] = ( $this->cmpstr( 40, $shahashlen ) ) ? $shahash : '';
                                }
                            }
                        }
                        $this->log_pop( $ulid_shorthash );
                    }
                    $_POST = $this_post;
                } else {
                    # clean up failed login hashes
                    $this->iphash_db_cleanup();
                }
                add_action( 'admin_init', array(
                     $this,
                    'admin_init' 
                ), 20 );
                add_action( 'admin_menu', array(
                     $this,
                    'admin_menu' 
                ), 20 );
                $this->ip_count = $this->count_banned_ips();
            }
            # end of only available to logged in Admins

            $this->_adv_mode      = $this->get_field_value( $this->options, 'advanced_mode' );
            $this->_ban_mode      = $this->get_field_value( $this->options, 'ban_mode' );
            $this->_email_report  = $this->get_field_value( $this->options, 'email_report' );
            $this->_tor_block     = $this->get_field_value( $this->options, 'tor_block' );
            if ( isset( $this->options[ 'server_ip' ] ) ) $this->_server_ip     = $this->get_field_value( $this->options, 'server_ip' );

            if ( false !== $this->is_wp( false, true, false ) ) { // if is an admin
                $this->update_logfile( $this->logs ); // set $this->logs
                $this->update_admin_ip( $this->get_ip() ); // Prevents the banning of admin IP addresses
            } else $this->options[ 'admin_ip' ] = '';
        }
        function define_plugin_settings() {
            $basename = plugin_basename( __FILE__ );
            $prefix = is_network_admin() ? 'network_admin_' : '';
            add_filter( 'plugin_action_links', array( $this, 'add_plugin_action_links'), 10, 2);
            add_action( 'admin_menu', array( $this, 'add_to_admin_menu' ) );
            $this->options[ 'admin_ip' ] = $this->get_ip();
        }
        function add_plugin_action_links( $links, $file ) {
            if ( strstr( $file, 'pareto-security/pareto_security.php' ) ) {
                $settings[ 'settings' ] = '<a href="'. esc_url( admin_url( "options-general.php?page=" . $this->_textdomain ) ) . '">Settings</a>';
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
        function log_pop( $ulid ) {
            $get_logs = $this->logs;
            foreach ( $ulid as $ukey => $hash ) {
                foreach( $get_logs as $key => $val ) {
                    $this_log = explode( ' ', $val );
                    if ( isset( $this_log[ 6 ] ) && $this->cmpstr( sha1( $this_log[ 6 ] ), $hash ) ) {
                        $ip = $this_log[ 2 ];
                        if ( false !== $this->check_ip( $ip, true ) ) {
                            $this->htaccess_unbanip( false, $ip );
                            unset( $get_logs[ $key ] );
                            break 1;
                        }
                    }

                }
            }
            $final_logfile = array();
            foreach( $get_logs as $key => $val ) {
                $final_logfile[] = $val;
            }
            $this->logs = $final_logfile;
            update_option( PARETO_LOG_LIST, $final_logfile );
        } 
        function count_banned_ips() {
            if ( false === $this->htapath() ) return 0;
            if ( file_exists( $this->htapath() ) ) {
                $mybans = file( $this->htapath() );
            } else return 0;
            if ( empty( $mybans ) ) return 0;
            $mybans_denyfrom = array();
            $mybans_denyfrom = $this->find_in_array( "deny from ", $mybans );
            return count( $mybans_denyfrom );         
        }
        function find_in_array( $string, $array = array(), $makebool = false ) {       
            foreach ( $array as $key => $value ) {
                unset ( $array[ $key ] );
                if ( false === strpos( $value, $string . 'all' ) && false !== strpos( $value, $string ) ) {
                    $array[ $key ] = $value;
                }
            }       
            if ( false !== $makebool ) return !empty( $array ); // return Boolean
            if ( false === $makebool ) return $array; // return instances of string
        }
        
        function update_logfile( $logfile = array() ) {
            $tmp_logfile = array();
            if ( empty( $this->logs ) ) {
                update_option( PARETO_LOG_LIST, array(
                     0 => SETTINGS_INSTALL_LOG ) );
                    $logfile = SETTINGS_INSTALL_LOG;
                    $this->logs = array();
                    $this->logs[ 0 ] = SETTINGS_INSTALL_LOG;
                    return;
            }
            $final_log = strtolower( substr( $this->logs[ count( $this->logs ) - 1 ], 0, 50 ) );

            # make sure install log remains
            #if ( count( $this->logs ) < 100 && false === strpos( $final_log, 'safe' ) ) {
            if ( count( $this->logs ) >= 99 && false === in_array( SETTINGS_INSTALL_LOG, $this->logs ) ) {
                array_pop( $this->logs );
                array_push( $this->logs, SETTINGS_INSTALL_LOG );
                update_option( PARETO_LOG_LIST, $this->logs );
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
            register_setting( PARETO_LOG_LIST, PARETO_LOG_LIST );
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
                    } elseif ( $this->cmpstr( $val, 'safe_list' ) ) {
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
            <form name="LogFile" method="post" action="options.php">
                <div class="metabox-holder">
                    <div class="postbox-container" style="width: 99%;">
 <?php
            // Render metaboxes
            settings_fields( $this->settings_field );
            do_meta_boxes( $this->pagehook, 'main', null );
            if ( isset( $wp_meta_boxes[ $this->pagehook ][ 'column2' ] ) ) do_meta_boxes( $this->pagehook, 'column2', null );
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
            add_meta_box( 'pareto-security-settings-donations', esc_html( 'Donations', $this->_textdomain ), array(
                 $this,
                'donations_box' 
            ), $this->pagehook, 'main' );
            add_meta_box( 'pareto-security-settings-logs', esc_html( 'Last 100 Incidents', $this->_textdomain ), array(
                 $this,
                'logfile_box' 
            ), $this->pagehook, 'main' );
        }
        
        function safelist_box() {
            if ( false === $this->_adv_mode ) return;
            $is_https  = ( ( array_key_exists( 'HTTPS', $_SERVER ) && $this->cmpstr( "on", @$_SERVER[ "HTTPS" ] ) ) ||
                           ( false !== getenv( 'HTTPS' ) && array_key_exists( 'HTTPS', getenv() ) && $this->cmpstr( "on", getenv( "HTTPS" ) ) ) ) ? true : false;
            $http      = ( false !== $is_https ) ? 'https://' : 'http://';
            $url       = str_replace( 'www.', '', $this->get_http_host() );
            $hsts_url  = 'https://hstspreload.org/?domain=' . $url;
            $hsts_link = '<a title="Register your domain with Google Chromes preload list" target="_blank" href="' . $hsts_url . '">' . $hsts_url . '</a>';
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
                    <td><input type="submit" class="button button-primary" name="save_options" value="<?php esc_attr_e( 'Save Options', $this->_textdomain ); ?>" /></td>
                </tr>
            </table>
<?php
        }
        function info_box() {
?>
           <table style="text-align: left;">
                <tr>
                    <td><strong><?php echo esc_html( 'Version:', $this->_textdomain ); ?></strong> <?php echo self::PARETO_VERSION; ?> <?php echo '&middot;'; ?> <strong><?php esc_html( 'Released:', $this->_textdomain ); ?></strong><?php echo PARETO_RELEASE_DATE; ?> ( <?php echo $this->time_zone; ?> )</td>
                    <td><strong><?php echo esc_html( 'Author:', $this->_textdomain ); ?></strong> <a title="Authors Twitter Account" target="_blank" href="https://twitter.com/te_taipo">@te_taipo</a></td>
                    <td><strong><?php echo esc_html( 'Web:', $this->_textdomain ); ?></strong> <a title="Authors Website" target="_blank" href="https://hokioisecurity.com">https://hokioisecurity.com</a></td>
                    <td><strong><?php echo esc_html( 'Email:', $this->_textdomain ); ?></strong> pareto-security@hokioisecurity.com</td>
                </tr>
                <tr>
                    <td colspan=3><strong><?php echo esc_html( 'Rate This Plugin:', $this->_textdomain ); ?></strong> <a title="Rate this plugin" href="https://wordpress.org/support/plugin/pareto-security/reviews/" target="_blank"><?php echo esc_html( 'Rate this plugin 5 stars on WordPress.org', $this->_textdomain ); ?></a>
                    </td>
                </tr>
            </table>
<?php
        }
        
        function donations_box() {
?>      <p>This plugin will always be completely free. If you feel it is beneficial to your website you can help in its upkeep by making a micro-donation below<br />
        <ul>
            <li><a title="Donate by supporting my patreon" href="https://patreon.com/te_taipo" target="_blank">https://patreon.com/te_taipo</a></li>
            <li><a title="Buy me a cup of coffee" href="https://ko-fi.com/te_taipo" target="_blank">https://ko-fi.com/te_taipo</a></li>
        </ul>
</p>
        <p><strong>Go to</strong> <a title="Other ways to support the development and maintenance of this plugin" href="https://hokioisecurity.com/donations/" target="_blank">https://hokioisecurity.com/donations/</a> to see more ways to support</p>
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
                                    <dt>&nbsp;&nbsp;- <?php echo esc_html( 'Lockdown Mode: Auto Detect Denial of Service Attack', $this->_textdomain ); ?></dt>
                                    <dt>&nbsp;&nbsp;- <?php echo esc_html( 'Advanced POST Filtering', $this->_textdomain ); ?></dt>
                                    <dt>&nbsp;&nbsp;- <?php echo esc_html( 'Filter login attempts :: detect and ban User/Password Cracking Attack', $this->_textdomain ); ?></dt>
                                    <dt>&nbsp;&nbsp;- <?php echo esc_html( 'XML-RPC Flood Protection - detect and ban User/Password Cracking Attack', $this->_textdomain ); ?></dt>                                  
								</dl>
							</div>
							<div class="divTableCell">
								<div class="divTable">
									<div class="divTableBody">
										<div class="divTableRow">
											<div class="divAdvancedMode"><input type="hidden" name="<?php echo $this->get_field_name( 'ban_mode' ); ?>" id="<?php echo $this->get_field_id( 'ban_mode' ); ?>" value="1" />
                                            <label class="container"><input type="checkbox" name="<?php echo $this->get_field_name( 'advanced_mode' ); ?>" id="<?php echo $this->get_field_id( 'advanced_mode' ); ?>" value="1" <?php
                                              if ( ( isset( $this->options[ 'advanced_mode' ] ) &&
                                                      false !== ( bool ) $this->options[ 'advanced_mode' ] ) ||
                                                      false !== ( bool ) $this->_adv_mode ) { ?>checked<?php } ?> />
                                            <span class="checkmark"></span></label>
                                            </div>
											<div class="divAdvancedMode"><label for="<?php echo $this->get_field_id( 'advanced_mode' ); ?>"><?php _e( '<b>Set Advanced Mode</b>', $this->_textdomain ); ?></label></div>
										</div>
										<div class="divTableRow">
											<div class="divAdvancedMode">&nbsp;</div>
											<div class="divAdvancedMode"><?php echo esc_html( '- Advanced filtering of the server host variable', $this->_textdomain ); ?>
                                                
                                                <br><?php echo esc_html( '- Domain Name Safe List', $this->_textdomain ); ?>
                                            </div>
										</div>
                                        <?php ?>
                                        <div class="divTableRow">
											<div class="divAdvancedMode">
                                                <label class="container"><input type="checkbox" name="<?php echo $this->get_field_name( 'tor_block' ); ?>" id="<?php echo $this->get_field_id( 'tor_block' ); ?>" value="1"
                                              <?php
                                              if ( isset( $this->options[ 'tor_block' ] ) &&
                                                   isset( $this->options[ 'advanced_mode' ] ) && $this->_tor_block == 1 ) { ?>checked<?php } ?> />
                                            <span class="checkmark"></span></label></div>
											<div class="divAdvancedMode"><label for="<?php echo $this->get_field_id( 'tor_block' ); ?>"><?php _e( '<strong>Block Tor Access</strong> WARNING: If you use Tor to access your admin, DO NOT ENABLE THIS!', $this->_textdomain ); ?></label></div>
										</div>
										
										<div class="divTableRow">
											<div class="divAdvancedMode">&nbsp;</div>
                                            <div class="divAdvancedMode">
                                                <?php echo esc_html( 'Prevent Tor users from:', $this->_textdomain ); ?>
                                            <br><?php echo esc_html( '- making log-in attempts, accessing XMLRPC', $this->_textdomain ); ?>
                                            <br><?php echo esc_html( '- making comments, using contact forms, and search functions', $this->_textdomain ); ?>
                                            <br><?php echo esc_html( 'Redirect users back to domain name', $this->_textdomain ); ?></div>
										</div>
										<?php ?>
										<div class="divTableRow">
											<div class="divAdvancedMode">
                                                <label class="container"><input type="checkbox" name="<?php echo $this->get_field_name( 'hard_ban_mode' ); ?>" id="<?php echo $this->get_field_id( 'hard_ban_mode' ); ?>" value="1"

                                              <?php if ( isset( $this->options[ 'hard_ban_mode' ] ) &&
                                                         false !== ( bool ) $this->_hard_ban_mode ) { ?>checked<?php } ?> />
                                            <span class="checkmark"></span></label></div>
											<div class="divAdvancedMode"><label for="<?php echo $this->get_field_id( 'hard_ban_mode' ); ?>"><?php _e( '<strong>Hard Ban Mode</strong>', $this->_textdomain ); ?></label></div>
										</div>
										<div class="divTableRow">
											<div class="divAdvancedMode">&nbsp;</div>
                                            <div class="divAdvancedMode">- Ban irregular user-agent/crawlers</div>
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
<br>
<label for="<?php echo $this->get_field_id( 'email_report' ); ?>" class="container"><?php echo _e( '<b>Email Notification:</b> Receive periodic notifications (every 5 events) of high/medium severity attacks', $this->_textdomain ); ?>
<input type="checkbox" name="<?php echo $this->get_field_name( 'email_report' ); ?>" id="<?php echo $this->get_field_id( 'email_report' ); ?>" value="1" <?php if ( ( isset( $this->options[ 'email_report' ] ) && false !== ( bool ) $this->options[ 'email_report' ] ) ) { ?>checked<?php } ?> /><span class="checkmark"></span></label>
<?php
        }
        function notes_box() {
            $mode     = esc_html( 'Standard Mode', $this->_textdomain );
            $mode     = ( false === ( bool ) $this->_adv_mode ) ? esc_html( 'Standard Mode', $this->_textdomain ) : esc_html( 'Advanced Mode', $this->_textdomain );
            $mode     = ( false !== ( bool ) $this->_tor_block ) ? esc_html( 'Advanced Mode, Tor Block Mode', $this->_textdomain ) : esc_html( $mode, $this->_textdomain );
            $mode     = ( false !== ( bool ) $this->_hard_ban_mode ) ? $mode . ', ' . esc_html( 'Hard Ban Mode', $this->_textdomain ) : esc_html( $mode, $this->_textdomain );
            $mode     = ( false !== $this->lockdown_status ) ? esc_html( 'Lockdown', $this->_textdomain ) : $mode;
            $ban_type = ( false !== ( bool ) $this->_adv_mode && false !== ( bool ) $this->_hard_ban_mode ) ? esc_html( 'Low, Medium and High severity requests added to banned IP list', $this->_textdomain ) : esc_html( 'Medium and High severity requests added to banned IP list', $this->_textdomain );
            $is_nginx = ( false === strpos( strtolower( $_SERVER[ "SERVER_SOFTWARE" ] ), "nginx" ) ) ? false : true;
            ?>
    <ul>
        <li><?php echo esc_html( '+ Status:', $this->_textdomain ); ?> <i><?php echo $mode; ?></i></li>
        <li><?php echo esc_html( '+ Server:', $this->_textdomain ); ?> <?php echo ( strlen( $_SERVER[ "SERVER_SOFTWARE" ] ) > 14 ) ? trim( substr( $_SERVER[ "SERVER_SOFTWARE" ], 0, 14 ) ) . "..." : $_SERVER[ "SERVER_SOFTWARE" ]; ?></li>
        <?php
            if ( false !== $this->htapath() && false === $this->is_iis() ) {
        ?>
        <?php if ( false === $is_nginx ) { ?><li><?php echo _e( '+ Your <code>.htaccess</code> is configured correctly in <code>' . $this->get_dir() . '</code>', $this->_textdomain ); ?></li>
        <li><?php echo _e( '+ There ' . ( ( $this->cmpstr( $this->ip_count, 1 ) ) ? 'is' : 'are' ) . ' currently [ ' . ( empty( $this->ip_count ) ? 0 : $this->ip_count ) . ' ] unique IP addresses banned by Pareto Security', $this->_textdomain ); ?></li>
        <li>+ <?php echo ( $this->_adv_mode ) ? esc_html( 'Hard Ban', $this->_textdomain ) : esc_html( 'Soft Ban', $this->_textdomain ); ?>: <?php echo $ban_type; ?></li>
        <?php } else { ?>
        <?php if ( false === $is_nginx ) { ?><li><?php echo _e( '- Your <code>.htaccess</code> file cannot be written to in <code>' . $this->get_dir() . '</code> Pareto Security will still soft ban attack vectors.', $this->_textdomain ); ?></li><?php } ?>
        <?php if ( false !== $is_nginx ) { ?><li><?php echo _e( '+ NGINX does not use .htaccess to ban IP addresses. Pareto Security will still block all attack vectors.', $this->_textdomain ); ?></li><?php } ?>
        <?php if ( false === $is_nginx ) { ?><li><?php echo esc_html( '- Hard Ban:', $this->_textdomain ); ?> <?php echo $ban_type; ?></li><?php } ?>
        <?php } ?>
        <?php } else { ?>
        <li>+ <?php if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT !== false ) { echo _e( 'DISALLOW_FILE_EDIT is set to true, preventing writing to .htaccess', $this->_textdomain ); ?>
        <?php }
        } ?>
        <li><?php echo ( ( version_compare( phpversion(), '7.0', '>=' ) ) ? _e( '+ ', $this->_textdomain ) : _e( '- ', $this->_textdomain ) ) . _e( 'Your server is running PHP version ' . substr( phpversion(), 0, 3 ), $this->_textdomain ); ?>
        <?php echo ( version_compare( phpversion(), '7.0', '>=' ) ) ? _e( ' &#x2713&#x2713&#x2713; ', $this->_textdomain ) : _e( ' <b>WARNING:</b> This version is insecure. Contact your webhost to upgrade to at least PHP 7.0', $this->_textdomain ); ?></li>
        <li><?php echo _e( '+ <a title="Smoke tests are performed shortly after Pareto Security is updated. If the smoke test site returns an error, please check again in a few days." target="_blank" href="https://plugintests.com/plugins/wporg/pareto-security/' . self::PARETO_VERSION . '">Click here</a> to view a smoke test was performed on Pareto Security version ' . self::PARETO_VERSION, $this->_textdomain ); ?></li>
    </ul>

       <?php }
       function logfile_box() { ?>
       <table style="width: 100%; text-align: left; background-color: #C9C9C9;">
            <tr>
                <td>
                <table class="hoverTable" style="width: 100%; text-align: left;">
                    <tbody>
                      <tr style="background-color:#5F607B">
                        <td style="padding:0px 3px 3px 3px;width:100px;color:#FFFFFF"><b><?php echo esc_html( 'Date-Time:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:70px;color:#FFFFFF"><b><?php echo esc_html( 'Severity:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:120px;color:#FFFFFF"><b><?php echo esc_html( 'Source IP Address:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:50px;color:#FFFFFF"><b><?php echo esc_html( 'Req:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;width:100px;color:#FFFFFF"><b><?php echo esc_html( 'Filename:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;color:#FFFFFF"><b><?php echo esc_html( 'Vector:', $this->_textdomain ); ?></b></font></td>
                        <td style="padding:0px 3px 3px 3px;color:#FFFFFF;width:30px;"><input name="multiselect" type="checkbox"  onclick="javascript:checkAll('LogFile', true);" /></td>
                         
                      </tr>
<?php
        $mylogs     = array();
        $mylogs_fin = array();
        $mylogs     = $this->logs;
        $i          = 0;
        $text_color = "#e68735";       
        while ( $i <= $this->_log_total ) {
            if ( isset( $mylogs[ $i ] ) ) {
                $row_colour = ''; // = ( $i % 2 == 0 ) ? "#F3F3F3" : "#FFFFFF";
                $req_var    = explode( " ", $mylogs[ $i ] );
                if ( $this->cmpstr( strtolower( $req_var[ 1 ] ), "low" ) ) {
                    $text_color = "#517ecf";
                } elseif ( $this->cmpstr( $req_var[ 1 ], "Medium" ) ) {
                    $text_color = "#e68735";
                } elseif ( empty( $req_var[ 1 ] ) ) {
                    $req_var[ 1 ] = "Medium";
                    $text_color   = "#e68735";
                } else
                    $text_color = "#c72b2c";
                $mylogs_fin[ $i ] = $mylogs[ $i ];
                $ip_addr = ( false !== $this->check_ip( $req_var[ 2 ], true ) ) ? $req_var[ 2 ] : '';
                if ( false === $this->is_server( $req_var[ 2 ] ) ) {
                    $ip_addr = ( false !== ( bool ) $this->check_ip( $req_var[ 2 ], true ) ) ? ' <a target="_blank" href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a' . $req_var[ 2 ] . '&run=networktools">[Blacklist]</a><a target="_blank" href="https://www.whois.com/whois/' . $req_var[ 2 ] . '">' . $req_var[ 2 ] . '</a>' : 'Invalid IP';
                }
                if ( $this->cmpstr( $req_var[ 1 ], "Safe" ) ) {
                    $req_var[ 0 ] = str_replace( '%20', ' ', $req_var[ 0 ] );
                    $text_color   = "#517ecf";
                }
                $this_timestamp = ( false !== is_numeric( $req_var[ 0 ] ) ) ? $this->set_timestamp( $req_var[ 0 ] ): $req_var[ 0 ];
                $uuid = ( isset( $req_var[ 6 ] ) ) ? sha1( preg_replace( "/[\n]/i", "", $req_var[ 6 ] ) ) : '';
                $ulid = ( !empty( $uuid ) ) ? "<input type=\"hidden\" name=\"ulid_" . $i . "\" value=\"" . $uuid . "\" />
                         <input title=\"Select Entry to Delete\" id=\"row" . $i . "\" class =\"checkbox\" type=\"checkbox\" name=\"ulid_check_" . substr( $uuid, 0, 6 ) . "\"/>
                         <input title=\"Delete Entries\" type=\"submit\" class=\"del-button\" name=\"save_options\" value=\"" . esc_html( 'x', $this->_textdomain ) . "\" />" : 'N/A';
                if ( $req_var[ 1 ] != "Safe" ) {
                    $this_timestamp = ( false !== strpos( $this_timestamp, 'AM' ) || false !== strpos( $this_timestamp, 'PM' ) ) ?
                                      ( false !== strpos( $this_timestamp, 'AM' ) ? substr( $this_timestamp, 0, strpos( $this_timestamp, 'AM' ) ) . ' AM' : substr( $this_timestamp, 0, strpos( $this_timestamp, 'PM' ) ) . ' PM' ) : $this_timestamp ;
                }
                $attack_string = str_replace( '%20', " ", preg_replace( "/[\n]/i", "", stripslashes( $req_var[ 5 ] ) ) );
                $attack_string = ( strlen( $attack_string ) > $this->_trim_log_entry ) ? substr( $attack_string, 0, ( $this->_trim_log_entry - 1 ) ) . "..." : $attack_string;
                $t = strtolower( $this->url_decoder( $attack_string ) );
                preg_match_all( "/exec|svg|javascript|script|alert|prompt|onload|onerror|fromcharcode|img src|iframe|vbscript|msgbox/i", $t, $matches );
                if ( !empty( $matches ) && ( count( $matches ) > 0 || count( $matches[ 0 ] ) > 0 ) ) {
                    $matches = array_unique( $matches[ 0 ] );
                    foreach( $matches as $match ) {
                        $t = str_replace( $match, preg_replace( '/^.{2}/', "$0 ", $match ), $t );
                    }
                    $attack_string = $t;
                }
                        echo "<tr style=\"font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;color:#3E3E3E;background-color:" . $row_colour . "\">" . "
                        <td title=\"Click Row to Select Log Entry\" onclick=\"checkRow(this, 'row" . $i . "');\" style=\"padding:3px 3px 3px 3px;vertical-align:top;width:100px; white-space: nowrap\">" . $this_timestamp . "</td>" . "
                        <td title=\"Click Row to Select Log Entry\" onclick=\"checkRow(this, 'row" . $i . "');\" style=\"padding:3px 3px 3px 3px; vertical-align:top;text-align:center; width:70px; white-space: nowrap; font-weight: bold; color:" . $text_color . "\">" . $req_var[ 1 ] . "</td>" . "
                        <td title=\"Click Row to Select Log Entry\" onclick=\"checkRow(this, 'row" . $i . "');\" style=\"padding:3px 3px 3px 3px; vertical-align:top; width:120px; white-space: nowrap\">" . $ip_addr . "</td>" . "
                        <td title=\"Click Row to Select Log Entry\" onclick=\"checkRow(this, 'row" . $i . "');\" style=\"padding:3px 3px 3px 3px; vertical-align:top; text-align:center; width:50px; white-space: nowrap\">" . $req_var[ 3 ] . "</td>" . "
                        <td title=\"Click Row to Select Log Entry\" onclick=\"checkRow(this, 'row" . $i . "');\" style=\"padding:3px 3px 3px 3px; vertical-align:top; width:100px; white-space: nowrap\">" . $req_var[ 4 ] . "</td>" . "
                        <td title=\"Click Row to Select Log Entry\" onclick=\"checkRow(this, 'row" . $i . "');\" style=\"padding:3px 3px 3px 3px; vertical-align:top;\">" . $attack_string . "</td>" . "
                        <td style=\"padding:3px 3px 3px 3px; vertical-align:top;width:30px;white-space: nowrap\">" . $ulid . "</td></tr>";
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
    $ParetoSecurity->send403();
endif;
