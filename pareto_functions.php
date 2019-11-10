<?php
class pareto_functions {
    private $_open_basedir = 0, $_banip = 0, $_quietscript = 0, $_get_ip_count = 0, $_total_ips = 500, $_post_filter_mode = 0, $_ban_time = 86400, $_hard_ban_count = 10;
    private $_doc_root, $_datalist, $_log_file, $_log_file_key;
    private $_bypassbanip = false, $_spider_bypass = false;
    private $_injectors = array(), $_ip_array = array(), $_get_all = array(), $_post_all = array();
    protected $lockdown_setting = 'pareto_security_lockdown', $_hard_ban_mode = false, $_tor_block = false, $_timestamp = '';
    protected $settings_field = 'pareto_security_settings_options', $ip_hash_list = 'pareto_security_ip_flood_list';
    public    $_trim_log_entry = 450, $_time_offset, $_adv_mode = 0, $safe_host = '';
	/**
	 * Pareto Security constructor.
	 *
	 */
    public function __construct() {
        if ( false !== $this->is_wp() ) {
            if ( !isset( $this->_time_offset ) ) $this->_time_offset = ( int ) get_option( 'gmt_offset' );
            $unix_time = $this->file_created();
            define( 'PARETO_RELEASE_DATE', date_i18n( 'F j, Y', $unix_time ) );
            define( 'SETTINGS_INSTALL_LOG', str_replace( ' ', '%20', PARETO_RELEASE_DATE ) . " Safe " . $_SERVER[ 'SERVER_ADDR' ] . " GET plugins.php Pareto%20Security%20Installed" );
            $this->do_filters();
            define( 'PARETO_LOG_LIST', 'pareto_security_log_list' );
        } else {
            define( 'PARETO_LOGS', __DIR__ . "/logs/" );
            $this->set_crypto_key_file();
        }
    }
	/**
	 * Runs through a series of WP filters
	 *
	 * @return void
	 */
    function do_filters() {
        if ( !function_exists( 'wp_delete_file' ) )  require_once ABSPATH . WPINC . '/functions.php'; 
        add_filter( 'wp_delete_file', array( $this, 'check_filenames' ) );
    }
	/**
	 * Check for AFD attempts
	 *
	 *
	 * @return array
	 */
    function check_filenames( $file ) {
        $file_path = $this->get_dir() . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads';
        if ( false === strpos( $file, $file_path ) ) {
            if ( false === $this->is_wp( false, true, true ) ) $this->karo( "Arbitrary File Deletion Attempt: " . $file, true, 'Medium', true );
        }
        return $file;
    }
	/**
	 * Sets error_reporting
	 *
	 * 
	 * @return void
	 */
    function _set_error_level() {
        $val = ( false !== $this->integ_prop( $this->_quietscript ) ) ? ( int ) $this->_quietscript : 0;
        @ini_set( 'display_errors', 0 );
        switch ( ( int ) $val ) {
            case ( 0 ):
                error_reporting( 6135 );
                break;
            case ( 1 ):
                error_reporting( 0 );
                break;
            case ( 2 ):
                error_reporting( 32767 );
                @ini_set( 'display_errors', 1 );
                break;
            default:
                error_reporting( 6135 );
        }
    }
    function http_status( $num ) {
        $http = array(
            200 => 'HTTP/1.1 200 OK',
            403 => 'HTTP/1.1 403 Forbidden',
            404 => 'HTTP/1.1 404 Not Found',
        );
        header( $http[ $num ] );
        return
            array(
                'code' => $num,
                'error' => $http[ $num ],
            );
    }     
	/**
	 * Custom 403 Access Denied
	 *
	 * 
	 * @return void
	 */
    function send403() {
        $this->http_status( 403 );
        exit();
    }
    /**
     * Send custom 200 OK denied 
     *
     * return void
     */
    function send200() {
        $this->http_status( 200 );
        exit();
    }
	/**
	 * Activates the plugin
	 *
	 * @return void
	 */
    public function _activate() {
        update_option( PARETO_LOG_LIST, array(
             0 => SETTINGS_INSTALL_LOG ) );
        update_option( $this->settings_field, array( // set defaults
             'advanced_mode' => 0,
             'hard_ban_mode' => 0,
             'email_report' => 1,
             'ban_mode' => 0,
             'tor_block' => 0
        ) );
        update_option( $this->ip_hash_list, array() );
    }
	/**
	 * Deactivates the plugin
	 *
	 * 
	 * @return void
	 */
    public function _deactivate() {
        if ( false !== $this->get_file_perms( $this->htapath(), true, true ) ) {
            # clear IP addresses from HTACCESS
            $this->htaccess_unbanip();
        }
        update_option( PARETO_LOG_LIST, "" );
        update_option( $this->settings_field, "" );
        update_option( $this->ip_hash_list, array() );
    }
	/**
	 * Prevent page execution
	 * Trigger logging
	 * Ban Ip Address
	 * 
	 * @return void
	 */
    function karo( $req = '', $t = false, $severity = '', $log_only = false, $safelist_url = '' ) {
        if ( $this->cmpstr( $severity, '' ) ) {
            $ban_type = 'Medium';
        } else $ban_type = $severity;

        $is_wp = $this->is_wp();
        $req      = ( $this->cmpstr( substr( $req, 0, 2 ), "/?" ) ) ? substr( $req, 2 ) : $req;
        $req      = ( $this->cmpstr( substr( $req, 0, 1 ), "/" ) ) ? substr( $req, 1 ) : $req;
        
        if ( false === $is_wp ) {
            if ( false !== $this->logfile_name() )
                $this->_log_file = $this->logfile_name();
            if ( false === $this->logfile_exists() ) $this->create_fileset();
        }

        $this_ip = $this->get_ip();
        $block_request = false;
        $is_admin_ip = false;
        if ( false !== $is_wp ) {
            $is_admin_ip = $this->is_admin_ip();
        }
        $block_request = ( false !== $this->is_iis() ||
                  false === ( bool ) $t ||
                  false !== $this->is_server( $this_ip ) ||
                  false !== $this->_bypassbanip ||
                  false !== $is_admin_ip ) ? true : false;
        $is_registered = false;
        if ( false !== $is_wp ) {
            $is_registered = true;
            $this_user = $this->get_wp_current_user();
            if ( strlen( $this_user ) > 0 ) $req = ( false !== $is_registered ) ? 'User: ' . $this_user . ' :: ' . $req : $req;
            if ( false === $log_only || false !== $is_admin_ip || ( $this->is_server( $this_ip ) && $this->cmpstr( 'wp-cron.php', $this->get_filename() ) ) ) {
                $req = '[Notice] ' . $req . ' (WP Admin IP)';
                $ban_type = 'Safe';
            } elseif ( false !== $block_request ) {
                $req = '[Blocked] ' . $req;
            } else {
                $req = '[Banned] '. $req;
            }
        }
        #$req = ( false !== $is_admin_ip ) ? $req . ' (WP Admin IP)' : $req;
                      
        # create the log entry
        # set $lockdown_mode
        $this->log_request( $req, $ban_type );

        # Give a logged in WP Admins a pass only when posting data
        # if notification only
        if ( false !== $this->is_wp( false, true ) || false === $log_only ) return;

        # Do not ban or block the following
        if ( false !== $this->cmpstr( $ban_type, 'Safe' ) || false !== $is_admin_ip ) return;

        # add IP address or return 403 only
        if ( false === $block_request ) $this->htaccessbanip( $this_ip );
        $this->send403();
    }
    function file_created() {
        $file_created = filemtime( __FILE__  );
        return $this->updated( $file_created, $this->_time_offset );
    }
	/**
	 * Create the log entry
	 * 
	 * @return void
	 */
    function write_log( $req = "", $req_orig = "", $ban_type ) {
        $logfile = array();
        $ban_type = strtolower( $ban_type );
        $logfile = get_option( PARETO_LOG_LIST );
        $req_orig  = $this->htmlentities_safe( $req_orig );
        # set lockdown mode
        if ( false !== $this->lockdown_mode( $logfile ) ) return; // no email notifications or entries into DB

        if ( isset( $this->options[ 'email_report' ] ) && false !== $this->options[ 'email_report' ] || $this->cmpstr( 'medium', $ban_type, true ) || $this->cmpstr( "high", $ban_type, true ) ) {
            $x = 0;
            # count medium and high log entries
            foreach( $logfile as $key => $val ) {
                $short_val = strtolower( substr( $val, 0, 79 ) );
                if ( ( false !== strpos( $short_val, "high" ) || false !== strpos( $short_val, "medium" ) ) && false === strpos( $short_val, "[blocked]" ) && false === strpos( $short_val, " safe " ) ) $x++;
            }        
            # email every 5 entries
            $ban_type = ucfirst( $ban_type );
            if ( false === $this->cmpstr( 'Safe', $ban_type, true ) && false === $this->cmpstr( 'Low', $ban_type, true ) ) {
                $logged_count = ( string ) ( $x / 5 );
                if ( false !== ( bool ) $this->_email_report && $x != 0 && false !== ctype_digit( $logged_count ) ) {
                    $text_color = ( $this->cmpstr( 'Medium', $ban_type, true ) ) ? "#e68735" : "#c72b2c";
                    $this->email_log( "\n<tr style=\"background-color: #F3F3F3\">\n" . "    <td style=\"font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;vertical-align:top; width:100px; white-space: nowrap\">" . $this->set_timestamp( time() ) . "</td>\n
                                             <td style=\"vertical-align:top; text-align: center; width:70px; white-space: nowrap; font-size:11px;white-space:nowrap; font-family:Verdana,Tahoma,Arial,sans-serif;font-weight: bold; color:" . $text_color . "\">" . $ban_type . "</td>\n
                                             <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:140px; white-space: nowrap\">" . $this->get_ip() . "</td>\n
                                             <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:50px; white-space: nowrap\">" . $_SERVER[ 'REQUEST_METHOD' ] . "</td>\n
                                             <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:100px; white-space: nowrap\">" . $this->get_filename() . "</td>\n
                                             <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;white-space: nowrap\"><code>" . $req_orig . "</code></td>\n
                                        </tr>" );
                }
            }
        }
        
        # Insert new entry
        array_unshift( $logfile, $req );
        if ( !empty( $logfile ) ) {
            $mylogs    = array();
            $log_total = ( ( $l_count = count( $logfile ) ) >= 100 ) ? 100 : $l_count;
            for ( $x = 0; ( $x <= $log_total && !empty( $logfile[ $x ] ) ); $x++ ) {
                $mylogs[ $x ] = $logfile[ $x ];
            }
            update_option( PARETO_LOG_LIST, $mylogs );
        }
    }
	/**
	 * Test attack rate, trigger lockdown
	 *
	 * @param $logfile = array()
	 * 
	 * @return void
	 */
    function lockdown_mode( $logfile ) {
        if ( empty( $logfile ) || 10 > count( $logfile ) ) return false;
        $timestamps = array();
        # only testing the last 10 timestamps.
        for ( $x = 0; $x <= 9; $x++ ) {
            $ts = $logfile[ $x ];
            if ( false !== is_numeric( trim( substr( $ts, 0, 10 ) ) ) ) {
                $ts = trim( substr( $ts, 0, 10 ) );
                $ts = $this->updated( $ts, $this->_time_offset );
                $timestamps[] = ( int ) $ts;
            } else {
                $ts = str_replace( '<br>', ' ', $ts );
                $ts = substr( $ts, 0, 27 );
                $ts = explode( ' ' , $ts );
                $timestamps[] = strtotime( $ts[ 0 ] . $ts[ 1 ] );
            }
        }
        # 10 entries in 10 minutes = trigger lockdown mode
        if ( 600 >= ( int ) ( time() - ( int ) $timestamps[ 9 ] ) ) {
            return true;
        } else {
            return false;
        }
    }
	/**
	 * Create the log entry if not Wordpress
	 * 
	 * @return void
	 */
    function write_log_non_wp( $req = "", $htpath ) {
        $logfile = PARETO_LOGS . $this->_log_file;
        if ( file_exists( $logfile ) ) {
            @chmod( $logfile, 0666 );
            $fp = fopen( $logfile, 'a' );
            fwrite( $fp, $req );
            fclose( $fp );
            $mylogs_tmp = array_reverse( file( $logfile ) );
            $mylogs     = array();
            $log_total  = ( ( $l_count = count( $mylogs_tmp ) ) >= 100 ) ? 99 : $l_count;
            for ( $x = 0; ( $x <= $log_total && !empty( $mylogs_tmp[ $x ] ) ); $x++ ) {
                $mylogs[ $x ] = $mylogs_tmp[ $x ];
            }
            $fp = fopen( $logfile, 'w' );
            fwrite( $fp, implode( array_reverse( $mylogs ), "" ) );
            fclose( $fp );
            chmod( $logfile, 0644 );
        }
    }
	/**
	 * Create a unique log string
	 * 
	 * @return string
	 */
    function get_ulid() {
        $ulid = substr( $this->cleanString( 6, $this->do_bcrypt( $this->get_wp_key(), 12 ) ), -16 );
        return $ulid;
    }
	/**
	 * Make log entry html safe
	 * 
	 * @return void
	 */
    function log_request( $req, $ban_type ) {
        if ( false !== ( bool ) $this->_adv_mode || ( false === ( bool ) $this->_adv_mode && $ban_type != "Low" ) ) {
            if ( false === $this->is_wp() ) date_default_timezone_set( 'NZ' );
            $req             = ( strlen( $req ) > $this->_trim_log_entry ) ? substr( $req, 0, $this->_trim_log_entry ) . "..." : $req;
            $req  = $this->cleanString( 11, $req ); // remove control characters (being extra safe)
            $req  = str_replace( "\\", "&bsol;", $req );
            $uuid = $this->get_ulid();
            $req_orig        = ( strlen( $req ) > 250 ) ? wordwrap( $req, 200, "<br />\n" ) : $req;
            $req             = time() . " " .
                               $ban_type . " " .
                               $this->get_ip() . " " .
                               $_SERVER[ 'REQUEST_METHOD' ] . " " .
                               $this->get_filename() . " " .
                               str_replace( " ", "%20", $req ) . " " .
                               $uuid;
            if ( false !== $this->is_wp() ) {
                $this->write_log( $req, $req_orig, $ban_type );
            } else {
                $this->write_log_non_wp( $req, $this->_log_file );
            }
        }
    }
	/**
	 * Get file permissions
	 * 
	 * @return string
	 */
    function dirfile_perms( $path ) {
        $length = strlen( decoct( fileperms( $path ) ) ) - 3;
        return substr( decoct( fileperms( $path ) ), $length );
    }
	/**
	 * Sets $this->_log_file_key
	 * 
	 * @return void
	 */
    function set_crypto_key_file() {
        $this->_log_file_key = substr( $this->get_uuid(), 0, 32 ) . '_request.key';
    }
	/**
	 * Generate a logfile name
	 * 
	 * @return string
	 */
    function logfile_name() {
        if ( false !== $this->logfile_exists() ) {
            $key_array = file( PARETO_LOGS . $this->_log_file_key );
        } else
            return false;
        $filename = substr( hash( 'sha256', $key_array[ 0 ], false ), 0, 32 ) . "_request.log";
        return $filename;
    }
	/**
	 * Delete logs
	 * 
	 * @return void
	 */    
    function logfile_cleanup() {
        $filelist = scandir( PARETO_LOGS );
        foreach ( $filelist as $key => $filename ) {
            if ( strlen( $filename ) > 20 && false === $this->cmpstr( $filename, $this->_log_file, true ) && $this->cmpstr( '_request.log', substr( $filename, -12, 12 ), true ) ) {
                $logfilename = PARETO_LOGS . $filename;
                if ( false === strpos( $logfilename, 'img' ) )
                    unlink( PARETO_LOGS . $filename );
            }
            if ( strlen( $filename ) > 20 && false === $this->cmpstr( $filename, $this->_log_file_key, true ) && $this->cmpstr( '_request.key', substr( $filename, -12, 12 ), true ) ) {
                unlink( PARETO_LOGS . $filename );
            }
        }
    }
    /**
	 * Check if logs exhist
	 * 
	 * @return boolean
	 */
    function logfile_exists() {
        return ( bool ) ( file_exists( PARETO_LOGS . ".htaccess" ) || file_exists( PARETO_LOGS . $this->_log_file_key ) );
    }
    /**
	 * Create unique string
	 * 
	 * @return string
	 */
    function do_bcrypt( $string, $cost = 5 ) {
        $salt  = ( function_exists( 'random_bytes' ) ) ? substr( strtr( base64_encode( random_bytes( 32 ) ), '+', '.' ), 0, 22 ) : substr( base64_encode( openssl_random_pseudo_bytes( 32 ) ), 0, 22 );
        $salt  = str_replace( "+", ".", $salt );
        $param = '$' . implode( '$', array(
             "2y",
            $cost,
            $salt 
        ) );
        $output = crypt( $string, $param );
        return $output;
    }

    /**
	 * If not WP, create log file set
	 * 
	 * @return void
	 */
    function create_fileset() {
        $htlog_content = 'Options -Indexes' . "\n" . 'Options +SymLinksIfOwnerMatch' . "\n" . 'ServerSignature off' . "\n" . '<Files ~ "^.*\_([Rr][Ee][Qq][Uu][Ee][Ss][Tt]\.)">' . "\n" . 'order allow,deny' . "\n" . 'deny from all' . "\n" . 'satisfy all' . "\n" . '</Files>' . "\n";
        
        if ( false === is_dir( PARETO_LOGS ) )
            @mkdir( PARETO_LOGS, 0755 );
        
        # Create key
        $crypto_key_file = PARETO_LOGS . $this->_log_file_key;
        $hash_string     = ( $this->is_wp() ) ? $this->get_wp_key() : $this->get_uuid();
        $key             = $this->do_bcrypt( $hash_string, 12 );
        $fp              = fopen( $crypto_key_file, 'w' );
        fwrite( $fp, $key );
        fclose( $fp );
        
        $this->_log_file = $this->logfile_name();
        
        $logfile = PARETO_LOGS . $this->_log_file;
        # Create logfile
        $fp      = fopen( $logfile, 'c' );
        fwrite( $fp, "" );
        fclose( $fp );
        
        # Create HTACCESS
        $fp = fopen( PARETO_LOGS . ".htaccess", 'w' );
        fwrite( $fp, $htlog_content );
        fclose( $fp );
        
        # remove any older logs
        if ( false !== $this->is_wp() )
            $this->logfile_cleanup();
        @chmod( PARETO_LOGS, 0755 );
        @chmod( PARETO_LOGS . ".htaccess", 0644 );
        @chmod( $logfile, 0644 );
        @chmod( $crypto_key, 0644 );
    }
    /**
	 * Generate a unique key from WP variables
	 * 
	 * @return string
	 */
    function get_wp_key() {
        $token = '';
        $key_vars  = array(
            'AUTH_KEY' => AUTH_KEY,
            'SECURE_AUTH_KEY' => SECURE_AUTH_KEY,
            'NONCE_KEY' => NONCE_KEY,
            'AUTH_SALT' => AUTH_SALT,
            'SECURE_AUTH_SALT' => SECURE_AUTH_SALT,
            'NONCE_SALT' => NONCE_SALT 
        );
        foreach ( $key_vars as $const_key => $const_arg ) {
            if ( defined( $const_key ) && strlen( $const_arg ) > 40 )
                $token = hash( 'sha256', $const_arg . $token, false );
        }
        return $token;
    }
    /**
	 * Create unique user id from server variables
	 * 
	 * @return string
	 */
    function get_uuid() {
        $_get_server = array_change_key_case( $_SERVER, CASE_LOWER );
        $uuid = '';
        $server_vars  = array(
            'server_admin',
            'server_addr',
            'document_root',
            'server_software',
            'path',
            'server_protocol',
            'rails_env',
            'gateway_interface',
            'server_addr',
            'server_name',
            'server_signature',
            'http_accept_language',
            'http_accept_encoding',
            'http_accept',
            'http_upgrade_insecure_requests',
            'http_cache_control',
            'ssl_tls_sni',
            'https',
            'dh_user',
            'dsid',
            'fcgi_role'
        );

        $x = 0;
        $uuid = '';
        while ( $x < count( $server_vars ) ) {
            if ( isset( $_get_server[ $server_vars[ $x ] ] ) ) {
                if ( !$_get_server[ $server_vars[ $x ] ] == 'max-age=0' ) {
                    $uuid = hash( 'sha256', $_get_server[ $server_vars[ $x ] ] . $uuid, false );
                }
            }
            $x++;
        }
        return $uuid;
    }   
    /**
	 * Convert unix timestamp to readable date
	 * 
	 * @return string
	 */
    function updated( $unixtime, $offset ) {
        if ( false !== $this->integ_prop( $offset ) ) {
            if ( $offset > 0 && $offset < 14 ) {
                return $unixtime + ( $offset * 3600 );
            } elseif ( $this->cmpstr( $offset, 0 ) ) {
                return $unixtime;
            }
        } elseif ( false !== preg_match( "#^(-[0-9]{1,}|[0-9]{1,})$#", $offset ) ) {
            $x = ( int ) str_replace( '-', '', ( string ) $offset );
            return $unixtime - ( $x * 3600 );
        }
    }
    /**
	 * Load XML lists into arrays
	 * 
	 * @return void
	 */
    public function load_lists( $blacklists = false, $injectors = false ) {
        if ( false !== $blacklists ) {
            $xml_lists = ( ( false !== $this->is_wp() ) ? plugin_dir_path( __FILE__ ) : dirname( __FILE__ ) ) . "/xml/lists.xml";
            if ( false !== $this->is_wp() ) $this->_datalist = wp_cache_get( 'mylists' );
            if ( file_exists( $xml_lists ) ) {
                $xml = simplexml_load_file( $xml_lists );
                $this->_datalist[ 1 ] = explode( ',', preg_replace(  "/[\s]/i", "", $xml->get ) );
                $this->_datalist[ 2 ] = explode( ',', preg_replace(  "/[\s]/i", "", $xml->post ) );
                $this->_datalist[ 3 ] = explode( ',', preg_replace(  "/[\s]/i", "", $xml->bad_ua ) );
                $this->_datalist[ 4 ] = explode( ',', preg_replace(  "/[\s]/i", "", $xml->good_ua ) );
                if ( false !== $this->is_wp() ) wp_cache_set( 'mylists', $this->_datalist, '', 10800 );
            }
        }
        if ( false !== $injectors ) {
            $xml_db = ( ( false !== $this->is_wp() ) ? plugin_dir_path( __FILE__ ) : dirname( __FILE__ ) ) . "/xml/injectors.xml";
            if ( false !== $this->is_wp() ) $this->_injectors = wp_cache_get( 'myinjectors' );
            if ( file_exists( $xml_db ) ) {
                $xml = simplexml_load_file( $xml_db );
                $this->_injectors[ 1 ] = preg_replace(  "/[\s]/i", "", $xml->vartrig );
                $this->_injectors[ 2 ] = preg_replace(  "/[\s]/i", "", $xml->matchlist );
                $this->_injectors[ 3 ] = preg_replace(  "/[\s]/i", "", $xml->sqlupdate );
                $this->_injectors[ 4 ] = preg_replace(  "/[\s]/i", "", $xml->fileinject );
                $this->_injectors[ 5 ] = preg_replace(  "/[\s]/i", "", $xml->pattern );
                $this->_injectors[ 6 ] = preg_replace(  "/[\s]/i", "", $this->decode_code( $xml->symtrig ) );
                if ( false !== $this->is_wp() ) wp_cache_set( 'myinjectors', $this->_injectors, '', 10800 );
            }
        }
    }
    /**
	 * Filter $string for injection attempts
	 * 
	 * @return boolean
	 */
    function injectMatch( $string ) {
        $string = $this->url_decoder( strtolower( $string ) );
        
        $matches1 = array();
        $matches2 = array();
        $matches3 = array();
        $matches4 = array();
        
        # these are the triggers to engage the rest of this function.
        $vartrig = $this->_injectors[ 1 ];
        for ( $x = 0; $x <= 9; $x++ ) {
            $this_string = $this->cleanString( $x, $string );
            preg_match_all( "/$vartrig/im", $this_string, $matches1 );
            # second set of tests, string must include at least one of these to trigger
            $symtrig = ( string ) $this->_injectors[ 6 ];
            preg_match_all( "/[$symtrig]|[0-9]/i", $this_string, $matches2 );
        }
        # Hutana we have a raru!
        if ( empty( $vartrig ) && empty( $symtrig ) ) return false;

        $a = 0;
        $b = 0;
        if ( !empty( $matches1[ 0 ] ) ) $a = count( array_unique( $matches1[ 0 ] ) );
        if ( !empty( $matches2[ 0 ] ) ) $b = count( array_unique( $matches2[ 0 ] ) );

        if ( ( ( int )$a > 0 ) && ( ( int )$b > 0 ) ) {
            $j            = 0;
            # toggle through 6 different filters
            $sqlmatchlist = $this->_injectors[ 2 ];
            $sqlupdatelist    = $this->_injectors[ 3 ];
            $sqlfilematchlist = $this->_injectors[ 4 ];

            while ( $j <= 9 ) {
                $this_string = $this->cleanString( $j, $string );

                # First up, REGEX! ( Borrowed from NoScript https://noscript.net/ )
                # Most injection attempts are caught here
                $regex_pattern = ( string ) $this->_injectors[ 5 ];
                if ( false !== ( bool ) preg_match( "/$regex_pattern/i", $this_string ) ) {
                    return true;
                }
                if ( false !== ( bool ) preg_match( "/\bdrop\b/i", $this_string ) && false !== ( bool ) preg_match( "/\btable\b|\buser\b/i", $this_string ) && false !== ( bool ) preg_match( "/--/i", $this_string ) ) {
                    return true;
                } elseif ( ( false !== strpos( $this_string, 'grant' ) ) && ( false !== strpos( $this_string, 'all' ) ) && ( false !== strpos( $this_string, 'privileges' ) ) ) {
                    return true;
                } elseif ( false !== ( bool ) preg_match( "/(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\)))/i", $this_string ) ) {
                    return true;
                } elseif ( preg_match_all( "/\bload\b|\bdata\b|\binfile\b|\btable\b|\bterminated\b/i", $this_string, $matches ) > 3 ) {
                    $match_list = array_unique( $matches[ 0 ] );
                    if ( count( $match_list ) > 3 )
                        return true;
                } elseif ( ( ( false !== ( bool ) preg_match( "/select|sleep|isnull|declare|ascii\(substring|length\(/i", $this_string, $matches1 ) ) &&
                             ( false !== ( bool ) preg_match( "/\band\b|\bif\b|group_|_ws|load_|exec|when|then|concat\(|\bfrom\b/i", $this_string, $matches2 ) ) &&
                             ( false !== ( bool ) preg_match_all( "/$sqlmatchlist/im", $this_string, $matches3 ) ) ) ) {
                             $this_matches = array();
                             $this_matches = array_merge( $matches1, $matches2, $matches3[ 0 ] );
                             $this_matches = array_unique( $this_matches );
                             $n = count( $this_matches );
                             if ( strpos( $this_string, 'union' ) ) $n = $n < 1;
                             if ( $n > 3 ) return true;
                } elseif ( false !== strpos( $this_string, 'from' ) && false !== strpos( $this_string, 'update' ) && false !== ( bool ) preg_match( "/\bset\b/i", $this_string ) && false !== ( bool ) preg_match( "/$sqlupdatelist/im", $this_string, $matches ) ) {
                    return true;
                } elseif ( false !== strpos( $this_string, 'having' ) && false !== ( bool ) preg_match( "/\bor\b|\band\b/i", $this_string ) && false !== ( bool ) preg_match( "/$sqlupdatelist/im", $this_string ) ) {
                    # tackle the noDB / js issue
                    return true;
                } elseif ( ( $this->substri_count( $this_string, 'var' ) > 1 ) && false !== ( bool ) preg_match( "/date\(|while\(|sleep\(/i", $this_string ) ) {
                    return true;
                    # reflected download attack
                } elseif ( ( substr_count( $this_string, '|' ) > 2 ) && false !== ( bool ) preg_match( "/json/i", $this_string ) ) {
                    return true;
                }
              
                # run through a set of filters to find specific attack vectors on the request string
                $thenode = $this->cleanString( $j, $this->getREQUEST_URI() );
                
                if ( ( false !== ( bool ) preg_match( "/onmouse(?:down|over)/i", $this_string ) ) && ( 2 < ( int ) preg_match_all( "/c(?:path|tthis|t\(this)|http:|(?:forgotte|admi)n|sqlpatch|ftp:|(?:aler|promp)t/i", $thenode, $matches ) ) ) {
                    $match_list = array_unique( $matches[ 0 ] );
                    if ( count( $match_list ) > 2 )
                        return true;
                } elseif ( ( ( false !== strpos( $thenode, 'ftp:' ) ) && ( $this->substri_count( $thenode, 'ftp' ) > 1 ) ) && ( 2 < ( int ) preg_match_all( "/@|\/\/|:/i", $thenode, $matches ) ) ) {
                    $match_list = array_unique( $matches[ 0 ] );
                    if ( count( $match_list ) > 2 )
                        return true;
                } elseif ( ( substr_count( $this_string, '../' ) > 3 ) || ( substr_count( $this_string, '..//' ) > 3 ) || ( $this->substri_count( $this_string, '0x2e0x2e/' ) > 1 ) ) {
                    if ( false !== ( bool ) preg_match( "/$sqlfilematchlist/im", $this_string ) ) {
                        return true;
                    }
                } elseif ( ( substr_count( $this_string, '/' ) > 1 ) && ( 2 <= ( int ) preg_match_all( "/$sqlfilematchlist/im", $thenode, $matches ) ) ) {
                    $match_list = array_unique( $matches[ 0 ] );
                    if ( count( $match_list ) > 2 )
                        return true;
                } elseif ( ( false !== ( bool ) preg_match( "/%0D%0A/i", $thenode ) ) && ( false !== strpos( $thenode, 'utf-7' ) ) ) {
                    return true;
                }
                if ( 5 <= substr_count( $this_string, '%' ) )
                    $this_string = str_replace( '%', '', $this_string );
                if ( ( false !== ( bool ) preg_match( "/\border by\b|\bgroup by\b/i", $this_string ) ) && ( false !== ( bool ) preg_match( "/select|\band\b/i", $this_string ) )  && ( false !== ( bool ) preg_match( "/\bcolumn\b|\bdesc\b|\berror\b|\bfrom\b|hav|\blimit\b|offset|\btable\b|\/|--/i", $this_string ) || ( false !== ( bool ) preg_match( "/\b[0-9]\b/i", $this_string ) ) ) ) {
                    return true;
                } elseif ( ( false !== ( bool ) preg_match( "/\btable\b|\bcolumn\b/i", $this_string ) ) && false !== strpos( $this_string, 'exists' ) && false !== ( bool ) preg_match( "/\bif\b|\berror\b|\buser\b|\bno\b/i", $this_string ) ) {
                    return true;
                } elseif ( ( false !== strpos( $this_string, 'waitfor' ) && false !== strpos( $this_string, 'delay' ) && ( ( bool ) preg_match( "/(:)/i", $this_string ) ) ) || ( false !== strpos( $this_string, 'nowait' ) && false !== strpos( $this_string, 'with' ) && ( false !== ( bool ) preg_match( "/--|\/|\blimit\b|\bshutdown\b|\bupdate\b|\bdesc\b/i", $this_string ) ) ) ) {
                    return true;
                } elseif ( false !== ( bool ) preg_match( "/\binto\b/i", $this_string ) && ( false !== ( bool ) preg_match( "/\boutfile\b/i", $this_string ) ) ) {
                    return true;
                } elseif ( false !== ( bool ) preg_match( "/\bdrop\b/i", $this_string ) && ( false !== ( bool ) preg_match( "/\--/i", $this_string ) ) && ( false !== ( bool ) preg_match( "/\btable\b/i", $this_string ) ) ) {
                    return true;
                } elseif ( ( ( false !== strpos( $this_string, 'create' ) && false !== ( bool ) preg_match( "/\btable\b|\buser\b|\bselect\b/i", $this_string, $matches1 ) ) ||
                             ( false !== strpos( $this_string, 'delete' ) && false !== strpos( $this_string, 'from' ) ) ||
                             ( false !== strpos( $this_string, 'insert' ) && ( false !== ( bool ) preg_match( "/\bexec\b|\binto\b|from/i", $this_string, $matches2 ) ) ) ||
                             ( false !== strpos( $this_string, 'select' ) && ( false !== ( bool ) preg_match_all( "/\bby\b|\bcase\b|extract|from|\bif\b|\binto\b|\bord\b|union/i", $this_string, $matches3 ) ) ) ) &&
                             ( ( false !== ( bool ) preg_match_all( "/$sqlmatchlist/im", $this_string, $matches4 ) ) ) ) {
                             $this_matches = array();
                             $get_match1 = ( is_array( $matches1 ) ) ? $matches1 : array();
                             $get_match2 = ( is_array( $matches2 ) ) ? $matches2 : array();
                             $get_match3 = ( is_array( $matches3[ 0 ] ) ) ? $matches3[ 0 ] : array();
                             $get_match4 = ( is_array( $matches4[ 0 ] ) ) ? $matches4[ 0 ] : array();
                             $this_matches = array_merge( $get_match1, $get_match2, $get_match3, $get_match4 );
                             $this_matches = array_unique( $this_matches );
                             if ( count( $this_matches ) > 3 ) return true;
                } elseif ( ( false !== strpos( $this_string, 'union' ) ) && ( false !== strpos( $this_string, 'select' ) ) && false !== ( bool ) preg_match( "/\bfrom\b|\bnull\b|--/i", $this_string ) ) {
                    return true;
                } elseif ( false !== strpos( $this_string, 'etc/passwd' ) ) {
                    return true;
                } elseif ( ( false !== strpos( $this_string, 'procedure' ) ) && ( false !== strpos( $this_string, 'analyse' ) ) && ( false !== strpos( $this_string, 'extractvalue' ) ) ) {
                    return true;
                } elseif ( false !== strpos( $this_string, 'null' ) ) {
                    $nstring = preg_replace( "/[^a-z]/i", '', $this->url_decoder( $this_string ) );
                    if ( false !== ( bool ) preg_match( "/(null){3,}/i", $nstring ) ) {
                        return true;
                    }
                }
                $j++;
            }
        }
        return false;
    }
    /**
	 * Filter datalists for blacklisted variables
	 * 
	 * @return boolean
	 */
    function datalist( $val, $list = 0 ) {
        $val = $this->cleanString( 9, $val );
        if ( !is_numeric( $val ) && empty( $val ) ) return false;
        if ( empty( $this->_datalist ) || !is_array( $this->_datalist ) ) return false;

        # although we try not to do this, arbitrary blacklisting of certain request variables
        # cannot be avoided. however I will attempt to keep this list short.

        // Remove whitespace from string
        $val            = preg_replace( "/\s+/i", '', $this->decode_code( str_replace( "'", '', ( $val ) ) ) );
        $_datalist_tmp = array();
        $val = $this->decode_code( $val );
        for ( $x = 0; $x < count( $this->_datalist[ ( int ) $list ] ); $x++ ) {
            $this_item = $this->decode_code( $this->_datalist[ ( int ) $list ][ $x ] );
            # Test 1: Hex test
            if ( false !== strpos( strtolower( pack( "H*", preg_replace( "/[^a-f0-9]/i", '', $val ) ) ), $this_item ) ) {
                return true;
            }
            # Test 2:
            if ( false !== strpos( strtolower( $val ), $this_item ) || false !== $this->cmpstr( $val, $this_item ) ) {
                return true;
            }
        }
        return false;
    }
    /**
	 * filter the lists
	 * @params $input,
	 *         $list,
	 *         $desc,
	 *         $bantype = boolean,
	 *         $severity = string,
	 *         $log = boolean,
	 *         $reqmatch = boolean,
	 *         $injectmatch = boolean	 *         
	 * @return void
	 */
    function do_blacklists( $input, $list, $desc, $bantype = false, $severity = "High", $log = false, $reqmatch = false, $injectmatch = false ) {
        if ( $list > 0 && false !== $reqmatch && false !== ( bool ) $this->datalist( $input, $list ) ) $this->karo( $desc . ": " . $input, $bantype, $severity, $log );
        if ( false !== $injectmatch && false !== $this->injectMatch( $input ) ) $this->karo( "Injection "  . $desc . ": " . $input, $bantype, $severity, $log );
        if ( ( false !== ( bool ) $this->_hard_ban_mode ) &&
             ( $list == 2 ) && ( !empty( $input ) ) &&
             ( false !== $this->controlchar_exists( $input ) ) ) {
               $this->karo( "Control Character Injection "  . $desc . ": " . $input, $bantype, "High", $log ); // test POST variables for control characters
        }
    }
    /**
	 * Filter REQUEST_URI
	 * 
	 * @return void
	 */
    public function _REQUEST_SHIELD() {
        
        $q_str = $this->getQUERY_STRING();
        $req_type = "Request";
        # Often part of a preemptive strike package
        if ( $this->cmpstr( 'wp-links-opml.php', $this->get_filename(), true ) ) {
            if ( $this->string_prop( $q_str, 2 ) ) {
                $qs = '?' . $q_str;
            } else $qs = '';
            # only for a logged in administrator
            if ( false === $this->is_wp( false, true ) )
                $this->karo( "WPScan: non-admin call to wp-links-opml.php" . $qs, ( ( false !== ( bool ) $this->_hard_ban_mode ) ? ( bool ) $this->_banip : false ), 'Low', true );
        }
        # if empty then the rest of no interest to us
        if ( false !== empty( $_REQUEST ) ) return;
        $_get_server = $_SERVER;
        $_get_post   = $_POST;
        
        # specific attacks that do not necessarily
        # involve query_string manipulation
        $req = $this->getREQUEST_URI();
        # Apache Struts2 Remote Code Execution
        preg_match_all( "/redirect|context|opensymphony|dispatcher|httpservletresponse|flush\(|getwriter/i", $req, $matches );
        if ( is_array( $matches[ 0 ] ) && ( count( $matches[ 0 ] ) > 4 ) ) {
            $match_count = ( $m = count( $matches[ 0 ] ) > 4 ) ? 4 : $m;
            for ( $x = 0; $x <= $match_count; $x++ ) {
                $results .= ( !is_array( $matches[ 0 ][ $x ] ) ) ? $matches[ 0 ][ $x ] . ' ' : '';
            }
            $this->karo( "Apache Struts2 RCE: " . $results, true, "Medium", true );
        }
        
        if ( false !== $q_str ) {
            # SQLMAP Prevention
            preg_match_all( "/union|all|select|script|table|from|schema|where|exec|etc/i", $q_str, $matches );
            if ( is_array( $matches[ 0 ] ) ) {
                $mcount = array_unique( $matches[ 0 ] );
                if ( count( $mcount ) >= 8 ) {
                    $req_type = "(SQLMAP) " . $req_type;
                    $this->karo( "SQLMAP Injection Attempt: " . $q_str, true, "Medium", true );
                }
            }        
            
            # Reflected File Download Attack
            $file_injects = ( string ) $this->_injectors[ 4 ];
            
            if ( false !== ( bool ) preg_match( "/$file_injects/i", $q_str, $matches ) ) {
                $match_len = strlen( $matches[ 0 ] );
                $end_char = substr( $q_str, strpos( $q_str, $matches[ 0 ] ) + $match_len, 1 );
                if ( ( empty( $end_char ) || false !== ( false === ctype_alpha( $end_char ) ) ) && ( false === ( bool ) preg_match( "/(?:\.|-|_|\/)/i", $end_char ) ) ) {
                    $this->karo( "Reflected File Download (RFD): " . $q_str, true, "High", true );
                }
            }
            # Reflected File Download Attack
            preg_match_all( '/echo|{ifs}|\||base64|decode|python/i', strtolower( $q_str ), $matches );
            if ( count( array_unique( $matches[ 0 ] ) ) > 4 ) $this->karo( "Reflected File Download (RFD): " . $q_str, true, "High", true );
        }
        # osCommerce / Magento specific exploit
        if ( false !== strpos( $req, '.php/admin' ) )
            $this->karo( "osCommerce / Magento Exploit: " . $req, true, "Low", true );
        
        # Null byte
        if ( false !== strpos( $req, '\0' ) ) $this->karo( "Null byte: " . $req, true, "Low", true );
       
        # prevent arbitrary file includes/uploads
        if ( false !== ( bool ) @ini_get( 'allow_url_include' ) ) {
            if ( false !== ( bool ) $this->instr_url( $req, false ) ) {
                preg_match( "/(?:http:|https:|ftp:|file:|php:)/i", $req, $matches );
                $match_count = count( $matches[ 0 ] );
                if ( false === stripos( $req, $this->get_http_host() ) && $this->cmpstr( $match_count, 1, true ) ) {
                    $this->karo( "RFI: " . $req, true, "High", true );
                } elseif ( false !== stripos( $req, $this->get_http_host() ) && count( $matches[ 0 ] ) > 1 ) {
                    $this->karo( "RFI: " . $req, true, "High", true );
                }
            }
        }
    
        # prevent command injection
        if ( false !== in_array( "'cmd'", $this->_get_all ) || false !== in_array( "'system'", $this->_get_all ) )
            $this->karo( "CMD Inject: " . $req, true, "High", true );
        
        if ( false !== $q_str ) {
            # Detect HTTP Parameter Pollution
            # i.e when devs mistakenly use $_REQUEST to return values
            $dup_check_get = array();
            $qs_arr        = explode( '&', $this->getQUERY_STRING() );
            for ( $x = 0; $x < count( $qs_arr ); $x++ ) {
                $this_key = strtolower( $this->decode_code( substr( $qs_arr[ $x ], 0, strpos( $qs_arr[ $x ], '=' ) ), false, true ) );
                if ( false !== $this->string_prop( $this_key, 1 ) && false === $this->cmpstr( '[]', substr( $this_key, -2 ) ) ) {
                    $dup_check_get[ $x ] = escapeshellarg( str_replace( "'", '', $this_key ) );
                }
            }
            $dup_check_get = array_unique( $dup_check_get );
        }

        # _POST
        if ( false !== $this->cmpstr( 'POST', $_get_server[ 'REQUEST_METHOD' ], true ) && false === empty( $_get_post ) ) {
            # while we're checking _POST, prevent attempts to esculate user privileges in WP
            if ( ( false !== $this->is_wp() && false !== function_exists( 'is_admin' ) && false === is_admin() ) &&
                   false !== $this->cmpstr( 'admin-ajax.php', $this->get_filename(), true ) ) {
                   if ( false !== in_array( 'default_role', $_get_post ) && false !== $this->cmpstr( 'administrator', $_get_post[ 'default_role' ], true ) )
                        $this->karo( "Privalege Esculation / Admin Bypass: " . $req, true, "High", true );
                   # Prevent the exploit of Unauthenticated Call Any Action or Update Any Option https://bit.ly/2FdoRhP
                   if ( isset( $_get_post[ 'action' ] ) && false !== $this->cmpstr( 'wpgdprc_process_action', $_get_post[ 'action' ], true ) &&
                        isset( $_get_post[ 'security' ] ) && isset( $_get_post[ 'data' ] ) ) {
                            preg_match_all( "/option|value|type|save_setting|append|true|enabled/i", $_get_post[ 'data' ], $matches );
                            $matches = array_unique( $matches[ 0 ] );
                            if ( count( $matches ) == 7 ) {
                                if ( !current_user_can( 'manage_options' ) ) $this->karo( "Unauthenticated Call Any Action or Update Any Option", true, "High", true );
                            }
                   }                    
            }
            if ( !empty( $dup_check_get ) ) {
                # Start HTTP Parameter Pollution
                $dup_check_post = array();
                for ( $x = 0; $x < count( $this->_post_all ); $x++ ) {
                    $this_key = strtolower( $this->decode_code( $this->_post_all[ $x ], false, true ) );
                    if ( $this->string_prop( $this_key, 1 ) && false === $this->cmpstr( '[]', substr( $this_key, -2 ) ) ) {
                        $dup_check_post[ $x ] = $this_key;
                    }
                }
                if ( false === empty( $dup_check_post ) )
                    $dup_check_post = array_unique( $dup_check_post );
                
                # We only test for duplicate keys that appear in both QUERY_STRING and POST global.
                if ( count( array_intersect( $dup_check_get, $dup_check_post ) ) > 0 ) {
                    if ( false !== ( bool ) $this->_hard_ban_mode ) {
                        $this->karo( "HTTP Parameter Pollution: " . implode( ', ', $dup_check_post ), ( bool ) $this->_banip, 'Medium', true );
                    } else {
                        if ( $this->is_wp() ) {
                            wp_safe_redirect( get_bloginfo( 'url' ) );
                            exit;
                        } else {
                            header( "Location: " . $this->getURL() );
                            exit();
                        }
                    }
                }
            }
        }
        # WP Author Discovery
        if ( false !== strpos( $req, '?author=' ) ) {
            $this->karo( "Authorised user discovery scan attempt", true, 'Low', true );
        }
        # WP Admin Authentication Bypass Attach
        if ( false !== strpos( $req, '?up_auto_log=' ) || false !== strpos( $req, '&up_auto_log=' ) ) {
            $this->karo( "Authentication Bypass Attack: " . $req, true, 'Low', true );
        }
        # WP DoS Mitigation CVE-2018-6389
        if ( false !== ( bool ) preg_match( '/^load-(?:scripts|styles).php$/i', $this->get_filename() ) ) {
            # Disable concatenation of JS and CSS files
            if ( false !== version_compare( phpversion(), '7.1', '<' ) && !defined( 'CURL_HTTP_VERSION_2_0' ) ) {
                # *chances* are high this server does not support HTTP2, s
                # so manually prevent concatenation of scripts
                if ( !defined( 'CONCATENATE_SCRIPTS' ) ) define( 'CONCATENATE_SCRIPTS', false );
            }
            # Now filter attack attempts
            if ( isset( $_REQUEST[ 'load' ] ) ) {
                $query_len = strlen( $_REQUEST[ 'load' ][ 0 ] );
                if ( $query_len > 1000 )
                    $this->karo( "CVE-2018-6389 DoS Attack: Query Length = " . $query_len, true, 'Medium', true );
            }
        }
        
        # this occurence of these many slashes etc are always an attack attempt
        $limit = 25;
        if ( ( substr_count( $req, '/' ) > $limit ) || ( substr_count( $req, '\\' ) > $limit ) || ( substr_count( $req, '|' ) > $limit ) ) {
            $this->karo( "Irregular Request: " . $req, false, 'Low', true );
        }

        preg_match_all( "/recently_products|ids|\[added_at\]|\[product_id\]|\[from\]/i", $q_str, $matches );
        if ( is_array( $matches[ 0 ] ) ) {
            $match_list = array_unique( $matches[ 0 ] );
            $match_list_count = count( $match_list );
            if ( $this->cmpstr( $match_list_count, 5 ) ) {
                $req_type = "(SQLMAP) " . $req_type;
            }
        }
        preg_match_all( "/opinionstage|content|login|callback|page|success/i", $q_str, $matches );
        if ( is_array( $matches[ 0 ] ) ) {
            $match_list = array_unique( $matches[ 0 ] );
            $match_list_count = count( $match_list );
            if ( $this->cmpstr( $match_list_count, 6 ) ) {
                $req_type = "OpinionStage Version 2.5.0 [Depreciated] Plugin " . $req_type;
            }
        }        
        # finally run the black lists one more time
        $this->do_blacklists( $this->getQUERY_STRING(), 1, $req_type, true, "High", true, true, true );
    }
    /**
	 * Filter GET array
	 * 
	 * @return void
	 */
    function querystring_filter( $val, $key ) {
        $this->_get_all[] = $this->decode_code( $key, true );
        if ( false !== ( bool ) $this->string_prop( $val, 1 ) ) {
            $val = strtolower( $this->decode_code( $val ) );
            $this->do_blacklists( $val, 1, "Request", true, "High", true, true, true );
        }
    }
    /**
	 * Filter GET variables
	 * 
	 * @return void
	 */
    public function _QUERYSTRING_SHIELD() {
        if ( false !== empty( $_REQUEST ) || false === $this->cmpstr( 'GET', $_SERVER[ 'REQUEST_METHOD' ], true ) || false === ( bool ) $this->string_prop( $this->getQUERY_STRING(), 1 ) ) {
            return; // of no interest to us
        } else {
            # run $_GET through filters
            array_walk_recursive( $_GET, array(
                 $this,
                'querystring_filter' 
            ) );
        }
        return;
    }
    /**
	 * Filter _POST array
	 * 
	 * @return void
	 */
    function post_filter( $val, $key ) {
        
        # catch attempts to insert malware
        if ( false !== strpos( $val, "array_diff_ukey" ) && ( false !== strpos( $val, "system" ) || false !== strpos( $val, "cmd" ) ) && $this->substri_count( $val, "array(" ) > 1 )
            $this->karo( "Malware Injection Attempt: " . $val, true, "High", true );
        # Attempts to pop a shell
        preg_match_all( "/php|system\(|import|python|connect|\?\>/i", $val, $matches );
        if ( is_array( $matches[ 0 ] ) ) {
            $match_list = array_unique( $matches[ 0 ] );
            if ( count( $match_list ) > 4 ) {
                $s   = strpos( $val, $match_list[ 0 ] );
                $f   = strlen( $val ) - $s;
                $val = substr( $val, $s, $f );
                $this->karo( "Shell Inject: " . $val, true, "High", true );
            }
        }
        $matches = array();
        # Satori Botnet
        preg_match_all( "/wget http|:\/\/|->|tmp\/r|-O|;sh/i", $val, $matches );
        if ( is_array( $matches[ 0 ] ) ) {
            $match_list = array_unique( $matches[ 0 ] );
            $match_list_count = count( $match_list );
            if ( $this->cmpstr( $match_list_count, 6 ) ) {
                $val = $this->cleanString( 6, $this->remove_comments( $val ) );
                $this->karo( "Botnet :: " . $val, true, 'Low', true );
            }
        } 
        preg_match_all( "/php|echo|base64|system\(|\_GET|cmd/i", $val, $matches );
        if ( is_array( $matches[ 0 ] ) ) {
            $match_list = array_unique( $matches[ 0 ] );
            if ( count( $match_list ) > 5 ) {
                $s   = strpos( $val, $match_list[ 0 ] );
                $f   = strlen( $val ) - $s;
                $val = substr( $val, $s, $f );
                $val = $this->cleanString( 9, $this->remove_comments( $val ) );
                $this->karo( "Shell Inject: " . $val, true, "High", true );
            }
        }
        $matches = array();
        
        if ( preg_match( "/@eval|base64/i", $val ) ) {
            $filtval = preg_replace( "/[^{}a-z0-9_?,();=\*@\[\]\$\/\-]/i", '', strtolower( $val ) );
            preg_match_all( "/@eval|base64\_|{|\]\(|\_post|\}\[|\)\;|\/\*|\*\//i", $filtval, $matches );
            if ( is_array( $matches[ 0 ] ) ) {
                $match_list = array_unique( $matches[ 0 ] );
                if ( count( $match_list ) > 4 ) {
                    $filtval = $this->cleanString( 6, $this->remove_comments( $filtval ) );
                    $this->karo( "Shell Inject: " . $filtval, true, "High", true );
                }
            }
            $matches = array();
            
            preg_match_all( "/@eval|\_magic\_quotes\_gpc|stripslashes|\_post\[chr\(/i", $filtval, $matches );
            if ( is_array( $matches[ 0 ] ) ) {
                $match_list = array_unique( $matches[ 0 ] );
                $match_list_count = count( $match_list );
                if ( $this->cmpstr( $match_list_count, 4 ) ) {
                    $val = $this->cleanString( 6, $this->remove_comments( $val ) );
                    $this->karo( "Malicious Data Exfiltrations Attempt :: " . $val, true, "High", true );
                }
            }            
        }
        $matches = array();
        
        preg_match_all( "/\_server|ini\_set|\_magic\_quotes\_runtime\(0|php\_uname|php\_self|print|die|posix\_/i", strtolower( $val ), $matches );
        if ( count( array_unique( $matches[ 0 ] ) ) > 4 ) {
                $val = $this->cleanString( 6, $this->remove_comments( $val ) );
                $this->karo( "Malicious Data Exfiltrations Attempt :: " . $val, true, "High", true );
        }
        $matches = array();
        
        preg_match_all( "/(?:script|type|text|javascript|http|pastebin)/i", $val, $matches );
        $this_match = count( array_unique( $matches[ 0 ] ) );
        if ( $this->cmpstr( $this_match, 6 ) ) {
            $trimval = trim( substr( $val, 0, 20 ) );
            $this->karo( "Malware Inject: Attempt to inject malware via Pastebin " . $trimval, true, "High", true );
        }

        # Load the keys into an array
        $this->_post_all[] = strtolower( $this->decode_code( $key, true ) );
        
        # Finally, the blacklist
        $this->do_blacklists( $this->decode_code( $val ), 2, "POST Request", true, "High", true, true, false );
    }
    /**
	 * Strip comment brackets
	 * 
	 * @return string
	 */
    function remove_comments( $str ) {
        while( strpos( $str, "/*" ) ) {
             $s       = strpos( $str, "/*" );
             $f       = strpos( $str, "*/" );
             if ( $f > $s ) $remval  = substr( $str, $s, ( $f - $s ) + 2 );
             $str = str_replace( $remval, "", $str );
         }
         return $str;
    }
    /**
	 * Filter _POST super global
	 * 
	 * @return void
	 */
    public function _POST_SHIELD() {
        if ( false === $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ], true ) )
            return; // of no interest to us
        # _POST content-length should be longer than 0
        if ( ( false !== ( bool ) $this->_adv_mode || false !== ( bool ) $this->_post_filter_mode ) ) {
            if ( count( $_POST, COUNT_RECURSIVE ) >= 10000 )
                $this->karo( "_POST DoS Attack", ( bool ) $this->_banip, "High", true ); // very likely a denial of service attack
        }
        array_walk_recursive( $_POST, array(
             $this,
            'post_filter' 
        ) );
        if ( false !== $this->is_wp() ) {
            if ( false !== ( bool ) $this->options[ 'advanced_mode' ] || false !== ( bool ) $this->_adv_mode ) {        
                if ( $this->cmpstr( 'xmlrpc.php', $this->get_filename(), true ) ) {
                    if ( isset( $HTTP_RAW_POST_DATA ) ) { // this is set above wp-load.php
                        # deal with this dangerous global
                        if ( $this->string_prop( $HTTP_RAW_POST_DATA ) && false !== $this->datalist( $this->decode_code( $HTTP_RAW_POST_DATA ), 2 ) ) $this->karo( "HTTP_RAW_POST_DATA contains attack code", true, "High", true );
                        # check it is the correct XML format
                        preg_match_all( "/methodCall|methodName|params|string|value|<|>/i", $HTTP_RAW_POST_DATA, $matches );
                        $matches = array_unique( $matches[ 0 ] );
                        if ( false !== $this->string_prop( $HTTP_RAW_POST_DATA ) && ( 7 > count( $matches ) ) ) {
                            # content is not XML
                            $this->karo( "HTTP_RAW_POST_DATA: Not valid XML", false, "Low", true );
                        }
                    }
                    if ( defined( 'XMLRPC_REQUEST' ) ) {
                            add_filter( 'authenticate', array( $this, 'xml_rpc_auth'), 20, 3 );
                    }
                }
            }
        }
    }
    /**
	 * Filter Wordpress login requests
	 * 
	 * @return void
	 */
    public function _LOGIN_SHIELD() {
        if ( false !== $this->is_wp() ) {
            if ( false !== ( bool ) $this->options[ 'advanced_mode' ] || false !== ( bool ) $this->_adv_mode ) {
                add_action( 'wp_logout', array( $this, 'on_logout' ) );
                add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
                if ( false !== $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ], true ) ) {
                    if ( ( isset( $_POST[ 'log' ] ) && isset( $_POST[ 'pwd' ] ) ) ) {
                        $this_user = $_POST[ 'log' ];
                        $this_pass = $_POST[ 'pwd' ];
                        if ( false !== $this->cmpstr( $this_user, '\\' ) && ( false !== strpos( $this_pass, '||' ) ) )
                                $this->karo( "SQLi Without Quotes Injection User: '" . $this_user . "' Pass: '" . substr( $this_pass, 0, 4 ) . "'", true, "Low", true );
                        $this->check_usernames( $this_user );
                    }
                }
            }
        }
        return;
    }
    /**
	 * Checks password is correct
	 *
	 * @params $check, $password, $hash, $user_id
	 * 
	 * @return boolean
	 */
    function pass_check( $check, $password, $hash, $user_id ) {
        if ( false === $check ) {
            if ( isset( $_POST[ 'log' ] ) ) {
                $this_user = $_POST[ 'log' ];
                $this->flood_check( $this->get_ip(), $this_user, 'WP Password', 10, 12 );
            }
        } else {
            $this->ip_hasher( true );
        }
        return $check;
    }
    /**
	 * On succesful logging in, set admin IP as safe
	 * 
	 * @return void
	 */
    function on_login( $user_login, $user ) {
        # this only triggers on successful login
        # never ban the ip of the administrator
        if ( isset( $this->options[ 'admin_ip' ] ) ) {
            if ( isset( $user->caps[ 'administrator' ] ) && false !== ( bool )$user->caps[ 'administrator' ] ) {
                 # set the admin ip to safe even before
                 # admin accesses pareto security settings
                 $this->update_admin_ip( $this->get_ip() );
            } else $this->update_admin_ip( '' );
        }
    }
    /**
	 * On logging out, remove admin IP
	 * 
	 * @return void
	 */
    function on_logout() {
        if ( false !== $this->is_wp( false, true ) ) {
            if ( isset( $this->options[ 'admin_ip' ] ) ) {
                // unset admin IP
                $this->update_admin_ip( '' );
            }
        }
    }
    /**
	 * Add or remove admin ip address from DB
	 * 
	 * @return void
	 */
    function update_admin_ip( $ip ) {
        update_option( $this->settings_field, array( // set defaults
                 'advanced_mode' => $this->_adv_mode,
                 'hard_ban_mode' => $this->_hard_ban_mode,
                 'tor_block'     => $this->_tor_block,
                 'email_report'  => $this->_email_report,
                 'ban_mode'      => $this->_ban_mode,
                 'safe_list'     => ( isset( $this->_domain_list ) ? $this->_domain_list : '' ),
                 'admin_ip'      => $ip
        ) );
        $this->options = get_option( $this->settings_field );
    }
    /**
	 * Check if username exists in database
	 * 
	 * @return boolean
	 */
    function check_usernames( $this_user, $threshold = 3, $hard_ban = 5  ) {
        $get_users = array();
        $blogusers     = get_users( array(
             'fields' => array(
                 'user_login',
                 'user_nicename',
                 'display_name'
            ) 
        ) );
        foreach ( $blogusers as $user ) {
            $get_users[] = $user->user_login;
            $get_users[] = $user->user_nicename;
            $get_users[] = $user->display_name;
        }
        $get_users = array_unique( $get_users );
        # will report false if XML or if password is not empty
        $pw_test = ( bool ) ( isset( $_POST[ 'pwd' ] ) && empty( $_POST[ 'pwd' ] ) );
        # if user is correct, also check pass, else return false
        if ( in_array( $this_user, $get_users ) && false === $pw_test ) {
            add_filter( 'check_password', array( $this, 'pass_check' ), 10, 4 );
        } else {
            # with a DoS attack, the user could change on every request
            # log the ip addresses of each request
            $this->flood_check( $this->get_ip(), $this_user, ( false === $pw_test ) ? 'WP User' : 'Empty WP Password', $threshold, $hard_ban );
        }
    }
    function ip_hasher( $input = false ) {
        # if XML-RPC user is correct
        $this->_ip_array = get_option( $this->ip_hash_list );
        $key = sha1( $this->get_ip() );            
        if ( false !== $input ) {
            if ( in_array( $key, $this->_ip_array ) ) {
                # if in array, remove
                unset( $this->_ip_array[ $key ] );
            }
        }
        update_option( $this->ip_hash_list, $this->_ip_array );
    }
    /**
	 * Check if username is registered
	 * @params $user, $username, $pass
	 * @return string
	 */
    function xml_rpc_auth( $user, $username, $pass ) {
        # this filter runs before the shields so will filter
        # incorrect usernames before _SPIDER_SHIELD filters
        
        # filter username through blacklists
        $post_data = array();
        $post_data = array( $username, $pass );
        array_walk_recursive( $post_data, array(
             $this,
            'post_filter' 
        ) );
        # Deal with invalid logins
        if ( array_key_exists( 'invalid_username', $user->errors ) ||
             array_key_exists( 'incorrect_password', $user->errors ) ) {
             $this->flood_check( $this->get_ip(), $username, 'XML-RPC User', 2, 3 );
        } else {
            $this->ip_hasher( true );
            $this->_spider_bypass = true;
        }
        return $user;
    }
    /**
	 * Check DB for old failed IP hashes
	 * 
	 * @return void
	 */    
    function iphash_db_cleanup() {
        $time_now = time();
        $this->_ip_array = get_option( $this->ip_hash_list );
        if ( empty( $this->_ip_array ) ) return;
        foreach( $this->_ip_array as $key => $val ) {
            $this_timestamp = ( int ) $this->_ip_array[ $key ][ 1 ];
            $n = ( int ) $this->_ip_array[ $key ][ 0 ];
            if ( $n > ( int ) $this->_hard_ban_count ) {
                # if time lapsed is greater than 7 days
                if ( ( $time_now < $this_timestamp ) > ( ( ( int ) $this->_ban_time / 24 ) * 168 ) ) {
                    unset( $this->_ip_array[ $key ] );
                } else {
                # if count higher than threshold, htaccess is not working
                # so leave hash in db
                continue;
                }
            }
            # if timestamp is older than $this->_ban_time then remove entry
            if ( ( $time_now - ( int ) $this->_ban_time ) > $this_timestamp ) unset( $this->_ip_array[ $key ] );
        }
        update_option( $this->ip_hash_list, $this->_ip_array );
        return;
    }
    /**
	 * Flood controls for incorrect usernames
	 * 
	 * @return void
	 */ 
    function flood_check( $ip, $uname = '', $type = '', $threshold = 5, $hard_ban = 7 ) {
         $uname = esc_html( $uname );
         if ( empty( $ip ) ) $ip = $this->get_ip();
         $iphash = sha1( $ip ); // hash the ip
         $time_now = time();

         if ( $hard_ban <> $this->_hard_ban_count ) $this->_hard_ban_count = $hard_ban;
         $this->_ip_array = get_option( $this->ip_hash_list );
         if ( !empty( $this->_ip_array ) && false !== array_key_exists( $iphash, $this->_ip_array ) ) { // check hash in database
              $current_count = ( int ) $this->_ip_array[ $iphash ][ 0 ];
              $time_stamp = ( int ) $this->_ip_array[ $iphash ][ 1 ];
              # if 24 hours hasn't lapsed
              if ( ( $time_now - $this->_ban_time ) < $time_stamp ) {
                # if threshold passed then return 403
                if ( $current_count >= $threshold ) {
                     # repeat failed login, restart timestamp
                     # if $current_count > $this->_hard_ban_count within 24 hours
                     # permanent IP ban
                     if ( $current_count >= $this->_hard_ban_count ) {
                        # this is a flood attack
                        # update the DB
                        $this->_ip_array[ $iphash ][ 0 ] = $current_count + 1;
                        update_option( $this->ip_hash_list, $this->_ip_array );
                        # ban to htaccess and 403
                        $this->karo( 'User/Password Cracking Attack :: [ ' . $current_count . ' ] Failed Login Attempts', true, "Medium", true );
                     } else {
                        # log only until $threshold, then 403 until hard ban count
                        $this->_ip_array[ $iphash ][ 0 ] = $current_count + 1;
                        update_option( $this->ip_hash_list, $this->_ip_array );
                        if ( $current_count <= ( $threshold - 1 ) ) {
                            $this->karo( 'Error: ' . $type . ': "' . $uname . '" [ ' . $current_count . ' ] Failed Login Attempts', false, "Safe" , false );
                        } else $this->send200(); // tricks flooders into continuing
                     }
                }
                $this->_ip_array[ $iphash ][ 0 ] = $current_count + 1;
                update_option( $this->ip_hash_list, $this->_ip_array );
             } else {
               # 24 hours has lapsed so start the count again
               $this->_ip_array[ $iphash ] = array( 0 => 1, 1 => $time_now );
               update_option( $this->ip_hash_list, $this->_ip_array );
             }
         } else {
            # add this entry to DB
            $this->_ip_array[ $iphash ] = array( 0 => 1, 1 => $time_now );
            update_option( $this->ip_hash_list, $this->_ip_array );
         }
    }
    /**
	 * Filter HTTP_HOST
	 * 
	 * @return void
	 */ 
    public function _HTTPHOST_SHIELD() {
        if ( isset( $_SERVER[ 'HTTP_HOST' ] ) ) {
            $this_http_host = trim( strtolower( $_SERVER[ 'HTTP_HOST' ] ) );
            
            # while not optimal, there is nothing below
            # that can right this issue
            if ( empty( $this_http_host ) ) return;
            
            # check for injections via HTTP_HOST
            $this->do_blacklists( $this_http_host, 0, "HOST", true, "High", true, false, true );
            
            # low level sanitise the host
            $http_host = $this->host_check( strtolower( $this_http_host ) );
            
            # Wordpress Host Check    
            if ( false !== $this->is_wp() ) {
                if ( false !== ( bool ) $this->_adv_mode ) {
                    # WP RCE HOST Attack
                    preg_match_all( "/xenial|directory|usr|spool|run/i", $http_host, $matches );
                    if ( is_array( $matches[ 0 ] ) ) {
                        $match_list = array_unique( $matches[ 0 ] );
                        if ( count( $match_list ) > 3 )
                            $this->karo( "WP RCE HOST Attack: " . $http_host, ( bool ) $this->_banip, "High", true );
                    }
                }
            }
            # Get URL from safe list
            if ( empty( $safelist_url ) ) return;
            # Set safe domain
            $this->set_safe_domain();

            # if IPaddress:port, strip the port number
            $this_http_host = $this->ip_filter( $this_http_host );
            if( function_exists( 'filter_var' ) && defined( 'FILTER_VALIDATE_IP' ) ) {
                if ( false !== filter_var( $this_http_host, FILTER_VALIDATE_IP ) ) {
                    # the SERVER_NAME is an IP so check it against SERVER_ADDR
                    if ( false === $this->is_server( $this_http_host ) ) {
                        $req = $this->getREQUEST_URI();
                        // TODO: need to check if there is a domain name
                        if ( false !== $this->cmpstr( 'CONNECT', $_SERVER[ 'REQUEST_METHOD' ], true ) ) {
                            $this->karo( $server_ip . " :: Incorrect Server IP / possible proxying attempt - Should be " . $_SERVER[ 'SERVER_ADDR' ], true, 'Medium', true, ( isset( $this->safe_host ) ? $this->safe_host : $this_http_host ) );
                        }
                    }
                } else {
                    # check HTTP HOST against the safe list
                    # to prevent DNS rebinding
                    $n = false;
                    foreach( $safelist_url as $url ) {
                        # check against whitelist
                        $url = trim( $url );
                        if ( strpos( $url, $this_http_host ) || ( false !== $this->cmpstr( $url, substr( $this_http_host , - strlen( $url ) ), true ) ) ) {
                            $n = true;
                            break;
                        }
                        # check if is server ip
                        if ( false !== $this->is_server( $this_http_host ) ) {
                            $n = true;
                            break;
                        }
                    }
                    if ( !in_array( $this_http_host, $safelist_url ) && $n === false ) {
                        if ( false !== $this->cmpstr( 'HEAD', $_SERVER[ 'REQUEST_METHOD' ], true ) ) $this->karo( $this_http_host . " :: DNS rebinding attempt - Should be " . $this->safe_host . ' or ' . $this->get_serverip(), false, 'Medium', true, $this->safe_host );
                    }
                }
            }
        }
    }
    function set_safe_domain() {
            $safelist_url = array();
            if ( isset( $this->options[ 'safe_list' ] ) && !empty( $this->options[ 'safe_list' ] ) ) {
                $server_ip = $this->get_servername(); // set something
                $safelist_url = array();
                $this_sname = $this->host_check( $this->options[ 'safe_list' ] );

                if ( !is_array( $this_sname ) ) {
                    # check there isn't two urls on separate lines.
                    if ( false !== strpos( $this_sname, "\n" ) ) {
                        $safelist_url = explode( "\n", $this_sname );
                    } else {
                        $safelist_url[] = $this_sname;
                    }
                }
            $this->safe_host = $safelist_url[ 0 ];
            }
    }
    function ip_filter( $ip ) {
        $ip_port_pattern = '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.)
                            {3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]):(?:
                            6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}
                            |[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$';
        $ip_port_pattern = preg_replace( "/[\s\r\n]/i", '', $ip_port_pattern );
        if ( false !== ( bool ) preg_match( "/$ip_port_pattern/i", $ip ) ) {
            return trim( substr( $ip, 0, strpos( $ip, ':' ) ) );
        } 
        return $ip;
    }
    function is_ip_address( $ip ) {
        $ip_pattern      = '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.)
                            {3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$';                            
        $ip_pattern = preg_replace( "/[\s\r\n]/i", '', $ip_pattern );
        
        $test_ip_chars = preg_replace( "/\.|:/i", '', $ip ); // leave numeric only
        
        if ( false !== is_numeric( $test_ip_chars ) && false !== ( bool ) preg_match( "/$ip_pattern/i", $ip ) ) {
                return true;
        }
        return false;
    }
    /**
	 * Filter array
	 * @params $val, $key
	 * @return void
	 */ 
    function cookie_filter( $val, $key ) {
        $this->do_blacklists( $this->decode_code( $key ), 1, "Cookie", true, "High", true, true, true );
        $this->do_blacklists( $this->decode_code( $val ), 1, "Cookie", true, "High", true, true, true );
    }
    /**
	 * Filter _COOKIE super global
	 * @params $val, $key
	 * @return void
	 */ 
    public function _COOKIE_SHIELD() {
        if ( false !== empty( $_COOKIE ) )
            return; // of no interest to us
        array_walk_recursive( $_COOKIE, array(
             $this,
            'cookie_filter' 
        ) );
    }
    /**
	 * Filter USER-AGENT
	 * 
	 * @return void
	 */ 
    public function _SPIDER_SHIELD() {
        $user_agent = strtolower( $this->decode_code( $_SERVER[ 'HTTP_USER_AGENT' ], true ) );
        if ( false !== ( bool ) $this->string_prop( $user_agent, 1 ) ) {
            # Shellshock
            preg_match_all( "/echo|\(\)|\;\}\;|\/bin\/bash|-c|uname|-i|>|md5sum/i", $user_agent, $matches );
            if ( is_array( $matches[ 0 ] ) ) {
                $match_list = array_unique( $matches[ 0 ] );
                if ( count( $match_list ) > 4 ) {
                    $s   = strpos( $user_agent, $match_list[ 0 ] );
                    $f   = strlen( $user_agent ) - $s;
                    $user_agent = substr( $user_agent, $s, $f );
                    $this->karo( "USER-AGENT (Shellshock): " . $user_agent, true, "High", true );
                }
            }

            # Mandatory filtering
            $this->do_blacklists( $user_agent, 3, "USER-AGENT", ( ( false !== ( bool ) $this->_adv_mode ) ? true : false ), 'Medium', true, true, true );

            # Only if in Hard Ban Mode
            # xml-rpc
            if ( false === $this->_spider_bypass ) {
                $this_ip = $this->get_ip();
                if ( false !== $this->_adv_mode && false !== ( bool ) $this->_hard_ban_mode ) {
                    if ( false !== strpos( $user_agent, 'mozilla' ) ) return;
                    # Allow unsupported user-agents for XML-RPC
                    if ( false !== $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ], true ) ) {
                        if ( false !== $this->cmpstr( 'xmlrpc.php', $this->get_filename(), true ) ) return;
                    }
                    # this allows a user added IP address to bypass the user-agent white list
                    if ( isset( $this->options[ 'safe_list' ] ) && !empty( $this->options[ 'safe_list' ] ) ) {
                        $ulist = explode( "\n", $this->host_check( $this->options[ 'safe_list' ] ) );
                        if ( is_array( $ulist ) ) {
                            foreach( $ulist as $val ) {
                                if ( ( false !== $this->check_ip( $val, true ) ) && false !== $this->cmpstr( $val, $this_ip ) ) {
                                    return;
                                }
                            }
                        }
                    }
                    # Only allow whitelisted user-agents
                    $is_admin = ( isset( $this->options[ 'admin_ip' ] ) && false !== $this->cmpstr( $this_ip, $this->options[ 'admin_ip' ] ) ) ? true: false;
                    if ( false !== $is_admin || ( false === $this->is_server() &&
                         false === $this->cmpstr( $user_agent, "''" ) &&
                         false === ( bool ) $this->datalist( $user_agent, 4 ) ) ) { // check if user-agent is whitelisted
                         $this->set_safe_domain();
                         $thisdomain = $this->get_http_host();
                         if ( false !== $this->is_ip_address( $thisdomain ) ) {
                            $thisdomain = ( isset( $this->safe_host ) ) ? $this->safe_host : $thisdomain;
                         }                          
                         if ( false !== $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ], true ) ) { // if request is POST then add post variables to log
                            $this_post = $this->flatten( $_POST );
                            $post_str = '';
                            foreach( $this_post as $key => $val ) {
                                if ( !is_array( $key ) && !is_array( $val ) ) $post_str .= $post_str . $key . '=' . $val . ',';
                            }
                            $user_agent = $user_agent . " \$_POST: " . ( ( strlen( $post_str ) > 100 ) ? substr( $post_str, 0, 120 ) . "..." : $post_str );
                         }
                         if ( ( bool ) false !== $this->_banip ) {
                            $this->karo( " Crawler/USER-AGENT: " . $user_agent, true, "Low", true, $thisdomain );
                         }
                    } else return;
                }
            }
            return;
        }
    }
    function flatten( $array, $prefix = '' ) {
        $result = array();
        foreach( $array as $key => $value ) {
            if ( is_array( $value ) ) {
                $result = $result + $this->flatten( $value, $prefix . $key . '.' );
            }
            else {
                $result[ $prefix . $key ] = $value;
            }
        }
        return $result;
    }    
    /**
	 * Strip port number from string
	 * 
	 * @return string
	 */
    function remove_ports( $host ) {
        $url_parts =  parse_url( $host );
        if ( isset( $url_parts[ 'host' ] ) && strlen( $url_parts[ 'host' ] ) > 4 && isset( $url_parts[ 'port' ] ) && strlen( $url_parts[ 'port' ] ) > 0 ) {
            return $url_parts[ 'host' ];
        } else return $host;
    }
    /**
	 * strip scheme from array variables
	 * @param $host_array
	 * @return array
	 */
    function fix_hosts( $host_array ) {
        $updated_host = array();
        if ( !is_array( $host_array ) ) {
           return preg_replace( "/https|http|:\/\//i", "", $this->remove_ports( $host_array ) );
        }
        for ( $x = 0; $x < count( $host_array ); $x++ ) {
                $a = $host_array[ $x ];
                $a = str_replace( 'https://', '', $a );
                $a = str_replace( 'http://', '', $a );
                if ( $this->cmpstr( strlen( $a ), 4 ) && $this->cmpstr( $a, 'www.', true ) ) $a = '';
                $updated_host[ $x ] = $this->remove_ports( $a );
        }
        return array_unique( $updated_host );
    }
    /**
	 * Filter HTTP_HOST
	 * @param $domain_list
	 * @return mixed
	 */
    function host_check( $domain_list ) {
        $checked_list = '';
        $checked_list = array();
        if ( is_array( $domain_list ) ) {
            for ( $x = 0; $x < count( $domain_list ); $x++ ) {
                    $y = $domain_list[ $x ];
                    if ( false !== filter_var( $y, FILTER_SANITIZE_URL ) ) $y = filter_var( $y, FILTER_SANITIZE_URL );
                    if ( false !== $this->check_ip( $y, true ) ) $y = filter_var( $y, FILTER_VALIDATE_IP );
            }
        }
         $domain_list = $this->fix_hosts( $domain_list );
         if ( is_array( $domain_list ) ) {
            return implode( "\n", $domain_list );
         } else return $domain_list;
    }
    /**
	 * check for URL in $string
	 * @param $string
	 * @return array
	 */
    function instr_url( $string, $domain_only = true ) {
        $urls = array();
        $dlist = ( false !== $domain_only ) ? explode( "\n", $string ) : $string;
        foreach ( $dlist as $domain ) {
            if ( false !== $domain_only ) {
                $domain = ( false === strpos( $string, '://' ) ) ? 'https://' . $domain : $domain;
                $domain = preg_replace( "/[\s]/i", " ", $domain );
            }
            preg_match_all( "/(?:(?:https?|ftp|file):\/\/|www\.|ftp\.)(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\/%=~_|$])/i", $domain, $matches );
            if ( count( $matches[ 0 ] ) > 0 ) {
                $domain = $matches[ 0 ][ 0 ];
                if ( false !== $domain_only ) {
                    $this_match = $domain;
                    $urls[] = $this_match;
                    if ( false === strpos( $this_match, "www." ) ) $urls[] = "www." . $this_match;
                } else $urls[] = $domain;
            } 
        }
        return array_values( array_unique( $urls ) );
    }
    /**
	 * check if string ends in .php
	 * @param $fname
	 * @return boolean
	 */
    function checkfilename( $fname ) {
        if ( false === empty( $fname ) && ( $this->cmpstr( $this->substri_count( $fname, '.php' ), 1 ) && false !== $this->cmpstr( '.php', substr( $fname, -4 ), true ) ) ) {
            return true;
        } else
            return false;
    }
    function get_real_path( $path ) {
        if ( function_exists( 'realpath' ) ) return realpath( $path );
        $path = str_replace( array( '/', '\\' ), DIRECTORY_SEPARATOR, $path );
        $parts = array_filter(explode( DIRECTORY_SEPARATOR, $path ), 'strlen' );
        $absolutes = array();
        foreach ( $parts as $part ) {
            if ( '.' == $part ) continue;
            if ( '..' == $part ) {
                array_pop( $absolutes );
            } else {
                $absolutes[] = $part;
            }
        }
        return implode( DIRECTORY_SEPARATOR, $absolutes );
    }    
    /**
	 * set the current file name, SCRIPT_FILENAME, PHP_SELF
	 * 
	 * @return string
	 */
    function get_filename() {
        $filename    = '';
        $_get_server = $_SERVER;
        $filename    = ( ( ( strlen( @ini_get( 'cgi.fix_pathinfo' ) ) > 0 ) && ( false === ( bool ) @ini_get( 'cgi.fix_pathinfo' ) ) ) ||
                         ( false === isset( $_get_server[ 'SCRIPT_FILENAME' ] ) && isset( $_get_server[ 'PHP_SELF' ] ) &&
                           false !== $this->string_prop( basename( $_get_server[ 'PHP_SELF' ] ), 1 ) ) ) ? basename( $_get_server[ 'PHP_SELF' ] ) : basename( realpath( $_get_server[ 'SCRIPT_FILENAME' ] ) );
        preg_match( "@[a-z0-9_-]+\.php@i", $filename, $matches );
        if ( is_array( $matches ) && array_key_exists( 0, $matches ) && false !== $this->cmpstr( '.php', substr( $matches[ 0 ], -4, 4 ), true ) && ( false !== $this->checkfilename( $matches[ 0 ] ) ) && ( $this->get_file_perms(  $matches[ 0 ], true ) ) ) {
          $filename = $matches[ 0 ];
        }
        return $filename;
    }
    /**
	 * filter array
	 * 
	 * @return string
	 */
    function cleanString( $b, $s ) {
        
        $s = strtolower( $this->url_decoder( $s ) );
        switch ( $b ) {
            case ( 0 ):
                return $s;
                break;
            case ( 1 ):
                return preg_replace( "/[^\s{}a-z0-9_?,()=@%:{}\/\.\-]/i", ' ', $s );
                break;
            case ( 2 ):
                return preg_replace( "/[^\s{}a-z0-9_?,=@%:{}\/\.\-]/i", ' ', $s );
                break;
            case ( 3 ):
                return preg_replace( "/[^\s=a-z0-9]/i", ' ', $s );
                break;
            case ( 4 ): // fwr_security pro
                return preg_replace( "/[^\s{}a-z0-9_\.\-]/i", '', $s );
                break;
            case ( 5 ):
                return str_replace( '//', '/', $s );
                break;
            case ( 6 ):
                return $this->remove_comments( $s );
                break;
            case ( 7 ):
                return base64_decode( $s );
                break;
            case ( 8 ):
                $s = preg_replace( "/[\s\r\n]/i", '', $s );
                $s = preg_replace( "/[^a-f0-9]/i", '', $s );
                return pack( "H*", $s );
                break;
            case ( 9 ):
                return trim( $s, " \t\n\r\0\x08\x0B" );
                break;
            case ( 10 ):
                return preg_replace( "/www\.|https:\/\/|http:\/\/|:\/\/|[^a-zA-Z0-9\.-]+/i", "", $s );
                break;
            case ( 11 ):
                return preg_replace('/[[:cntrl:]]/', '', $s ); // remove control characters
                break;            
            
            default:
                return $s;
        }
    }
    /**
	 * process htaccess filtering
	 *
	 * @params $mybans, $newline
	 * 
	 * @return array
	 */
    function do_htaccess( $mybans, $newline, $thisdomain ) {
        $final_htaccess = array();
        $mybansips = array();
        $thisdomain = $this->get_http_host();
        $limitstart = "# " . $thisdomain . " Pareto Security Ban\n";
        $limitend   = "# End of " . $thisdomain . " Pareto Security Ban\n";  
        for ( $i = 0; $i <= count( $mybans ); $i++ ) {
            if ( false !== strpos( $mybans[ $i ], "deny from" ) ) {
               if ( false !== ( bool ) preg_match( "/^deny from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i", $mybans[ $i ] ) ) {
                    $mybansips[] = $mybans[ $i ];
               }
            } elseif ( false === strpos( $mybans[ $i ], " Pareto Security Ban" ) &&
                       false === strpos( $mybans[ $i ], "order allow,deny" ) &&
                       false === strpos( $mybans[ $i ], "allow from all" ) ) {
                       $final_htaccess[] = $mybans[ $i ];
            }
        }
        # pop off the last empty lines, one at a time
        $n = count( $final_htaccess ) - 1;
        for( $x = 0; $x <= 3; $x++ ) {
            $n = count( $final_htaccess ) - 1;
            if ( strlen( $final_htaccess[ $n ] ) <= 2 ) unset( $final_htaccess[ $n ] );
            if ( $x > 3 ) break;
        }
        if ( count( $mybansips ) >= ( $this->_total_ips ) ) {
            $mybansips = array_reverse( $mybansips );
            $mybansips = array_splice( $mybansips, 0, $this->_total_ips - 1 );
            $mybansips = array_merge( $mybansips, array( $newline ) );
            $mybansips = array_reverse( $mybansips );
        } elseif ( count( $mybansips ) < $this->_total_ips ) $mybansips = array_merge( $mybansips, array( $newline ) );
        $final_htaccess = array_merge( $final_htaccess,  array( "\n\n" ), array( $limitstart ), array( "order allow,deny\n" ), $mybansips, array( "allow from all\n" ), array( $limitend ) );
        return $final_htaccess; 
    }
    /**
	 * open .htaccess, create string to append
	 *
	 * @params $banip
	 * 
	 * @return void
	 */
    function htaccessbanip( $banip ) {
        # if IP is empty or too short, or .htaccess is not read/write
        if ( false !== empty( $banip ) || ( strlen( $banip ) < 7 ) || ( false === $this->htapath() ) ||
           ( isset( $this->options[ 'admin_ip' ] ) && false !== $this->cmpstr( $banip, $this->options[ 'admin_ip' ] ) ) ) {
            return $this->karo( "", false, "Low", true );
        } else {
            $this->set_safe_domain();
            $mybans     = file( $this->htapath() );
            $thisdomain = $this->get_http_host();
            if ( false !== $this->is_ip_address( $thisdomain ) ) {
                $thisdomain = ( isset( $this->safe_host ) ) ? $this->safe_host : $thisdomain;
            }
            $limitend   = "# End of " . $thisdomain . " Pareto Security Ban\n";
            $newline    = "deny from $banip\n";
            $limitstart = "# " . $thisdomain . " Pareto Security Ban\n";
            if ( in_array( $newline, $mybans ) ) exit();
            if ( in_array( $limitend, $mybans ) && in_array( $limitstart, $mybans ) ) {
                # if Pareto Security is already present in htaccess
                $mybans = $this->do_htaccess( $mybans, $newline, $thisdomain );
            } else {
                array_push( $mybans, "\n", $limitstart, "order allow,deny\n", $newline, "allow from all\n", $limitend );
            }
            $this->write_htaccess( $mybans );
        }
    }
    /**
	 * remove all IP addresses from .htaccess
	 *
	 * @param $allips = boolean,
	 * #param $ip = string
	 * 
	 * @return void
	 */
    function htaccess_unbanip( $allips = true, $ip = '' ) {
        if ( false === $this->htapath() ) return;
        $final_htaccess = array();
        $mybans     = file( $this->htapath() );
        $thisdomain = $this->get_http_host();
        if ( false !== $this->is_ip_address( $thisdomain ) ) {
            $thisdomain = ( isset( $this->safe_host ) ) ? $this->safe_host : $thisdomain;
        }        
        $limitstart = "# " . $thisdomain . " Pareto Security Ban\n";       
        $limitend   = "# End of " . $thisdomain . " Pareto Security Ban\n";
        if ( empty( $mybans ) || false === in_array( $limitstart, $mybans ) ) return;
        if ( false !== $allips ) {
            update_option( PARETO_LOG_LIST, array(
                 0 => SETTINGS_INSTALL_LOG ) );
            $logfile = SETTINGS_INSTALL_LOG;
            $this->logs = array();
            $this->logs[ 0 ] = SETTINGS_INSTALL_LOG;
            # Clear bans from HTACCESS
            for ( $i = 0; $i <= count( $mybans ); $i++ ) {
                if ( false === strpos( $mybans[ $i ], " Pareto Security Ban" ) &&
                           false === strpos( $mybans[ $i ], "order allow,deny" ) &&
                           false === strpos( $mybans[ $i ], "deny from" ) &&
                           false === strpos( $mybans[ $i ], "allow from all" ) ) {
                           $final_htaccess[] = $mybans[ $i ];
                }
            }
            # pop off the last empty lines, one at a time
            $n = count( $final_htaccess ) - 1;
            for( $x = 0; $x <= 5; $x++ ) {
                $n = count( $final_htaccess ) - 1;
                if ( strlen( $final_htaccess[ $n ] ) <= 2 ) unset( $final_htaccess[ $n ] );
                if ( $x > 5 ) break;
            }            
            $mybans = $final_htaccess;
        } elseif ( strlen( $ip ) > 0 ) {
            # remnove a single entry
            for ( $x = 0; $x < count( $mybans ); $x++ ) {
                if ( strpos( $mybans[ $x ], $ip ) ) unset( $mybans[ $x ] );
            }
        }
        $this->write_htaccess( $mybans );
    }
    /**
	 * open htaccess, write array
	 *
	 * @param $mybans = array
	 * 
	 * @return void
	 */    
    function write_htaccess( $mybans ) {
        if ( !is_array( $mybans ) ) return;   
        $orig_octal = $this->dirfile_perms( $this->htapath() );
        if ( false === $this->get_file_perms( $this->htapath(), true, true ) ) {
            chmod( $this->htapath(), 0666 );
        }
        $myfile = fopen( $this->htapath(), 'w' );
        fwrite( $myfile, implode( $mybans, '' ) );
        fclose( $myfile );
        chmod( $this->htapath(), 0644 );
    }
    /**
	 * process file information
	 *
	 * @param $f = string
	 * @param $r = boolean
	 * @param $w = boolean
	 * 
	 * @return boolean
	 */ 
    function get_file_perms( $f = '', $r = false, $w = false ) {
        # f = if file exists return bool
        # r = if file exists & readable return bool
        # w = if file exists, readable & writable return bool
        $x = false;
        if ( false !== ( bool ) $w )
            $r = true;
        if ( false !== file_exists( $f ) ) {
            $x = true;
        } else
            return false;
        $x = ( false !== ( bool ) $r ) ? is_readable( $f ) : $x;
        $x = ( false !== ( bool ) $w ) ? is_writable( $f ) : $x;
        return ( bool ) $x;
    }
    function get_servername() {
        if ( false !== getenv( 'SERVER_NAME' ) && ( false !== ( bool ) $this->string_prop( getenv( 'SERVER_NAME' ), 2 ) ) ) {
            return getenv( 'SERVER_NAME' );
        } else {
            return $_SERVER[ 'SERVER_NAME' ];
        }        
    }
    function get_serverip() {
        if ( false !== getenv( 'SERVER_ADDR' ) && ( false !== ( bool ) $this->string_prop( getenv( 'SERVER_ADDR' ), 2 ) ) ) {
            return getenv( 'SERVER_ADDR' );
        } else {
            return $_SERVER[ 'SERVER_ADDR' ];
        }
    }
    
    /**
	 * get the host name
	 *
	 * @param $withhttp = boolean
	 * @param $encoding = string
	 * 
	 * @return string
	 */ 
    function get_http_host( $withhttp = false, $encoding = 'UTF-8' ) {
        $is_ip = false;
        $final_sname = "";
        $servername = $this->get_servername();  
        $final_sname = htmlspecialchars( $servername, ( ( version_compare( phpversion(), '5.4', '>=' ) ) ? ENT_HTML5 : ENT_QUOTES ), $encoding );
        $final_sname = filter_var( $final_sname, FILTER_SANITIZE_URL );
        if ( false === $final_sname ) $this->karo( $final_sname . " :: Failed Filter Test", false, 'Low', true );
        $final_sname = $this->cleanString( 9, $final_sname );
        $final_sname = $this->cleanString( 11, $final_sname );

        # filter domain names
        $http       = ( false !== $withhttp ) ? ( ( ( array_key_exists( 'HTTPS', $_SERVER ) && $this->cmpstr( "on", @$_SERVER[ "HTTPS" ], true ) ) ||
                                                    ( array_key_exists( 'HTTPS', getenv() ) && $this->cmpstr( "on", getenv( "HTTPS" ), true ) ) ) ? 'https://' : 'http://' ) : '';
        return $http . trim( $final_sname );
    }
    function _detect_tor() {
      $is_tor = false; // if error, always return false
      if ( $_SERVER[ 'SERVER_ADDR' ] ) {
        # give TorHS and admins a pass
        if ( false !== $this->cmpstr( $this->get_serverip(), '127.0.0.1' ) && false !== $this->cmpstr( $this->get_ip(), '127.0.0.1' ) ) return false; // likely either admin accessing the site or website is running on a TorHS
        $req = $this->_reverse_ip( $this->get_ip() ) . "." . $_SERVER[ 'SERVER_PORT' ] . "." . $this->_reverse_ip( $_SERVER[ 'SERVER_ADDR' ] ) . ".ip-port.exitlist.torproject.org.";
        $is_tor = ( "127.0.0.2" == gethostbyname( $req ) ) ? true : false;
        return $is_tor;
      } else return false;
    }
    function _reverse_ip( $ip ) {
      return implode( ".", array_reverse( explode( ".", $ip ) ) );
    }
    function tor_restrict() {
        if ( false === ( bool ) $this->_tor_block ||
             false !== $this->is_wp( true, true ) ||
             false === $this->is_wp() ||
             false !== $this->is_admin_ip() ) return;
        
        $istor = ( false !== $this->_detect_tor() ) ? true : false;
        if ( false === $istor ) return;
        $_get_server = $_SERVER;

        if ( false !== $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ], true ) ||
             isset( $_REQUEST[ 's' ] ) ||
             false !== stripos( $this->get_filename(), 'wp-login.php' ) ||
             false !== stripos( $this->get_filename(), 'xmlrpc.php' ) ) exit( '<center><font face="verdana" size="1">Notice: Pareto Security plugin settings have prevent you from accessing aspects of this website using Tor</font></center>' );
    }
    function is_admin_ip() {
        $is_admin_ip = ( false !== isset( $this->options[ 'admin_ip' ] ) && false !== $this->cmpstr( $this->get_ip(), $this->options[ 'admin_ip' ] ) ) ? true : false;
        return $is_admin_ip;
    }
    /**
	 * get the full URL
	 *
	 * @param $withhttp = boolean
	 * 
	 * @return string
	 */     
    function getURL( $withhttp = true ) {
        $pre_req = $this->getREQUEST_URI();
        $q = ( bool ) isset( $_SERVER[ 'QUERY_STRING' ] );
        $is_q = ( bool ) strpos( $pre_req, "?" );
        $query     = ( false !== $is_q ) ? "?" . $_SERVER[ 'QUERY_STRING' ] : "";
        $req     = ( false !== $is_q ) ? $this->decode_code( substr( $pre_req, 0, strpos( $pre_req, '?' ) ) ) : $pre_req;
        $this->do_blacklists( $req, 1, "Request", true, "High", true, true, true );
        $locale  = ( ( false !== $withhttp ) ? $this->get_http_host( true ) : $this->get_http_host( false ) ) . $req . $query;
        $locale  = $this->cleanString( 9, $locale );
        return $locale;
    }
    /**
	 * get the directory path to the root folder
	 * 
	 * @return string
	 */   
    function get_dir() {
        $get_root                       = '';
        $_get_server                    = $_SERVER;
        if ( isset( $this->_doc_root ) && ( false !== ( bool ) $this->string_prop( $this->_doc_root, 2 ) ) ) {
            # is set by the user
            $get_root = $this->_doc_root;
        } elseif ( false !== $this->is_wp() && false !== defined( 'ABSPATH' ) ) {
            $get_root = ABSPATH;
        } elseif ( false !== strpos( $_get_server[ 'DOCUMENT_ROOT' ], 'usr/local' ) || empty( $_get_server[ 'DOCUMENT_ROOT' ] ) || strlen( $_get_server[ 'DOCUMENT_ROOT' ] ) < 4 ) {
            # if for some reason there is a problem with DOCUMENT_ROOT, then do this the bad way
            $f     = dirname( __FILE__ );
            $sf    = realpath( $_get_server[ 'SCRIPT_FILENAME' ] );

            $fbits = explode( DIRECTORY_SEPARATOR, $f );
            foreach ( $fbits as $a => $b ) {
                if ( false === empty( $b ) && ( false === strpos( $sf, $b ) ) ) {
                    $f = str_replace( $b, '', $f );
                    $f = str_replace( '//', '', $f );
                }
            }
            $get_root = realpath( $f );
        } else {
            $get_root = realpath( $_get_server[ 'DOCUMENT_ROOT' ] ) . PHP_EOL;
        }
        if ( strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN' ) {
            $get_root = str_replace( '/', '\\', $get_root );
        } else
            $get_root = str_replace( '\\', '/', $get_root );
        if ( !defined( 'WP_PLUGIN_DIR' ) ) {
            return $_get_server[ 'DOCUMENT_ROOT' ];
        } else return $get_root;
    }
    /**
	 * check the ip address is not the server
	 *
	 * @param $ip = string
	 * @param $localhost = boolean
	 * 
	 * @return boolean
	 */   
    function is_server( $ip = '', $localhost = true ) {
        # tests if ip address reported as _SERVER[ 'SERVER_ADDR' ]
        # is either server ip ( localhost access ) or is 127.0.0.1
        # ( i.e onion visitors )
        if ( $this->cmpstr( strlen( $ip ), 0 ) ) $ip = $this->get_ip();
        if ( false !== $this->cmpstr( $ip, $this->get_serverip() ) ) {
            return true;
        } elseif ( ( false !== $localhost ) &&  $this->cmpstr( '127.0.0.', substr( $ip, 0, 8 ) ) ) {    
            return true;
        }
        return false;
    }
    /**
     * $this->check_ip()
     *
     * @param mixed $ip
     * @return boolean
     */
    function check_ip( $ip, $bypass = false ) {
        if ( function_exists( 'filter_var' ) && defined( 'FILTER_VALIDATE_IP' ) && defined( 'FILTER_FLAG_IPV4' ) && defined( 'FILTER_FLAG_IPV6' ) ) {
            if ( false === ( bool ) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 || FILTER_FLAG_IPV6 ) ) return false;
            if ( false !== $this->is_server( $ip ) ) {
                if ( false === ( bool ) $bypass ) $this->_bypassbanip = true;
            }
            return true;
        } else return false;
    }
    /**
     * get_ip()
     *
     * @return
     */
    function get_ip() {
        
        $_get_server = $_SERVER;
        $svars       = array(
                                'HTTP_FORWARDED_FOR',
                                'HTTP_CLIENT_IP',
                                'HTTP_X_CLUSTER_CLIENT_IP',
                                'HTTP_X_ORIGINATING_IP',
                                'HTTP_X_REMOTE_IP',
                                'HTTP_FORWARDED',
                                'HTTP_CF_CONNECTING_IP',
                                'HTTP_X_FORWARDED_FOR' 
                            );
        
        # the point here is to not accidentally ban an ip address that could
        # be an upline proxy, instead just allow an exit() action if
        # it turns out the request is malicious
        $x = 0;
        while ( $x < count( $svars ) ) {
            $iplist = array();
            if ( array_key_exists( $svars[ $x ], $_get_server ) ) {
                $the_header = $_get_server[ $svars[ $x ] ];
                $the_header = ( false !== strpos( $the_header, ',' ) ) ? str_replace( ' ', '', $the_header ) : str_replace( ' ', ',', $the_header );
                if ( false !== strpos( $the_header, ',' ) ) {
                    $iplist = explode( ',', $the_header );
                    # Check the validity of each ip
                    foreach ( $iplist as $ip ) {
                        if ( false !== $this->check_ip( $ip ) ) {
                            $this->_bypassbanip = true;
                        }
                    }
                } elseif ( false === empty( $_get_server[ $svars[ $x ] ] ) && false !== $this->check_ip( $_get_server[ $svars[ $x ] ] ) ) {
                    $this->_bypassbanip = true;
                }
            }
            $x++;
        }
        $this_ip = $this->getREMOTE_ADDR();
        if ( false !== $this->cmpstr( $this_ip, '::1' ) )
            $this_ip = '127.0.0.1';
        # for TorHS to prevent banning of server IP
        if ( false !== $this->is_server( $this_ip ) ) {
            $this->_bypassbanip = true;
        }
        # generally speaking, never trust any ip headers except REMOTE_ADDR
        return $this_ip;
    }
    /**
     * x_secure_headers()
     */
    function x_secure_headers() {
        $errlevel = @ini_get( 'error_reporting' );
        error_reporting( 0 );
        $header = array(
            "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            "access-control-allow-methods: GET, POST, HEAD",
            "X-Frame-Options: SAMEORIGIN",
            "X-Content-Type-Options: nosniff",
            "X-Xss-Protection: 1; mode=block",
            "X-download-options: noopen",
            "X-Permitted-Cross-Domain-Policies: master-only",
            "Content-Type: text/html; charset=UTF-8" 
        );
        if ( false !== ( bool ) @ini_get( 'expose_php' ) || false !== $this->cmpstr( 'on', @ini_get( 'expose_php' ), true ) ) {
            array_push( $header, "X-powered-by: Pareto Security - https://wordpress.org/plugins/pareto-security/" );
        }
        foreach ( $header as $sent ) {
            header( $sent );
        }
        error_reporting( $errlevel );
        return;
    }
    /**
     * substri_count()
     */
    function substri_count( $hs, $n ) {
        return substr_count( strtoupper( $hs ), strtoupper( $n ) );
    }
    /**
     * decode_code()
     * @return
     */
    function decode_code( $code, $escapeshell = false, $b64_decode = false, $filter = false ) {
        $code = ( $this->substri_count( $code, '\u00' ) > 0 ) ? str_ireplace( '\u00', '%', $code ) : $code;
        $code = ( $this->substri_count( $code, '&#x' ) > 0 && substr_count( $code, ';' ) > 0 ) ? str_replace( ';', '%', str_replace( '&#x', '%', $code ) ) : $code;
        $code = ( false !== $b64_decode ) ? base64_decode( $code ) : $code;
        if ( false !== $escapeshell ) {
            $code = str_replace( "'", "", $code );
            return $this->url_decoder( escapeshellarg( $code ) );
        } elseif ( false !== $filter ) {
            return filter_var( $this->url_decoder( $code ), FILTER_UNSAFE_RAW, FILTER_SANITIZE_SPECIAL_CHARS );
        } else
            return $this->url_decoder( $code );
    }
    /**
     * url_decoder()
     */
    function url_decoder( $var ) {
        return rawurldecode( urldecode( str_replace( chr( 0 ), '', $var ) ) );
    }
    function controlchar_exists( $input ) {
        $char_count  = strlen( preg_replace( '/[^\x00-\x08\x10-\x19]/', '', $input ) ); // detect null-printing control characters
       #$char_count  = strlen( preg_replace( '/[^\x0E\x0F\x1A\x1B\xC29D\xDFBD\xDFBE\xDFBF]/', '', $input ) ); // This filter is causing false positives
        if ( $char_count > 0 ) return true;
        return false;
    }
    function htmlentities_safe( $input ) {
        if ( function_exists( 'utf8_encode' ) ) {
            return htmlentities( utf8_encode( $input ), ENT_HTML5 | ENT_QUOTES | ENT_SUBSTITUTE | ENT_DISALLOWED ); // PHP 7.2
         } else {
            return htmlentities( $input, ENT_HTML5 | ENT_QUOTES | ENT_SUBSTITUTE | ENT_DISALLOWED, 'UTF-8' ); // PHP 5.4 to 7.1
         }
    }
    /**
     * getREQUEST_URI()
     */
    function getREQUEST_URI() {
        if ( false !== getenv( 'REQUEST_URI' ) && ( false !== ( bool ) $this->string_prop( getenv( 'REQUEST_URI' ), 2 ) ) ) {
            return strtolower( $this->url_decoder( getenv( 'REQUEST_URI' ) ) );
        } else {
            return strtolower( $this->url_decoder( $_SERVER[ 'REQUEST_URI' ] ) );
        }
    }
    /**
     * getREMOTE_ADDR()
     */
    function getREMOTE_ADDR() {
        if ( false !== getenv( 'REMOTE_ADDR' ) && ( false !== ( bool ) $this->string_prop( getenv( 'REMOTE_ADDR' ), 2 ) ) && false !== $this->check_ip( getenv( 'REMOTE_ADDR' ) ) ) {
            return getenv( 'REMOTE_ADDR' );
        } elseif ( false !== $_SERVER( 'REMOTE_ADDR' ) && ( false !== ( bool ) $this->string_prop( $_SERVER( 'REMOTE_ADDR' ), 2 ) ) && false !== $this->check_ip( $_SERVER( 'REMOTE_ADDR' ) ) ) {
            return $_SERVER[ 'REMOTE_ADDR' ];
        }
    }
    /**
     * getQUERY_STRING()
     */
    function getQUERY_STRING() {
        if ( false !== getenv( 'QUERY_STRING' ) ) {
            return strtolower( $this->decode_code( getenv( 'QUERY_STRING' ) ) );
        } elseif ( isset( $_SERVER[ 'QUERY_STRING' ] ) ) {
            return strtolower( $this->decode_code( $_SERVER[ 'QUERY_STRING' ] ) );
        } else return false;
    }
    /**
     * string_prop()
     */
    function string_prop( $str, $len = 0 ) {
        # is not an array, is a string, is of at least a specified length ( default is 0 )
        if ( false !== is_array( $str ) )
            return false;
        $x = false;
        $x = ( is_string( $str ) ) ? ( ( strlen( $str ) >= ( int ) $len ) ? true : false ) : false;
        return ( bool ) $x;
    }
    /**
     * integ_prop()
     */
    function integ_prop( $integ ) {
        if ( false !== ( $this->cmpstr( strval( $integ ), strval( intval( $integ ) ) ) ) && ( false !== filter_var( $integ, FILTER_VALIDATE_INT ) ) &&
                       ( false !== ctype_digit( strval( $integ ) ) ) && ( false !== preg_match( '/^\d+$/', $integ ) ) && ( $this->cmpstr( $integ, 0 ) || false === empty( $integ ) ) &&
                       ( false !== is_int( $integ ) ) && ( false === is_float( $integ ) ) ) {
            if ( function_exists( 'filter_var' ) && defined( 'FILTER_VALIDATE_INT' ) ) {
                return ( ( filter_var( $integ, FILTER_VALIDATE_INT ) === 0 || false !== filter_var( $integ, FILTER_VALIDATE_INT ) ) ? true : false );
            } else
                return true;
        } else
            return false;
    }
    /**
     * cmpstr()
     * @return bool
     */
    function cmpstr( $s, $c, $ci = false ) {
        if ( false !== $ci ) {
            if ( strcasecmp( $s, $c ) == 0 ) {
                return true;
            } else
                return false;
        } elseif ( false === $ci ) {
            if ( strcmp( $s, $c ) == 0 ) {
                return true;
            } else
                return false;
        }
    }
    function htapath() {
        $dir_path = NULL;
        if ( false !== $this->is_wp() ) {
            include_once( ABSPATH . 'wp-admin/includes/file.php' );
            if ( false !== $this->get_file_perms( ( get_home_path() . '.htaccess' ), TRUE, TRUE ) ) {
                $dir_path = get_home_path() . '.htaccess';
            }
        }
        $rpath_arr = explode( DIRECTORY_SEPARATOR, $this->get_dir() );
        # we don't want to test back too far.
        $x         = 0;
        $root_path = NULL;
        While ( false === $this->cmpstr( get_current_user(), $rpath_arr[ count( $rpath_arr ) - 1 ], true ) ) {
            $root_path = str_replace( "//", "/", implode( DIRECTORY_SEPARATOR, $rpath_arr ) . DIRECTORY_SEPARATOR . '.htaccess' );
            if ( false !== $this->get_file_perms( $root_path, TRUE, TRUE ) )
                break;
            if ( false !== $this->cmpstr( $this->get_http_host(), $rpath_arr[ count( $rpath_arr ) - $x ], true ) )
                break;
            if ( $x > 20 )
                break; // we're likely looping :-/
            array_pop( $rpath_arr );
            $x++;
        }
        $dir_path = ( false !== is_null( $dir_path ) && false === $this->is_wp() ) ? $this->get_dir() . '/.htaccess' : $dir_path;
        if ( false === is_null( $root_path ) ) {
            return $root_path;
        } elseif ( false !== $this->get_file_perms( $dir_path, TRUE, TRUE ) ) {
            return $dir_path;
        } else
            return false;
    }
    function email_log( $pareto_report2 = '' ) {
        $blog_email     = 'wordpress@' . $this->get_http_host();
        $admin_email    = get_option( 'admin_email' );
        $blog_name      = get_option( 'blogname' );
        $blog_url       = ( false !== strpos( get_option( 'siteurl' ), $this->get_http_host() ) ) ? get_option( 'siteurl' ) : $this->get_http_host( true );
        $headers        = array(
            'Content-Type: text/html; charset=UTF-8',
            'From: Pareto Security - ' . $blog_name . ' <' . $blog_email . '>' 
        );
        $img_tag        = '<img src="' . $this->ps_icon . '">';

            $pareto_report  = '    
                          <!--[if mso]>
                                <style type="text/css">
                                body, table, tr, td {font-size: small; font-family: Verdana, Helvetica, sans-serif !important;}
                                </style>
                          <![endif]-->
       <style>
        code{
            direction: ltr;
            text-align: left;
        }
        code {font-size:1.0em;
              margin: 0px; 
              padding:5px;
              background-color:transparent;
              color: #3E3E3E}        
        </style>                          
                          <table style="width:100%;">
                                <tr style="background-color:#F3F3F3;">
                                    <td>' . $img_tag . '</td><td><H2>PARETO SECURITY LOG FILE</H2></td>
                                </tr>
                                <tr>
                          </table>
                          <table style="width:100%;">
                                <tr>
                                    <td><strong>Record of the Last 5 High/Med Severity Incidents</strong></td>
                                </tr>
                                <tr>
                          </table>
                          <table style="width:100%; text-align: left; background-color: #C9C9C9;">
                                    <tr>
                                        <td>
                                        <table style="width: 100%; text-align: left;">
                                            <tbody>
                                              <tr style="background-color:#5F607B; color: #FFFFFF;font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;">
                                                <td style="width:100px; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif; color: #FFFFF;"><b>Date-Time:</b></td>
                                                <td style="width:60px; color: #FFFFFF;font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;"><b>Severity:</b></td>
                                                <td style="width:120px; color: #FFFFFF;font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;"><b>IP Address:</b></td>
                                                <td style="width:50px; color: #FFFFFF;font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;"><b>Req:</b></td>
                                                <td style="width:80px; color: #FFFFFFfont-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;;"><b>Filename:</b></td>
                                                <td style="color: #FFFFFF;font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;"><b>Attack String:</b></td>
                                              </tr>
                                              <tr>
                                                <td></td>
                                                <td></td>
                                                <td></td>
                                                <td></td>
                                                <td></td>
                                              </tr>';
        $pareto_report3 = '';
        $mylogs = array();
        
        $mylogs     = get_option( PARETO_LOG_LIST );
        $i          = 0;
        $text_color = "#e68735";
        $n = 0;
        while ( $i <= 99 ) {
            if ( isset( $mylogs[ $i ] ) && $n < 4 ) {
                $row_colour = ( $this->cmpstr( ( $i % 2 ), 0 ) ) ? "#E6E6F5" : "#F3F3F3";
                $req_var    = explode( ' ', $mylogs[ $i ] );
                if ( preg_match( "/low|safe/i", $req_var[ 1 ] ) ) {
                        $i++;
                        continue;
                } else $n++;
                if ( $this->cmpstr( $req_var[ 1 ], "Medium", true ) ) {
                    $text_color = "#e68735";
                } elseif ( empty( $req_var[ 1 ] ) ) {
                    $req_var[ 1 ] = "Medium";
                    $text_color   = "#e68735";
                } else
                    $text_color = "#c72b2c";
                $mylogs_fin[ $i ] = $mylogs[ $i ];
                $ip_addr          = $req_var[ 2 ];
                $attack_string    = str_replace( '%20', " ", preg_replace( "/[\n]/i", "", stripslashes( $req_var[ 5 ] ) ) );
                $attack_string    = ( strlen( $attack_string ) > 250 ) ? wordwrap( $attack_string, 200, "<br />\n" ) : $attack_string;
                $this_timestamp = ( false !== is_numeric( $req_var[ 0 ] ) ) ? $this->set_timestamp( $req_var[ 0 ] ): $req_var[ 0 ];
                $pareto_report3 .= "\n<tr style=\"background-color: " . $row_colour . ";\">\n" .
                                   "    <td style=\"vertical-align:top; width:100px; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif; white-space: nowrap\">" . $this->url_decoder( $this_timestamp ) . "</td>\n" .
                                   "    <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;text-align: center; width:60px; white-space: nowrap; font-weight: bold; color:" . $text_color . "\">" . $req_var[ 1 ] . "</td>\n" .
                                   "    <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:140px; white-space: nowrap\">" . $ip_addr . "</td>\n" .
                                   "    <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:50px; white-space: nowrap\">" . $req_var[ 3 ] . "</td>\n" .
                                   "    <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:100px; white-space: nowrap\">" . $req_var[ 4 ] . "</td>\n" .
                                   "    <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;white-space: nowrap\"><code>" . $attack_string . "</code></td>\n</tr>\n";
            } else
                break;
            $i++;
        }
        $pareto_report3 .= '
        </table>
                </td>
            </tr>
        </table>
        <br /><br />Pareto Security :: <a target=_"Blank" href="https://hokioisecurity.com/?p=17">https://hokioisecurity.com</a>
        <br /><br />You are receiving these because you enabled Email Notifications for Pareto Security. To disable notifications, go
        <a target="Blank" href="' . $blog_url . '/wp-admin/options-general.php?page=pareto_security_settings">here</a>';
        
        $pareto_report_full = $pareto_report . $pareto_report2 . $pareto_report3;
        $status = wp_mail( $admin_email, 'Pareto Security Attack Report for ' . $blog_url, $pareto_report_full, $headers );
    }
    function get_wp_current_user() {
            $current_user = wp_get_current_user();
            $this_user = $current_user->user_login;
            return $this_user;
    }
    /**
     * check if this is Wordpress
     *
     * @param boolean $isinadmin
     * @param boolean $isadmin
     * @param boolean $is_authorised
     * 
     * @return boolean
     */
    public function is_wp( $isinadmin = false, $isadmin = false, $is_authorised = false ) {
        if ( defined( 'WP_PLUGIN_DIR' ) && false !== function_exists( 'is_admin' ) ) {
            if ( false !== $isinadmin ) {
                if ( ( false === ( bool ) defined( 'WP_ADMIN' ) || false !== WP_ADMIN ) && false === is_admin() ) return false;
            }
            if ( false !== $isadmin ) { // current user has administrators rights
                $current_user = $this->get_wp_current_user();
                if ( false !== is_object( $current_user ) ) {
                    $is_superadmin = ( false === function_exists( 'is_super_admin' ) && false !== is_super_admin( $current_user->ID ) ) ? true : false;
                    if ( function_exists( 'user_can' ) && false === ( bool ) user_can( $current_user, 'administrator' ) && false === $is_superadmin ) return false;
                } elseif ( false === is_object( $current_user ) && false !== is_admin() && $current_user == 0 ) {
                       if ( current_user_can( 'editor' ) || current_user_can( 'administrator' ) || current_user_can( 'setup_network' ) ) {
                            return true;
                       } else return false;
                } else return false;
            }
            if ( false !== $is_authorised ) {
                    $current_user = $this->get_wp_current_user();
                    if ( function_exists( 'user_can' ) && false === user_can( $current_user, 'editor' ) && false === user_can( $current_user, 'author' ) ) {
                        return false;
                    }
            }
            return true;
        }
        return false;
    }
    public function do_security_settings() {
        # defaults sets errors to production settings
        $this->_set_error_level();
        # disable assert function in local scope
        # shouldn't be available to production websites
        @ini_set( 'assert.active', '0' );
        # Send secure headers
        $this->x_secure_headers();
        $this->tor_restrict();
        if ( false !== $this->is_wp() ) {
            $this->settings_field = 'pareto_security_settings_options';
            $this->options = get_option( $this->settings_field );
        # set the safe domain
        $this->set_safe_domain();
        }
        $this->ps_icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAACXBIWXMAAAsSAAALEgHS3X78AAAHkElEQVR4nO3aW1MaaRoH8PkSe7e3c7u1tZdblUrUUVOzmamtGfGAZqICTeMRUWMwnBVoRE6CZwl4yDg4QtydqMMaVjRG8IByEEU5KGDwEGcS5AvsBTuk7SZKtCdK1Tz1v3pvnv5Vv89L09WfRdO8PrvuC7hq/QG47sIMEDp4Ez44Dr0+2ts/9IUOt4OHnuDRVujI5d/XajTqgYGenh6VSqVSKg16PVZNo1gBDt78+jmef4sAZRKhDCL09zLorw+gz0ugP+OhP+GFPDaLzXoftVqNSdN4YQM4PP4lGxDlguJ47oLiu6A4FxRnkdv+RhBxzwIG+vsxaRovbACvj06+IL0HwCXZIBLQ19eHSdN4YQbISgbIBcVfUkQcBKC3F5Om8cJoBo5/ySAmB/wjPQBvfv1LCf82QXiHIMwkCDMIwkwiFE8uIEQA+m/gFopGoxu+sGsnaN8KrLh8Fvt2IrMWO4vBuFlD3Pvjf6uFQ5QWDZGjLmX0FdO7Cxo78xtUeTQlOoX1Cg7rht0BpkqfdLsnzb2KNvQMhMPhqcnJ6d9qanJyf38/bQC9PT329fXqqqrampp4qiornU5n2gC6OjvXbLY6KrWeRouHWltrX19PG4BKqVxZWUEAbKurnw5Al49lEKAUgz5GOxQKq9WKACwvL386gHd3f9Xltdq3F2xbc8sbJovTuGCfnLP9ZE4Sg3GRxTxzjMplslevXiEAFovl9wI8eTZHl+uaZD80SEZp4qe1ohGqaKQWGqkWDlXyB8EW7fmp4A1wWEw4QCaVzs/PIwALCwsnJyeRSCQcDu/t7QWDwYODA2wArC5D6js+lRmQSaWzs7MIwPz8fHdXFxkAiAQCkUAAyeQOheLmAl68eIEAmM1mmVRKBoBE+K2t2AA43dgDjEYjAmAymUQQBAcwGQxsAC29E5gDpqemEICZmRkBnw8HND18iA2gtW8iiwhdOnfJUIoAHo8HB9Dq6qLRaCQSCYVCu7u7gUAgEol8BOD09DQWi8VisRmLq1NnunRUT6fZzDOnkFQiSQpgMBhwQHVVld/vLykuzsfh8nG4woICSCi8AOAJhDldBk6XgaEcfyQfeyQfa5KPMZTjrE7DpcNU6tislABNDx/CARQQdG9s5ONw+KKieBobGi4AWB07t8sE2UAbhvkSRP4j+xCgsaEBDgDJ5LW1NVxeXgJAAcELAEtObyYRusrIpjLEUolkenr6QgAZAJaWluCA+yUl7969SxsAQCJZFhfhgMKCghsBkEmlP6cAIBGJaMDbt28vmoFyQTbQlk1uywXbYRGjVtpzQHEOOX6V7xezyW1oAJfN4sAil8n+YzTW19U10Gjx1FFrTSZTY0M9CACJAESi1WqFD3HRhQBPIPy448dHcl21QHuPyLpHYt0jsb4isb+t5FfwBr4GOP8EuYngaZLyZtW3lYJvKvn/T0VrRctAfg0ET2GtkEbn1dG5v4XHgRSaH/5VQWOAVDpYSwep9Ara45HxyUoa4wGZCo/u3zOFpRTcfSCewlLKy9XNFZfX7Q0mB8QrFou5nI4CXF5xUWFxUWExvohEJKyv2QhlpSBASkTZoRgf0zXW1zfU0+Kh1lS7nE42k8FlsxJhMNlfkNtzwPfJJouzSCL4Sg7Yjl6JL+ZS2nMpknhywPYMIpRJhG6XCc4DRKPR9fV1+OYryM+3Wq3lZWXwPapQKAYHBxP7uJ5Gq62pcToczLMvUZoZ7BxMhyoXFGcDbRcAEAfwhwBarRYBcNwUgM2W3gCHw5HSFkIBbsoW2nS7EQfwUmqApHcg4woPs0lzp/yiIfZ6vbi8vPhjYD4OV4zHLy8tpTLEaIBAIFzbCq66dy+dTf9rX+jAG4x49177Qwd7+4fhg+MLAEdHR98/fTo4OKjVaIaHh58/f+5wONCAoaGhlO4AAUq8rP7Y3Crlj04tJr3I8wDoctjtlwZcZQaySCLd9HlvXFIF2JMBhlEAp9N5QwEbGxsIgLKjA30HXC4X5oAJ0woGgO3t7e/u3yeUlyeSFOB2uzEHGBfsGAAODw9HR0f1ev3Es2d6vX5Mp7NaLOgfss3NTQSAzmDfSflFKjq3SvlzK24MAOiKxWJqtRoB8Hg86GPU5g7Y3P5zsrYZsG/tOj27rp095/aec3vPvRPc9IU8/vB2YP/w+OR3AZyenj5BAXZ2dhCAx0zOV9Xyr2tk6HxTp8hvVBU/6n7A6CNyBigtmopW7fkbBktANBpFA7xeL/zqP3YGskii0clXnw6g0WgQAL/fz+Vw0gYwhHqUCAQCLTxe2gB0Ol0znZ5IU2NjKBjkt7amDSBpCQUCBCD1Y/RWKX/kp5fXDBBBEBzA5wuMCw7jgh2dmUXnC4vTvLzx0rZpsXtWXN41ty8cObpmgFgshgOYLG4ZayARAltNadXWQMP17d+zVBh8uoU9QCKRpDgD+Kbuq7fDHiCXydIboFAoUgR814zBh0PYA5RKZYoAgPvk6u2wB3R1dp4FcD70l7KSr716O+wB3V1dj5ubE+FwWzQT82qDud9g7tPP9o7P9uln+w1mtcE8Obd29XbYAwKBgAdWPp8P8xbw+uPT4+uu/wEGULwcmNYlVgAAAABJRU5ErkJggg==";
    }
    function set_timestamp( $unixtime ) {
        if ( false === is_int( (int ) $unixtime ) ) return $unixtime;
        $offset = $this->_time_offset;
        return ( false !== $this->is_wp() ) ? date_i18n( 'd-m-Y', ( $this->updated( $unixtime, $offset ) ) ) . "<br>" .
                                              date_i18n( 'h:i:sA', ( $this->updated( $unixtime, $offset ) ) ) : date( "d.m.y-G:i" );
    }
    public function advanced_mode( $mode = 0 ) {
        if ( false !== ( bool ) $mode ) {
            $this->_banip            = 1;
            $this->_adv_mode         = 1;
            $this->_post_filter_mode = 1;
        }
    }
    function is_iis() {
        $software = strtolower( $_SERVER[ "SERVER_SOFTWARE" ] );
        if ( false !== strpos( $software, "microsoft-iis") )
            return true;
        else
            return false;
    }
}
