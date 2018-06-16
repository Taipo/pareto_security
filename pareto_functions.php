<?php
class pareto_functions {
    # if open_basedir is not set in php.ini. Leave disabled unless you are sure about using this.
    protected $_open_basedir = 0;
    # activate _SPIDER_SHIELD()
    public $_hard_ban_mode = false;
    public $_spider_block = 0;
    # ban attack ip address to the root /.htaccess file. Leave this disabled if you are hosting a website using TOR's Hidden Services
    protected $_banip = 0;
    # path to the root directory of the site, e.g /home/user/public_html
    public $_doc_root = '';
    # log file directory
    public $_log_dir = '';
    # Correct Production Server Settings = 0, prevent any errors from displaying = 1, Show all errors = 2 ( depends on the php.ini settings )
    public $_quietscript = 0;
    # Custom set a number of above settings all at once
    public $_adv_mode = 0;
    # Other
    protected $_bypassbanip = false;
    protected $_spider_bypass = false;
    public $_post_filter_mode = 0;
    public $_timestamp = '';
    public $log_list = 'pareto_security_log_list';
    public $settings_field = 'pareto_security_settings_options';
    public $ip_hash_list = 'pareto_security_ip_flood_list';
    protected $_ban_time = 86400; // 24 hours
    protected $_hard_ban_count = 20; // failed login attempts in a 24 hours period
    protected $_get_all = array();
    protected $_post_all = array();
    protected $_log_file = '';
    protected $_log_file_key = '';
    function __construct() {
        define( 'PARETO_LOGS', dirname( __FILE__ ) . "/logs/" );
        $this->set_crypto_key_file();
        $this->set_safe_request();
    }
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
    
    /**
     * send403()
     *
     */
    function send403() {
        $status   = '403 Access Denied';
        $protocol = ( isset( $_SERVER[ 'SERVER_PROTOCOL' ] ) ? substr( $_SERVER[ 'SERVER_PROTOCOL' ], 0, 8 ) : 'HTTP/1.1' ) . ' ';
        $header   = array(
             $protocol . $status,
            'Status: ' . $status,
            'Content-Length: 0'
        );
        foreach ( $header as $sent ) {
            header( $sent );
        }
        exit();
    }
    
    /**
     * send444()
     *
     */
    function send444() {
        error_reporting( 0 );
        $status   = '444 No Response';
        $protocol = ( isset( $_SERVER[ 'SERVER_PROTOCOL' ] ) ? substr( $_SERVER[ 'SERVER_PROTOCOL' ], 0, 8 ) : 'HTTP/1.1' ) . ' ';
        $header   = array(
             $protocol . $status,
            'Status: ' . $status 
        );
        
        foreach ( $header as $sent ) {
            header( $sent );
        }
        exit();
    }
    function _activate() {
        $this_log = str_replace( ' ', '%20', PARETO_RELEASE_DATE ) . " Safe " . str_replace( ' ', '%20', $_SERVER[ 'SERVER_ADDR' ] ) . " GET plugins.php Pareto%20Security%20Installed";
        update_option( $this->log_list, array(
             0 => $this_log ) );
        update_option( $this->settings_field, array( // set defaults
             'advanced_mode' => 0,
             'hard_ban_mode' => 0,
             'email_report' => 1,
             'ban_mode' => 0 
        ) );
        update_option( $this->ip_hash_list, array() );
    }
    function _deactivate() {
        update_option( $this->log_list, "" );
        update_option( $this->settings_field, "" );
        update_option( $this->ip_hash_list, array() );
    }
    /**
     * karo()
     *
     * @return
     */
    
    function karo( $req = '', $t = false, $severity = '', $log_only = false ) {

        # Give a logged in WP Admins a pass only when posting data
        if ( false !== $this->is_wp( false, true ) ) return;
        
        if ( $severity == '' )
            $ban_type = 'Medium';
        $ban_type = $severity;
        
        $req      = ( substr( $req, 0, 2 ) == "/?" ) ? substr( $req, 2 ) : $req;
        $req      = ( substr( $req, 0, 1 ) == "/" ) ? substr( $req, 1 ) : $req;
        # Will only log all requests if in advanced mode, else just Medium severity and above
        if ( false == $this->is_wp() ) {
            if ( false !== $this->logfile_name() )
                $this->_log_file = $this->logfile_name();
            if ( false === $this->logfile_exists() )
                $this->create_fileset();
        }
        
        # create the log entry
        $this->log_request( $req, $ban_type );
        
        # if notification only
        if ( false === $log_only ) return;
        # if IP ban manually disabled
        if ( false === ( bool ) $t ) $this->send403();
        
        # if is IIS server, IP address is server or should not be banned
        if ( false !== $this->is_iis() || false !== $this->is_server( $this->get_ip() ) || false !== $this->_bypassbanip ) $this->send403();
                    
        # Add IP address to htaccess file
        if ( ( ( false !== $this->_adv_mode || false !== ( bool ) $this->_banip ) || false !== $t ) ) $this->htaccessbanip( $this->get_ip() );
        $this->send403();
    }
    function write_log( $req = "" ) {
        $logfile = array();
        $logfile = get_option( $this->log_list );
        array_unshift( $logfile, $req );
        
        $mylogs    = array();
        $log_total = ( ( $l_count = count( $logfile ) ) >= 100 ) ? 99 : $l_count;
        
        for ( $x = 0; ( $x <= $log_total && !empty( $logfile[ $x ] ) ); $x++ ) {
            $mylogs[ $x ] = $logfile[ $x ];
        }
        update_option( $this->log_list, $mylogs );
    }
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
    function log_request( $req, $ban_type ) {
        if ( false !== ( bool ) $this->_adv_mode || ( false === ( bool ) $this->_adv_mode && $ban_type != "Low" ) ) {
            if ( false === $this->is_wp() )
                date_default_timezone_set( 'NZ' );
            
            $trim            = 500;
            $req             = ( strlen( $req ) > $trim ) ? substr( $req, 0, $trim ) . "..." : $req;
            $req             = htmlentities( $req, ( ( version_compare( phpversion(), '5.4', '>=' ) ) ? ENT_HTML5 | ENT_QUOTES : ENT_COMPAT | ENT_HTML401 ), 'UTF-8' );
            $req_orig        = ( strlen( $req ) > 250 ) ? wordwrap( $req, 200, "<br />\n" ) : $req;
            $req             = str_replace( "\\", "&bsol;", $req );
            $this->_timestamp = $this->set_timestamp();
            
            $req             = $this->_timestamp . " " . $ban_type . " " . $this->get_ip() . " " . $_SERVER[ 'REQUEST_METHOD' ] . " " . $this->get_filename() . " " . str_replace( " ", "%20", $req ) . "\n";
            if ( ( 'Medium' == $ban_type || 'High' == $ban_type ) && false !== ( bool ) $this->_email_report ) {
                $text_color = ( 'Medium' == $ban_type  ) ? "#e68735" : "#c72b2c";
                $this->email_log( "\n<tr style=\"background-color: #F3F3F3\">\n" . "    <td style=\"font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;vertical-align:top; width:100px; white-space: nowrap\">" . $this->_timestamp . "</td>\n
                                         <td style=\"vertical-align:top; text-align: center; width:60px; white-space: nowrap; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;font-weight: bold; color:" . $text_color . "\">" . $ban_type . "</td>\n
                                         <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:140px; white-space: nowrap\">" . $this->get_ip() . "</td>\n
                                         <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:50px; white-space: nowrap\">" . $_SERVER[ 'REQUEST_METHOD' ] . "</td>\n
                                         <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;width:100px; white-space: nowrap\">" . $this->get_filename() . "</td>\n
                                         <td style=\"vertical-align:top; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;white-space: nowrap\"><code>" . $req_orig . "</code> [LATEST]</td>\n
                                    </tr>" );
            }
          
            if ( false == $this->is_wp() ) {
                $this->write_log_non_wp( $req, $this->_log_file );
            } else
                $this->write_log( $req );
        }
    }
    function dirfile_perms( $path ) {
        $length = strlen( decoct( fileperms( $path ) ) ) - 3;
        return substr( decoct( fileperms( $path ) ), $length );
    }
    function set_crypto_key_file() {
        $this->_log_file_key = substr( $this->get_uuid(), 0, 32 ) . '_request.key';
    }
    function logfile_name() {
        if ( false !== $this->logfile_exists() ) {
            $key_array = file( PARETO_LOGS . $this->_log_file_key );
        } else
            return false;
        $filename = substr( hash( 'sha256', $key_array[ 0 ], false ), 0, 32 ) . "_request.log";
        return $filename;
    }
    function logfile_cleanup() {
        $filelist = scandir( PARETO_LOGS );
        foreach ( $filelist as $key => $filename ) {
            if ( strlen( $filename ) > 20 && false === $this->cmpstr( $filename, $this->_log_file ) && '_request.log' == substr( $filename, -12, 12 ) ) {
                $logfilename = PARETO_LOGS . $filename;
                if ( false === strpos( $logfilename, 'img' ) )
                    unlink( PARETO_LOGS . $filename );
            }
            if ( strlen( $filename ) > 20 && false === $this->cmpstr( $filename, $this->_log_file_key ) && '_request.key' == substr( $filename, -12, 12 ) ) {
                unlink( PARETO_LOGS . $filename );
            }
        }
    }
    function logfile_exists() {
        return ( bool ) ( file_exists( PARETO_LOGS . ".htaccess" ) || file_exists( PARETO_LOGS . $this->_log_file_key ) );
    }
    function do_bcrypt( $string, $cost = 5 ) {
        $salt  = ( function_exists( 'openssl_random_pseudo_bytes' ) ) ? substr( base64_encode( openssl_random_pseudo_bytes( 17 ) ), 0, 22 ) : substr( strtr( base64_encode( mcrypt_create_iv( 16, MCRYPT_DEV_URANDOM ) ), '+', '.' ), 0, 22 );
        $salt  = str_replace( "+", ".", $salt );
        $param = '$' . implode( '$', array(
             "2y",
            $cost,
            $salt 
        ) );
        
        $output = crypt( $string, $param );
        return $output;
    }
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
    function get_wp_key() {
        $_key_vars = '';
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
                $_key_vars = hash( 'sha256', $const_arg . $_key_vars, false );
        }
        return $_key_vars;
    }
    function get_uuid() {
        $_server_vars = '';
        $server_vars  = array(
             'SERVER_ADMIN',
            'SERVER_ADDR',
            'DOCUMENT_ROOT',
            'HTTP_X_REWRITE_URL',
            'SERVER_SOFTWARE',
            'PATH',
            'SERVER_SOFTWARE' 
        );
        
        $x = 0;
        while ( $x < count( $server_vars ) ) {
            if ( isset( $_SERVER[ $server_vars[ $x ] ] ) )
                $_server_vars = hash( 'sha256', $_SERVER[ $server_vars[ $x ] ] . $_server_vars, false );
            $x++;
        }
        return $_server_vars;
    }
    function updated( $unixtime, $offset ) {
        if ( false !== $this->integ_prop( $offset ) ) {
            if ( $offset > 0 && $offset < 14 ) {
                return $unixtime + ( $offset * 3600 );
            } elseif ( $offset == 0 ) {
                return $unixtime;
            }
        } elseif ( false !== preg_match( "#^(-[0-9]{1,}|[0-9]{1,})$#", $offset ) ) {
            $x = ( int ) str_replace( '-', '', ( string ) $offset );
            return $unixtime - ( $x * 3600 );
        }
    }
    /**
     * injectMatch()
     *
     * @param mixed $string
     * @return
     */
    function injectMatch( $string ) {
        
        $string = $this->url_decoder( strtolower( $string ) );
        
        # these are the triggers to engage the rest of this function.
        $vartrig = "\/\/|\.\.\/|%0d%0a|0x|\ba(?:ll\b|lert\b|scii\()\b|\bb(?:ase64\b|enchmark\b|y\b)|
                    \bc(?:ase\b|har\b|olumn\b|onvert\b|ookie\b|reate\b)|\bd(?:eclare\b|ata\b|ate\b|
                    elete\b|rop\b)|concat|e(?:rror|tc|val|xec|xtractvalue)|f(?:rom|tp)|g(?:rant|roup)|
                    having|\bi(?:f\b|nsert\b|snull\b|nto\b)|j(?:s|json)|l(?:ength\(|oad)|master|onmouse|
                    null|php|\bs(?:chema\b|elect\b|et\b|hell\b|how\b|leep\b)|\btable\b|u(?:nion|pdate|ser|tf)|
                    var|w(?:aitfor|hen|here|hile)";
        $vartrig = preg_replace( "/\s+/i", " ", $vartrig );

        for ( $x = 0; $x <= 9; $x++ ) {
            $this_string = $this->cleanString( $x, $string );
            preg_match_all( "/$vartrig/im", $this_string, $matches1 );
            # second set of tests, string must include at least one of these to trigger
            preg_match_all( "/[$,:;@\#'<>.^*()!\/\[\]\|\+-]|[0-9]/i", $this_string, $matches2 );
        }
        $a = 0;
        $b = 0;
        if ( !empty( $matches1[ 0 ] ) ) $a = count( array_unique( $matches1[ 0 ] ) );
        if ( !empty( $matches2[ 0 ] ) ) $b = count( array_unique( $matches2[ 0 ] ) );

        if ( ( 0 == ( int )$a ) || ( ( int )$b <= 1 ) ) {
            return false; // if either tests are false then we are not interested in this query.
        } else { // else we are very interested in this query.
            $j            = 0;
            # toggle through 6 different filters
            $sqlmatchlist = "(?:abs|ascii|base64|bin|cast|chr|char|charset|collation|concat|
                conv|convert|count|curdate|database|date|decode|diff|distinct|else|
                elt|end|encode|encrypt|extract|field|_file|floor|format|hex|hostname|if|
                inner|insert|instr|interval|join|lcase|left|length|like|load_file|
                locate|lock|log|lower|lpad|ltrim|max|md5|mid|mod|name|now|null|ord|
                password|position|quote|rand|repeat|replace|reverse|right|rlike|round|
                row_count|rpad|rtrim|_set|schema|sha1|sha2|sha3|serverproperty|
                soundex|space|strcmp|substr|substr_index|substring|sum|time|trim|truncate|
                ucase|unhex|upper|_user|user|values|varchar|version|while|ws|xor)|
                _(?:decrypt|encrypt|get|post|server|cookie|global|or|request|xor)|
                (?:column|db|load|not|octet|sql|table|xp)_|@@|_and|absolute|\baction\b|
                \badd\b|\ball\b|allocate|\balter\b|\basc\b|assertion|authorization|avg|base64|
                \bbegin\b|benchmark|between|\bbit\b|bitlength|bit_length|both|bulk|\bcall\b|cascade|
                cascaded|\bcase\b|catalog|char_length|\bcheck\b|\bclose\b|coalesce|collate|commit|
                condition|\bconnect\b|connection|constraint|constraints|contains|continue|
                \bcount\b|corresponding|\bcross\b|\bcurrent\b|current_date|\bdate\b|current_path|
                current_time|current_timestamp|current_user|deallocate|decimal|default|
                deferrable|deferred|\bdesc\b|describe|descriptor|deterministic|diagnostics|
                decode|disconnect|distinct|domain|double|\bdrop\b|dump|elseif|encode|escape|
                except|execute|exists|exit|export|external|exception|false|fetch|first|
                float|\bfor\b|foreign|found|full|function|\bgo\b|goto|grant|handler|having|
                identity|immediate|\bin\b|indicator|informa|initially|inout|input|insensitive|
                int\(|integer|intersect|interval|into|\bis\b|isolation|\bkey\b|language|\blast\b|
                leading|leave|level|limit|local|loop|made by|\bmake\b|match|\bmin\b|minute|
                module|month|nchar|next|not_like|not_regexp|nullif|numeric|octet_length|only|
                \bopen\b|option|\border\b|\bout\b|outfile|outer|output|overlaps|\bpad\b|parameter|
                partial|\bpass\b|path|post|precision|prepare|preserve|primary|prior|\bpriv\b|
                privileges|procedure|read|real|references|regexp|relative|rename|resignal|
                restrict|return|revoke|rollback|routine|rows|server|scroll|second|section|
                session|session_user|\bset\b|\bshell\b|sleep|signal|size|smallint|\bsome\b|
                specific|sqlcode|sqlerror|sqlexception|sqlstate|sqlwarning|system_user|temporary|
                \bto\b|trailing|transaction|translate|translation|timestamp|timezone_hour|
                timezone_minute|true|\bundo\b|unique|unknown|until|update|usage|using|varying|
                view|when|whenever|where|\bwith\b|work|write|\(0x|@@|cast|integer|auto_prepend_file|
                allow_url_include|0x3c62723e";

            $sqlupdatelist    = "\bcolumn\b|\bdata\b|concat\(|\bemail\b|\blogin\b|
                                \bname\b|\bpass\b|sha1|sha2|\btable\b|\bwhere\b|\buser\b|
                                \bval\b|0x|--";
            $sqlfilematchlist = 'access_|access.|\balias\b|apache|\/bin|win.|
                                \bboot\b|config|\benviron\b|error_|error.|\/etc|httpd|
                                _log|\.(?:js|txt|exe|ht|ini|bat|log)|\blib\b|\bproc\b|
                                \bsql\b|tmp|tmp\/sess|\busr\b|\bvar\b|\/(?:uploa|passw)d';

            while ( $j <= 9 ) {
                $this_string = $this->cleanString( $j, $string );

                # First up, REGEX! ( Borrowed from NoScript https://noscript.net/ )
                # Most injection attempts are caught here
                if ( false !== ( bool ) preg_match( "/(?:(?:(?:\b|[^a-z])union[^a-z]|\()[\w\W]*(?:\b|[^a-z])select[^a-z]|(?:updatexml|extractvalue)(?:\b|[^a-z])[\w\W]*\()[\w\W]+(?:(?:0x|x')[0-9a-f]{16}|(?:0b|b')[01]{64}|\(|\|\||\+)/i", $this_string ) ) {
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
                } elseif ( ( $this->substri_count( $this_string, 'var' ) > 1 ) && false !== ( bool ) preg_match( "/date\(|while\(|sleep\(/i", $this_string ) ) {
                    return true;
                    # reflected download attack
                } elseif ( ( substr_count( $this_string, '|' ) > 2 ) && false !== ( bool ) preg_match( "/json/i", $this_string ) ) {
                    return true;
                }
              
                # run through a set of filters to find specific attack vectors on the request string
                $thenode = $this->cleanString( $j, $this->getREQUEST_URI() );
                
                if ( ( false !== ( bool ) preg_match( "/onmouse(?:down|over)/i", $this_string ) ) && ( 2 < ( int ) preg_match_all( "/c(?:path|tthis|t\(this)|http:|(?:forgotte|admi)n|sqlpatch|,,|ftp:|(?:aler|promp)t/i", $thenode, $matches ) ) ) {
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
                if ( ( false !== ( bool ) preg_match( "/\border by\b|\bgroup by\b/i", $this_string ) ) && ( false !== ( bool ) preg_match( "/\bcolumn\b|\bdesc\b|\berror\b|\bfrom\b|hav|\blimit\b|offset|\btable\b|\/|--/i", $this_string ) || ( false !== ( bool ) preg_match( "/\b[0-9]\b/i", $this_string ) ) ) ) {
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
                             $this_matches = array_merge( $matches1, $matches2, $matches3[ 0 ], $matches4[ 0 ] );
                             $this_matches = array_unique( $this_matches );
                             if ( count( $this_matches ) > 3 ) return true;
                } elseif ( ( false !== strpos( $this_string, 'union' ) ) && ( false !== strpos( $this_string, 'select' ) ) && false !== ( bool ) preg_match( "/\bfrom\b|\bnull\b/i", $this_string ) ) {
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
     * datalist()
     *
     * @return
     */
    function datalist( $val, $list = 0 ) {
        $val = $this->cleanString( 9, $val );
        if ( !is_numeric( $val ) && empty( $val ) ) return false;
        # although we try not to do this, arbitrary blacklisting of certain request variables
        # cannot be avoided. however I will attempt to keep this list short.
        $_datalist      = array();
        // Remove whitespace from string
        $val            = preg_replace( "/\s+/i", '', $this->decode_code( str_replace( "'", '', ( $val ) ) ) );
        # _REQUEST[]
        $_datalist[ 1 ] = array(
            "php/login",
            "eval(",
            "base64_",
            "_46esab",
            "@eval",
            "}catch(e",
            "allow_url_",
            "safe_mode",
            "disable_functions",
            "phpinfo(",
            "shell_exec(",
            "open_basedir",
            "auto_prepend_file",
            ")limit",
            "script>",
            "wget",
            "string.fromcharcode",
            "prompt(",
            "onerror=alert(",
            "/var/lib/php",
            "4294967296",
            "get[cmd",
            "><script",
            "\$_request[cmd",
            "cmd.exe",
            "usr/bin/perl",
            "javascript:alert(",
            "php_uname",
            "@@hostname",
            "passthru(",
            "sha1(",
            "sha2(",
            "expect://[",
            "php://",
            "iframesrc=",
            "<iframe",
            "\$_get",
            "ob_start",
            "../cmd",
            "document.",
            "fsockopen",
            "md5(",
            "onload=",
            "mysql_query",
            "window.location",
            "/frameset",
            "location.replace(",
            "()}",
            "@@datadir",
            "_start_",
            "php_self",
            "}if(",
            ":;};",
            "[link=http://",
            "\$_session",
            "\$_request",
            "\$_env",
            "\$_server",
            ";!--=",
            "substr(",
            "\$_post",
            "hex_ent",
            "inurl:",
            "replace(",
            ".php/admin",
            "mosconfig_",
            "<@replace(",
            "=alert(",
            "ki9xsevsrs8q",
            "auto_prepend_file",
            "unhex(",
            "error_reporting(",
            "http_cmd",
            "127.0.0.1:",
            "set-cookie",
            "http/1.",
            "print@@variable",
            "xp_cmdshell",
            "globals[",
            "rush=",
            "sp_password",
            "/etc/",
            "file_get_contents(",
            "*(|(objectclass=|||",
            "../wp-",
            ".htaccess",
            ";echo",
            "system(",
            "set_magic_quotes_runtime",
            "preg_replace",
            "call_user_func(",
            "socket_create",
            "xmlrpc_decode"
        );
        
        # _POST[] 
        $_datalist[ 2 ] = array(
            "eval(",
            "fromcharcode",
            "allow_url_",
            ")*cmd",
            "=cmd|",
            "@eval",
            "concat(",
            "usr/bin/perl",
            "shell_exec(",
            "string.fromcharcode",
            "/etc/passwd",
            "file_get_contents(",
            "fopen(",
            "get[cmd",
            "/bin/cat",
            "passthru(",
            "cpowershelliex",
            "><javas",
            "\$_request[cmd",
            "system(" ,
			"document.cookie.escape",
            "uname-a",
            "phpinfo(",
            "echo`", // using ` is the same as shell_exec
            "php_", // predefined PHP constants
            "default_include_path", // predefined PHP constants
            "pear_", // predefined PHP constants
            "ywxlcnqo", //  base64 alert
            "zxzhbcg=", // base64 eval(
            "znjvbunoyxjdb2rl", // base64 fromCharCode
            "u0vmrunulyoqlw==", // base64 SELECT/**/
        );
        
        # 'User-Agent'
        $_datalist[ 3 ] = array(
            "usr/bin/perl",
            ":;};",
            "system(",
            "base64_",
            "phpinfo(",
            "eval(",
            "getconfig(",
            ".chr(",
            "passthru",
            "shell_exec",
            "popen(",
            "exec(",
            "onerror",
            "wpscan",
            "document.location",
            "jdatabasedrivermysql",
            "\${print"
        );
        
        $_datalist[ 4 ] = array(
            "mozilla",
            "android",
            "windows",
            "chrome",
            "safari",
            "opera",
            "apple",
            "google",
            "whatsapp",
            "facebookexternalhit",
            "wordpress",
            "twitter",
            "msn.com",
            "wp.com",
            "pinterest",
            "netcraftssl",
            "go-http-client",
            "argotic",
            "twingly",
            "reeder",
            "w3m",
            "midori",
            "windows nt",
            "lynx",
            "netsurf",
            "alexa",
            "ia_archiver", // alexa
            "bing",
            "duckduckbot",
            "baiduspider"
        );
        
        if ( false !== strpos( $val, "=" ) || false !== preg_match('%^[a-zA-Z0-9/+]*={0,2}$%', $val ) ) $base_val = strtolower( $this->decode_code( $val, false, true ) );
            $val = $this->decode_code( $val );
            for ( $x = 0; $x < count( $_datalist[ ( int ) $list ] ); $x++ ) {
                $this_item = $this->decode_code( $_datalist[ ( int ) $list ][ $x ] );
                # Test 1: Is Base64
                if ( isset( $base_val ) && false !== stripos( $base_val, $this_item ) ) {
                    return true;
                }
                # Test 2: Hex test
                if ( false !== strpos( strtolower( pack( "H*", preg_replace( "/[^a-f0-9]/i", '', $val ) ) ), $this_item ) ) {
                    return true;
                }
                # Test 3:
                if ( false !== strpos( strtolower( $val ), $this_item ) ) {
                    return true;
                }
            }
            return false;
    }
    function do_blacklists( $input ) {
        if ( false !== ( bool ) $this->datalist( $input, 1 ) ) $this->karo( "Blacklisted Request: " . $input, true, 'High', true );
        if ( false !== $this->injectMatch( $input ) ) $this->karo( "DB Inject: " . $input, true, 'High', true );
    }
    /**
     * _REQUEST_Shield()
     *
     * @return
     */
    function _REQUEST_SHIELD() {
        # Often part of a preemptive strike package
        if ( 'wp-links-opml.php' == $this->get_filename() ) {
            # only for a logged in administrator
            if ( false === $this->is_wp( false, true ) )
                $this->karo( "WPScan: non-admin call to wp-links-opml.php", ( ( false !== ( bool ) $this->_hard_ban_mode ) ? ( bool ) $this->_banip : false ), 'Medium', true );
        }
        
        # if empty then the rest of no interest to us
        if ( false !== empty( $_REQUEST ) )
            return;
        $_get_server = $_SERVER;
        $_get_post   = $_POST;
        
        # specific attacks that do not necessarily
        # involve query_string manipulation
        $req = strtolower( $this->url_decoder( $this->getREQUEST_URI() ) );
        # Apache Struts2 Remote Code Execution
        preg_match_all( "/redirect|context|opensymphony|dispatcher|httpservletresponse|flush\(|getwriter/i", $req, $matches );
        if ( is_array( $matches[ 0 ] ) && ( count( $matches[ 0 ] ) > 4 ) ) {
            $match_count = ( $m = count( $matches[ 0 ] ) > 4 ) ? 4 : $m;
            for ( $x = 0; $x <= $match_count; $x++ ) {
                $results .= ( !is_array( $matches[ 0 ][ $x ] ) ) ? $matches[ 0 ][ $x ] . ' ' : '';
            }
            $this->karo( "Apache Struts2 RCE: " . $results, true, 'High', true );
        }
        
        # Reflected File Download Attack
        if ( false !== ( bool ) preg_match( "/\.(?:bat|cmd|ini|htac|htpa|passwd)/i", $req ) )
            $this->karo( "Reflected File Download: " . $req, true, 'High', true );
        
        # osCommerce / Magento specific exploit
        if ( false !== strpos( $req, '.php/admin' ) )
            $this->karo( "osCommerce / Magento Exploit: " . $req, true, 'High', true );
        
        # Null byte
        if ( false !== strpos( $req, '\0' ) ) $this->karo( "Null byte: " . $req, true, 'High', true );
        
        # prevent arbitrary file includes/uploads
        if ( false !== ( bool ) @ini_get( 'allow_url_include' ) ) {
            if ( false !== ( bool ) $this->instr_url( $req, false ) ) {
                preg_match( "/(?:http:|https:|ftp:|file:|php:)/i", $req, $matches );
                if ( false === stripos( $req, $this->get_http_host() ) && count( $matches[ 0 ] ) == 1 ) {
                    $this->karo( "RFI: " . $req, true, 'High', true );
                } elseif ( false !== stripos( $req, $this->get_http_host() ) && count( $matches[ 0 ] ) > 1 ) {
                    $this->karo( "RFI: " . $req, true, 'High', true );
                }
            }
        }
        
        # prevent command injection
        if ( false !== in_array( "'cmd'", $this->_get_all ) || false !== in_array( "'system'", $this->_get_all ) )
            $this->karo( "CMD Inject: " . $req, true, 'High', true );
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
        # _POST
        if ( false !== $this->cmpstr( 'POST', $_get_server[ 'REQUEST_METHOD' ] ) && false === empty( $_get_post ) ) {
            # while we're checking _POST, prevent attempts to esculate user privileges in WP
            if ( ( false !== function_exists( 'is_admin' ) && false === is_admin() ) && false !== $this->cmpstr( 'admin-ajax.php', $this->get_filename() ) && ( false !== in_array( 'default_role', $_get_post ) && false !== $this->cmpstr( 'administrator', $_get_post[ 'default_role' ] ) ) )
                $this->karo( "Privalege Esculation: " . $req, true, 'High', true );
            
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
                        require_once ABSPATH . WPINC . '/pluggable.php';
                        wp_safe_redirect( get_bloginfo( 'url' ) );
                        exit;
                    } else {
                        header( "Location: " . $this->getURL() );
                        exit();
                    }
                }
            }
        }
        # WP Author Discovery
        if ( false !== strpos( $req, '?author=' ) ) {
            $this->karo( "Author Discovery: " . $req, true, 'Medium', true );
        }
        
        # WP DoS Mitigation CVE-2018-6389
        
        # In order for this to work you need to add the following code to wp-admin/load-script.php 
        # if ( false !== strpos( $_SERVER[ 'SCRIPT_NAME' ], 'load-scripts.php' ) ) require( ABSPATH . 'wp-admin/admin.php' );
        # and in wp-admin/load-styles.php
        # if ( false !== strpos( $_SERVER[ 'SCRIPT_NAME' ], 'load-styles.php' ) ) require( ABSPATH . 'wp-admin/admin.php' );
        if ( false !== $this->cmpstr( $this->get_filename(), 'wp-login.php' ) ) define( 'CONCATENATE_SCRIPTS', false );
        if ( isset( $_REQUEST[ 'load' ] ) ) {
            $query_len = strlen( $_REQUEST[ 'load' ][ 0 ] );
            if ( $query_len > 1000 )
                $this->karo( "CVE-2018-6389 DoS Attack: Query Length = " . $query_len, true, 'High', true );
        }
      
        # this occurence of these many slashes etc are always an attack attempt
        if ( ( substr_count( $req, '/' ) > 20 ) || ( substr_count( $req, '\\' ) > 20 ) || ( substr_count( $req, '|' ) > 20 ) ) {
            $this->karo( "Irregular Request: " . $req, false, 'Low', true );
        }
        # finally run the black lists one more time
        $this->do_blacklists( $this->getQUERY_STRING() );
    }
    /**
     * get_filter()
     *
     * @return
     */
    function querystring_filter( $val, $key ) {
        $this->_get_all[] = $this->decode_code( $key, true );
        if ( false !== ( bool ) $this->string_prop( $val, 1 ) ) {
            $val = $this->decode_code( $val );
            if ( false !== ( bool ) $this->datalist( $val, 1 ) )
                $this->karo( "Blacklisted Req: " . $key . " = " . $val, true, 'High', true );
            if ( false !== $this->injectMatch( $val ) )
                $this->karo( "DB Inject: " . $key . "=" . $val, true, 'High', true );
        }
    }
    /**
     * _QUERYSTRING_SHIELD()
     *
     * @return
     */
    function _QUERYSTRING_SHIELD() {
        if ( false !== empty( $_REQUEST ) || false === $this->cmpstr( 'GET', $_SERVER[ 'REQUEST_METHOD' ] ) || false === ( bool ) $this->string_prop( $this->getQUERY_STRING(), 1 ) ) {
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
     * post_filter()
     *
     * @return
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
                $this->karo( "Shell Inject: " . $val, true, 'High', true );
            }
        }
        $matches = array();
        # Satori Botnet
        preg_match_all( "/wget http|:\/\/|->|tmp\/r|-O|;sh/i", $val, $matches );
        if ( is_array( $matches[ 0 ] ) ) {
            $match_list = array_unique( $matches[ 0 ] );
            if ( count( $match_list ) == 6 ) {
                $val = $this->cleanString( 6, $this->remove_comments( $val ) );
                $this->karo( "Satori Botnet :: " . $val, true, 'High', true );
            }
        } 
        preg_match_all( "/php|echo|base64|system\(|\_GET|cmd/i", $val, $matches );
        if ( is_array( $matches[ 0 ] ) ) {
            $match_list = array_unique( $matches[ 0 ] );
            if ( count( $match_list ) > 5 ) {
                $s   = strpos( $val, $match_list[ 0 ] );
                $f   = strlen( $val ) - $s;
                $val = substr( $val, $s, $f );
                $val = preg_replace( "/[\s\t\n\r\0\x08\x0B]/i", "", $this->remove_comments( $val ) );
                $this->karo( "Shell Inject: " . $val, true, 'High', true );
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
                    $this->karo( "Shell Inject: " . $filtval, true, 'High', true );
                }
            }
            $matches = array();
            
            preg_match_all( "/@eval|\_magic\_quotes\_gpc|stripslashes|\_post\[chr\(/i", $filtval, $matches );
            if ( is_array( $matches[ 0 ] ) ) {
                $match_list = array_unique( $matches[ 0 ] );
                if ( count( $match_list ) == 4 ) {
                    $val = $this->cleanString( 6, $this->remove_comments( $val ) );
                    $this->karo( "Malicious Data Exfiltrations Attempt :: " . $val, true, 'High', true );
                }
            }            
        }
        $matches = array();
        
        preg_match_all( "/\_server|ini\_set|\_magic\_quotes\_runtime\(0|php\_uname|php\_self|print|die|posix\_/i", strtolower( $val ), $matches );
        if ( count( array_unique( $matches[ 0 ] ) ) > 4 ) {
                $val = $this->cleanString( 6, $this->remove_comments( $val ) );
                $this->karo( "Malicious Data Exfiltrations Attempt :: " . $val, true, 'High', true );
        }
        $matches = array();
        
        preg_match_all( "/(?:script|type|text|javascript|http|pastebin)/i", $val, $matches );
        if ( count( array_unique( $matches[ 0 ] ) ) == 6 )
                $this->karo( "Malware Inject: Attempt to inject malware via Pastebin", true, 'High', true );
               
        # Load the keys into an array
        $this->_post_all[] = strtolower( $this->decode_code( $key, true ) );
        
        # Finally, the blacklist
        if ( false !== $this->datalist( $this->decode_code( $val ), 2 ) ) {
                $this->karo( "Blacklisted _POST Request: " . $val, true, 'High', true );
        }
    }
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
     * _POST_SHIELD()
     */
    function _POST_SHIELD() {
        if ( false === $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ] ) )
            return; // of no interest to us
        # _POST content-length should be longer than 0
        if ( ( false !== ( bool ) $this->_adv_mode || false !== ( bool ) $this->_post_filter_mode ) ) {
            if ( count( $_POST, COUNT_RECURSIVE ) >= 10000 )
                $this->karo( "_POST DoS Attack", ( bool ) $this->_banip, 'High', true ); // very likely a denial of service attack
        }
        array_walk_recursive( $_POST, array(
             $this,
            'post_filter' 
        ) );
        if ( 'xmlrpc.php' == $this->get_filename() ) {
            if ( false !== ( bool ) $this->_hard_ban_mode && isset( $HTTP_RAW_POST_DATA ) ) {
                # deal with this dangerous global
                if ( is_string( $HTTP_RAW_POST_DATA ) && false !== $this->datalist( $this->decode_code( $HTTP_RAW_POST_DATA ), 2 ) ) $this->karo( "HTTP_RAW_POST_DATA contains attack code", true, 'High', true );
                # check it is the correct XML format
                preg_match_all( "/methodCall|methodName|params|string|value|<|>/i", $HTTP_RAW_POST_DATA, $matches );
                $matches = array_unique( $matches[ 0 ] );
                if ( false !== is_string( $HTTP_RAW_POST_DATA ) && ( 7 > count( $matches ) ) ) {
                    # content is not XML
                    $this->karo( "HTTP_RAW_POST_DATA: Not valid XML", false, "Low", true );
                }
            }
            if ( defined( 'XMLRPC_REQUEST' ) ) {
                    add_filter( 'authenticate', array( $this, 'xml_rpc_auth'), 20, 3 );
            }
        }
    }
    /**
     * _LOGIN_SHIELD()
     *
     */
    function _LOGIN_SHIELD( $username = "" ) {
        
        if ( false !== $this->is_wp() && ( false !== ( bool ) $this->options[ 'advanced_mode' ] || false !== ( bool ) $this->_adv_mode ) ) {

            if ( false !== $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ] ) ) {
                if ( ( isset( $_POST[ 'log' ] ) && isset( $_POST[ 'pwd' ] ) ) || ( strlen( $username ) > 0 ) ) {
                    $this_user = $_POST[ 'log' ];
                    if ( false === $this->check_usernames( $this_user, false ) ) {
                        $this->flood_check( $this->get_ip(), $this_user );
                        return;
                    }
                    return;
                }
            }
        }
        return;
    }
   function check_usernames( $this_user, $ip = false ) {
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
        $ip_array = get_option( $this->ip_hash_list );
        $key = sha1( $this->get_ip() );
        if ( false !== ( bool ) $ip ) {
            unset( $ip_array[ $key ] );
            update_option( $this->ip_hash_list, $ip_array );
            return true;
        } else {
            if ( in_array( $this_user, $get_users ) ) {
                 if ( false !== array_key_exists( $key, $ip_array ) ) unset( $ip_array[ $key ] );
                 return true;
            } else
                return false;
        }
        return false;
    }
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
             $this->flood_check( $this->get_ip(), $username, 5, 5 );
        } else {
            $correct = $this->check_usernames( $username, true );
            $this->_spider_bypass = true;
        }
        return $user;
    }
    function iphash_db_cleanup() {
        $time_now = time();
        $ip_array = get_option( $this->ip_hash_list );
        if ( empty( $ip_array ) ) return;
        foreach( $ip_array as $key => $val ) {
            $this_timestamp = ( int ) $ip_array[ $key ][ 1 ];
            $n = ( int ) $ip_array[ $key ][ 0 ];
            if ( $n > ( int ) $this->_hard_ban_count ) {
                # if time lapsed is greater than 7 days
                if ( ( $time_now < $this_timestamp ) > ( ( ( int ) $this->_ban_time / 24 ) * 168 ) ) {
                    unset( $ip_array[ $key ] );
                } else {
                # if count higher than threshold, htaccess is not working
                # so leave hash in db
                continue;
                }
            }
            # if timestamp is older than $this->_ban_time then remove entry
            if ( ( $time_now - ( int ) $this->_ban_time ) > $this_timestamp ) unset( $ip_array[ $key ] );
            unset( $ip_array[ $key ] );
        }
        update_option( $this->ip_hash_list, $ip_array );
        return;
    }
    function flood_check( $ip, $uname='', $threshold = 5, $hard_ban = 20 ) {
         $iphash = sha1( $ip ); // hash the ip
         $time_now = time();
         $dos = false;
         $ban = false;
         if ( $hard_ban <> $this->_hard_ban_count ) $this->_hard_ban_count = $hard_ban;
         $ip_array = get_option( $this->ip_hash_list );
          if ( false !== array_key_exists( $iphash, $ip_array ) ) { // check hash in database
              $current_count = ( int ) $ip_array[ $iphash ][ 0 ];
              $time_stamp = ( int ) $ip_array[ $iphash ][ 1 ];
              # if 24 hours hasn't lapsed
              if ( ( $time_now - $this->_ban_time ) < $time_stamp ) {
                # if threshold passed then return 403
                if ( $current_count >= $threshold ) {
                     # repeat failed login, restart timestap
                     # if $current_count > $this->_hard_ban_count within 24 hours
                     # permanent IP ban
                     if ( $current_count >= $this->_hard_ban_count ) {
                        # this is a password flood attack
                        # ban to htaccess and 403
                        $dos = true;
                     } else {
                        # return 403
                        $ban = true;
                     }
                }
                $ip_array[ $iphash ][ 0 ] = $current_count + 1;
             } else {
               # 24 hours has lapsed so start the count again
               $ip_array[ $iphash ] = array( 0 => 1, 1 => $time_now );
             }
         } else {
            # add this entry to DB
            $ip_array[ $iphash ] = array( 0 => 1, 1 => $time_now );
         }

         # update the DB
         update_option( $this->ip_hash_list, $ip_array );
         # finally, deal with thresholds
         # this will lighten the load on a busy server
         if ( false !== $dos ) {
                $this->karo( 'Denial of Service Attack ' . $this->_hard_ban_count . ' or more incorrect XMLRPC login attempts', true, 'High', true );
         }
         if ( false !== $ban ) {
            $this->karo( 'Unregistered Username: ' . esc_html( $uname ), false, "Low", true );
         }
    }
    /**
     * _HTTPHOST_SHIELD()
     *
     */
    function _HTTPHOST_SHIELD() {
        # short $_SERVER[ 'SERVER_NAME' ] can indicate server hack
        # see http://bit.ly/1UeGu0W
        if ( false === $this->string_prop( $this->get_http_host(), 3 ) ) $this->karo( "HOST ERROR: " . $this->get_http_host(), false, "Low", true );
        
        if ( isset( $_SERVER[ 'HTTP_HOST' ] ) ) {
            
            if ( false !== $this->injectMatch( $_SERVER[ 'HTTP_HOST' ] ) ) $this->karo( "HOST Inject: " . $_SERVER[ 'HTTP_HOST' ], ( bool ) $this->_banip, 'High', true );
            
            # low level sanitise the host
            $http_host = $this->host_check( strtolower( $_SERVER[ 'HTTP_HOST' ] ) );
            
            # Wordpress Host Check    
            if ( false !== $this->is_wp() ) {
                if ( false !== ( bool ) $this->_adv_mode ) {
                    # WP RCE HOST Attack
                    preg_match_all( "/xenial|directory|usr|spool|run/i", $http_host, $matches );
                    if ( is_array( $matches[ 0 ] ) ) {
                        $match_list = array_unique( $matches[ 0 ] );
                        if ( count( $match_list ) > 3 )
                            $this->karo( "WP RCE HOST Attack: " . $http_host, ( bool ) $this->_banip, 'High', true );
                    }
                }
            }
        }
    }
    /**
     * cookie_filter()
     *
     * @return
     */
    function cookie_filter( $val, $key ) {
        
        if ( false !== ( bool ) $this->datalist( $this->decode_code( $key ), 1 ) || false !== ( bool ) $this->datalist( $this->decode_code( $val ), 1 ) ) {
            $this->karo( "Cookie: " . $key . "=" . $val, true, 'High', true );
        }
        if ( false !== ( bool ) $this->injectMatch( $key ) || false !== ( bool ) $this->injectMatch( $val ) ) {
            $this->karo( "Cookie Inject: " . $key . "=" . $val, true, 'High', true );
        }
    }
    /**
     * _COOKIE_SHIELD()
     *
     * @return
     */
    function _COOKIE_SHIELD() {
        if ( false !== empty( $_COOKIE ) )
            return; // of no interest to us
        array_walk_recursive( $_COOKIE, array(
             $this,
            'cookie_filter' 
        ) );
    }
    /**
     * _SPIDER_SHIELD()
     * Basic whitelist
     * Bad Spider Block / UA filter
     */
    function _SPIDER_SHIELD() {
        $val = strtolower( $this->decode_code( $_SERVER[ 'HTTP_USER_AGENT' ], true ) );
        if ( false !== ( bool ) $this->string_prop( $val, 1 ) ) {
            # Shellshock
            preg_match_all( "/echo|\(\)|\;\}\;|\/bin\/bash|-c|uname|-i|>|md5sum/i", $val, $matches );
            if ( is_array( $matches[ 0 ] ) ) {
                $match_list = array_unique( $matches[ 0 ] );
                if ( count( $match_list ) > 4 ) {
                    $s   = strpos( $val, $match_list[ 0 ] );
                    $f   = strlen( $val ) - $s;
                    $val = substr( $val, $s, $f );
                    $this->karo( "USER-AGENT (Shellshock): " . $val, true, 'High', true );
                }
            }
            # mandatory filtering
            if ( false !== $this->injectMatch( $val ) ) {
                $this->karo( "USER-AGENT Injection: " . $val, true, 'High', true );
            }
            if ( false !== ( bool ) $this->datalist( $val, 3 ) ) {
                $this->karo( "Blacklisted USER-AGENT Item: " . $val, ( ( false !== ( bool ) $this->_hard_ban_mode ) ? ( bool ) $this->_banip : false ), 'Medium', true );
            }
            # Only if in Advanced Mode and non-authenitcated
            # xml-rpc
            if ( false === $this->_spider_bypass ) {
                if ( false !== ( bool ) $this->_adv_mode ) {
                    # Disable this in wp-admin (disable advanced mode) if you want bots to crawl your website
                    if ( false === $this->cmpstr( $val, "''" ) && false === ( bool ) $this->datalist( $val, 4 ) ) {
                        if ( false === $this->is_server( $this->get_ip() ) && ( bool ) false !== $this->_banip ) {
                            $this->karo( ( ( false !== ( bool ) $this->_hard_ban_mode ) ? "Banned" : "Blocked" ) . " Crawler/USER-AGENT: " . $val, ( ( false !== ( bool ) $this->_hard_ban_mode ) ? ( bool ) $this->_banip : false ), "Low", true );
                        }
                    } else return;
                }
            }
        }
    }
    function filter_domain( $domain_list, $with_qs = true ) {
        $url_host = parse_url( $domain_list, PHP_URL_HOST );
        if ( empty( $url_host ) ) $domain = "https://" . $domain_list;
        $domain = strtolower( $domain );
        if ( false === $with_qs ) $domain = substr( $domain_list, strpos( $domain_list, $domain ) );
        return $domain;
    }
    function remove_ports( $host ) {
        $url_parts =  parse_url( $host );
        if ( isset( $url_parts[ 'host' ] ) && strlen( $url_parts[ 'host' ] ) > 4 && isset( $url_parts[ 'port' ] ) && strlen( $url_parts[ 'port' ] ) > 0 ) {
            return $url_parts[ 'host' ];
        } else return $host;
    }
    function fix_hosts( $host_array ) {
        $updated_host = array();
        if ( !is_array( $host_array ) ) {
           return preg_replace( "/https|http|:\/\//i", "", $this->remove_ports( $host_array ) );
        }
        for ( $x = 0; $x < count( $host_array ); $x++ ) {
                $a = $host_array[ $x ];
                $a = str_replace( 'https://', '', $a );
                $a = str_replace( 'http://', '', $a );
                if ( strlen( $a ) == 4 && $a == 'www.' ) $a = '';
                $updated_host[ $x ] = $this->remove_ports( $a );
        }
        return array_unique( $updated_host );
    }    
    function host_check( $domain_list ) {
        $checked_list = '';
        $checked_list = array();
        if ( is_array( $domain_list ) ) {
            for ( $x = 0; $x < count( $domain_list ); $x++ ) {
                    $y = $domain_list[ $x ];
                    if ( false !== filter_var( $y, FILTER_SANITIZE_URL ) ) $y = filter_var( $y, FILTER_SANITIZE_URL );
                    if ( false !== $this->check_ip( $y ) ) $y = filter_var( $y, FILTER_VALIDATE_IP );
            }
        }
         $domain_list = $this->fix_hosts( $domain_list );
         if ( is_array( $domain_list ) ) {
            return implode( "\n", $domain_list );
         } else return $domain_list;
    }
    /**
     * instr_url()
     * 
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
     * checkfilename()
     *
     * @param mixed $fname
     * @return
     */
    function checkfilename( $fname ) {
        if ( false === empty( $fname ) && ( $this->substri_count( $fname, '.php' ) == 1 && false !== $this->cmpstr( '.php', substr( $fname, -4 ) ) ) ) {
            return true;
        } else
            return false;
    }
    
    /**
     * get_filename()
     *
     * @return
     */
    function get_filename() {
        $filename    = '';
        $_get_server = $_SERVER;
        $filename    = ( ( ( strlen( @ini_get( 'cgi.fix_pathinfo' ) ) > 0 ) && ( false === ( bool ) @ini_get( 'cgi.fix_pathinfo' ) ) ) || ( false === isset( $_get_server[ 'SCRIPT_FILENAME' ] ) && isset( $_get_server[ 'PHP_SELF' ] ) && false !== $this->string_prop( basename( $_get_server[ 'PHP_SELF' ] ), 1 ) ) ) ? basename( $_get_server[ 'PHP_SELF' ] ) : basename( realpath( $_get_server[ 'SCRIPT_FILENAME' ] ) );
        preg_match( "@[a-z0-9_-]+\.php@i", $filename, $matches );
        if ( is_array( $matches ) && array_key_exists( 0, $matches ) && false !== $this->cmpstr( '.php', substr( $matches[ 0 ], -4, 4 ) ) && ( false !== $this->checkfilename( $matches[ 0 ] ) ) && ( $this->get_file_perms( $matches[ 0 ], true ) ) ) {
            $filename = $matches[ 0 ];
        }
        return $filename;
    }
    
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
            default:
                return $s;
        }
    }
    /**
     * htaccessbanip()
     *
     * @param mixed $banip
     * @return
     */
    function htaccessbanip( $banip ) {

        # if IP is empty or too short, or .htaccess is not read/write
        if ( false !== empty( $banip ) || ( strlen( $banip ) < 7 ) || ( false === $this->htapath() ) ) {
            return $this->karo( "", false, "Low", true );
        } else {
            $thisdomain = preg_replace( "/www\.|https:\/\/|http:\/\/|:\/\/|[^a-zA-Z0-9\.]+/i", "", $this->get_http_host() );
            $limitend   = "# End of " . $thisdomain . " Pareto Security Ban\n";
            $newline    = "deny from $banip\n";
            $mybans     = file( $this->htapath() );
            $lastline   = "";
            if ( in_array( $newline, $mybans ) )
                exit();
            if ( in_array( $limitend, $mybans ) ) {
                $i = count( $mybans ) - 1;
                while ( $mybans[ $i ] != $limitend ) {
                    $lastline = array_pop( $mybans ) . $lastline;
                    $i--;
                }
                $lastline = array_pop( $mybans ) . $lastline;
                $lastline = array_pop( $mybans ) . $lastline;
                array_push( $mybans, $newline, $lastline );
            } else {
                array_push( $mybans, "\r\n# " . $thisdomain . " Pareto Security Ban\n", "order allow,deny\n", $newline, "allow from all\n", $limitend );
            }
            $orig_octal = $this->dirfile_perms( $this->htapath() );
            if ( false === $this->get_file_perms( $this->htapath(), true, true ) ) {
                chmod( $this->htapath(), 0666 );
            }
            $myfile = fopen( $this->htapath(), 'w' );
            fwrite( $myfile, implode( $mybans, '' ) );
            fclose( $myfile );
        }
    }
    /**
     * htaccessbanip()
     *
     * @param mixed $banip
     * @return
     */
    function htaccess_unbanip() {
        $thisdomain = preg_replace( "/www\.|https:\/\/|http:\/\/|:\/\/|[^a-zA-Z0-9\.]+/i", "", $this->get_http_host() );
        $limitstart = "# " . $thisdomain . " Pareto Security Ban\n";
        $limitend   = "# End of " . $thisdomain . " Pareto Security Ban\n";
        $mybans     = file( $this->htapath() );
        if ( in_array( $limitend, $mybans ) ) {
            $i = count( $mybans ) - 1;
            while ( $mybans[ $i ] >= 0 ) {
                if ( false !== strpos( $mybans[ $i ], $limitend ) ) {
                    $lastline = $i;
                    break;
                }
                $i--;
            }
            $i = 0;
            while ( $mybans[ $i ] >= 0 ) {
                if ( false !== strpos( $mybans[ $i ], $limitstart ) ) {
                    $firstline = $i;
                    break;
                }
                $i++;
            }
            $mybans_tmp     = array_slice( $mybans, 0, $firstline );
            $mybans_end_tmp = array_slice( $mybans, $lastline + 1, count( $mybans ) );
            $mybans         = empty( $mybans_end_tmp ) ? $mybans_tmp : array_merge( $mybans_tmp, $mybans_end_tmp );
        }
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
     * get_file_perms()
     *
     * @return boolean
     */
    function get_file_perms( $f = NULL, $r = false, $w = false ) {
        # if file exists return bool
        # if file exists & readable return bool
        # if file exists, readable & writable return bool
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
    /**
     * get_http_host()
     *
     * @return
     */
    function get_http_host( $withhttp = false, $encoding = 'UTF-8' ) {
        $is_ip = false;
        $final_sname = "";
        if ( false !== getenv( 'SERVER_NAME' ) && ( false !== ( bool ) $this->string_prop( getenv( 'SERVER_NAME' ), 2 ) ) ) {
            $servername = getenv( 'SERVER_NAME' );
        } else {
            $servername = $_SERVER[ 'SERVER_NAME' ];
        }

        // check if server name is an IP address
        if ( function_exists( 'filter_var' ) && defined( 'FILTER_VALIDATE_IP' ) && ( false !== filter_var( $servername, FILTER_VALIDATE_IP ) ) && false !== $this->check_ip( $servername ) ) {
            // is an ip address
            $server_ip = $servername;
            # is the servers IP address
            $is_ip = true;
            # the SERVER_NAME is an IP so check it against SERVER_ADDR
            if ( false === $this->is_server( $server_ip ) ) {
                $this->karo( $server_ip . " :: Incorrect Server IP - Should be " . $_SERVER[ 'SERVER_ADDR' ], false, 'Low', true );
            }
        }
        
        if ( false === $is_ip ) {
            $final_sname = htmlspecialchars( $servername, ( ( version_compare( phpversion(), '5.4', '>=' ) ) ? ENT_HTML5 : ENT_QUOTES ), $encoding );
            $final_sname = filter_var( $final_sname, FILTER_SANITIZE_URL );
            if ( false === $final_sname ) $this->karo( $final_sname . " :: Failed Filter Test", false, 'Low', true );
            $final_sname = $final_sname;
        } else $final_sname = $servername; // is an IP address
        # Check http_host against the safe list
        if ( isset( $this->options[ 'safe_list' ] ) && !empty( $this->options[ 'safe_list' ] ) ) {
            $this->_server_names = $this->host_check( $this->options[ 'safe_list' ] );
            if ( !is_array( $this->_server_names ) ) {
                if ( false !== strpos( $this->_server_names, "\n" ) ) {
                    $this->_server_names = explode( "\n", $this->_server_names );
                } else $this->_server_names[ 0 ] = $this->_server_names;
            }
            if ( is_array( $this->_server_names ) ) {
                if ( false !== in_array( $final_sname, $this->_server_names ) ) {
                    if ( false !== $this->check_ip( $final_sname ) ) {
                        # is an ip address
                        if ( false !== $this->is_server( $final_sname ) ) {
                            # is IP and is server IP
                            $this->karo( "Notice: HTTP-HOST is server IP address " . $final_sname, false, 'Safe', false );
                        } else {
                            $this->karo( "Notice: HTTP-HOST: " . $http_host . " is not the server IP address - " . $_SERVER[ 'SERVER_ADDR' ], false, 'Safe', false );
                        }
                    }
                } else {
                    # grab the domain name from the safe list
                    foreach( $this->_server_names as $names ) {
                        if ( false === $this->check_ip( $names ) ) {
                            if ( false === filter_var( $names, FILTER_SANITIZE_URL ) ) {
                                 continue;
                            } else {
                                $final_sname = filter_var( $names, FILTER_SANITIZE_URL );
                                break;
                            }
                        }
                    }
                }
            } else
                $final_sname = $this->_server_names;
        }     
        $final_sname = $this->cleanString( 9, $final_sname );
        # filter domain names
        $http       = ( false !== $withhttp ) ? ( ( ( array_key_exists( 'HTTPS', $_SERVER ) && "on" == @$_SERVER[ "HTTPS" ] ) || ( array_key_exists( 'HTTPS', getenv() ) && "on" == getenv( "HTTPS" ) ) ) ? 'https://' : 'http://' ) : '';
        return $http . $final_sname;
    }
    function getURL( $withhttp = true ) {
        $pre_req = strtolower( $this->url_decoder( $this->getREQUEST_URI() ) );
        $q = ( bool ) isset( $_SERVER[ 'QUERY_STRING' ] );
        $is_q = ( bool ) strpos( $pre_req, "?" );
        $query     = ( false !== $is_q ) ? "?" . $_SERVER[ 'QUERY_STRING' ] : "";
        $req     = ( false !== $is_q ) ? $this->decode_code( substr( $pre_req, 0, strpos( $pre_req, '?' ) ) ) : $pre_req;
        $this->do_blacklists( $req );
        $locale  = ( ( false !== $withhttp ) ? $this->get_http_host( true ) : $this->get_http_host( false ) ) . $req . $query;
        $locale  = $this->cleanString( 9, $locale );
        return $locale;
    }
    /**
     * get_dir()
     *
     * @return
     */
    function get_dir() {
        $get_root                       = '';
        $_get_server                    = $_SERVER;
        $_get_server[ 'DOCUMENT_ROOT' ] = '';
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
            $get_root                   = realpath( $f );
            $_SERVER[ 'DOCUMENT_ROOT' ] = $get_root;
        } else {
            $get_root = realpath( $_get_server[ 'DOCUMENT_ROOT' ] ) . PHP_EOL;
        }
        if ( strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN' ) {
            $get_root = str_replace( '/', '\\', $get_root );
        } else
            $get_root = str_replace( '\\', '/', $get_root );
        return $get_root;
    }
    /**
     * is_server()
     * @return bool
     */
    function is_server( $ip = '', $localhost = true ) {
        # tests if ip address reported as _SERVER[ 'SERVER_ADDR' ]
        # is either server ip ( localhost access ) or is 127.0.0.1
        # ( i.e onion visitors )
        
        if ( strlen( $ip ) == 0 ) $ip = $this->get_ip();
        if ( false !== $this->cmpstr( $ip, $_SERVER[ 'SERVER_ADDR' ] ) ) {
            return true;
        } elseif ( ( false !== $localhost ) &&  '127.0.0.' == substr( $ip, 0, 8 ) ) {    
            return true;
        }
        return false;
    }
    
    /**
     * $this->check_ip()
     *
     * @param mixed $ip
     * @return
     */
    function check_ip( $ip ) {
        $check = false;
        if ( function_exists( 'filter_var' ) && defined( 'FILTER_VALIDATE_IP' ) && defined( 'FILTER_FLAG_IPV4' ) && defined( 'FILTER_FLAG_IPV6' ) ) {
            if ( false === ( bool ) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 || FILTER_FLAG_IPV6 ) ) {
                return false;
            }
            if ( false !== $this->is_server( $ip ) ) {
                $this->_bypassbanip = true;
            }
            return true;
        } else
            return false;
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
                                'HTTP_X_Forwarded_For' 
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
    function setOpenBaseDir() {
        if ( false === ( bool ) $this->_open_basedir )
            return;
        if ( strlen( @ini_get( 'open_basedir' ) == 0 ) ) {
            return @ini_set( 'open_basedir', $this->get_dir() );
        }
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
            array_push( $header, "X-powered-by: Pareto Security - https://hokioisecurity.com" );
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
    /**
     * getREQUEST_URI()
     */
    function getREQUEST_URI() {
        if ( false !== getenv( 'REQUEST_URI' ) && ( false !== ( bool ) $this->string_prop( getenv( 'REQUEST_URI' ), 2 ) ) ) {
            return getenv( 'REQUEST_URI' );
        } else {
            return $_SERVER[ 'REQUEST_URI' ];
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
        } else {
            return strtolower( $this->decode_code( $_SERVER[ 'QUERY_STRING' ] ) );
        }
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
        if ( false !== ( strval( $integ ) == strval( intval( $integ ) ) ) && ( false !== filter_var( $integ, FILTER_VALIDATE_INT ) ) && ( false !== ctype_digit( strval( $integ ) ) ) && ( false !== preg_match( '/^\d+$/', $integ ) ) && ( $integ == 0 || false === empty( $integ ) ) && ( false !== is_int( $integ ) ) && ( false === is_float( $integ ) ) ) {
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
        if ( $this->is_wp() ) {
            include_once( ABSPATH . 'wp-admin/includes/file.php' );
            $dir_path = get_home_path();
            return $dir_path . '.htaccess';
        }
        $rpath_arr = explode( DIRECTORY_SEPARATOR, $this->get_dir() );
        # we don't want to test back too far.
        $x         = 0;
        $root_path = NULL;
        While ( false === $this->cmpstr( get_current_user(), $rpath_arr[ count( $rpath_arr ) - 1 ] ) ) {
            $root_path = str_replace( "//", "/", implode( DIRECTORY_SEPARATOR, $rpath_arr ) . DIRECTORY_SEPARATOR . '.htaccess' );
            if ( false !== $this->get_file_perms( $root_path, TRUE, TRUE ) )
                break;
            if ( false !== $this->cmpstr( $this->get_http_host(), $rpath_arr[ count( $rpath_arr ) - $x ] ) )
                break;
            if ( $x > 20 )
                break; // we're likely looping :-/
            array_pop( $rpath_arr );
            $x++;
        }
        $dir_path = $this->get_dir() . '.htaccess';

        if ( false === is_null( $root_path ) ) {
            return $root_path;
        } elseif ( false !== $this->get_file_perms( $dir_path, TRUE, TRUE ) ) {
            return $dir_path;
        } else
            return false;
    }
    function email_log( $pareto_report2 = '' ) {
        if ( false === function_exists( 'wp_mail' ) ) require_once ABSPATH . WPINC . '/pluggable.php';
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
                                    <td>' . $img_tag . '</td><td><H2>PARETO SECURITY</H2></td>
                                </tr>
                                <tr>
                          </table>
                          <table style="width:100%;">
                                <tr>
                                    <td><strong>Record of High/Med Severity Attack: Last 5 Incidents</strong></td>
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
                                                <td style="width:140px; color: #FFFFFF;font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;"><b>IP Address:</b></td>
                                                <td style="width:50px; color: #FFFFFF;font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;"><b>Req:</b></td>
                                                <td style="width:100px; color: #FFFFFFfont-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif;;"><b>Filename:</b></td>
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
        
        $mylogs     = get_option( $this->log_list );
        $i          = 0;
        $text_color = "#e68735";
        $n = 0;
        while ( $i <= 99 ) {
            if ( isset( $mylogs[ $i ] ) && $n < 5 ) {
                $row_colour = ( $i % 2 == 0 ) ? "#E6E6F5" : "#F3F3F3";
                $req_var    = explode( ' ', $mylogs[ $i ] );
                if ( preg_match( "/low|safe/i", $req_var[ 1 ] ) ) {
                        $i++;
                        continue;
                } else $n++;
                if ( $req_var[ 1 ] == "Medium" ) {
                    $text_color = "#e68735";
                } elseif ( empty( $req_var[ 1 ] ) ) {
                    $req_var[ 1 ] = "Medium";
                    $text_color   = "#e68735";
                } else
                    $text_color = "#c72b2c";
                $mylogs_fin[ $i ] = $mylogs[ $i ];
                $ip_addr          = $req_var[ 2 ];
                $attack_string    = str_replace( '%20', " ", preg_replace( "/[\n]/i", "", stripslashes( $req_var[ 5 ] ) ) );
                $attack_string    = wordwrap( $attack_string, 100, "<br />\n" );
                $pareto_report3 .= "\n<tr style=\"background-color: " . $row_colour . ";\">\n" .
                                   "    <td style=\"vertical-align:top; width:100px; font-size:11px;font-family:Verdana,Tahoma,Arial,sans-serif; white-space: nowrap\">" . $this->url_decoder( $req_var[ 0 ] ) . "</td>\n" .
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
    function is_wp( $isinadmin = false, $isadmin = false ) {
        if ( defined( 'WP_PLUGIN_DIR' ) && false !== function_exists( 'is_admin' ) ) {
            if ( false !== $isinadmin ) {
                if ( false !== file_exists( ABSPATH . WPINC . '/pluggable.php' ) && false === function_exists( 'is_admin' ) ) require_once ABSPATH . WPINC . '/pluggable.php';
                if ( ( false === ( bool ) defined( 'WP_ADMIN' ) || false !== WP_ADMIN ) && false === is_admin() ) return false;
            }
            if ( false !== $isadmin ) { // current user has administrators rights
                if ( false !== file_exists( ABSPATH . WPINC . '/pluggable.php' ) && false === function_exists( 'wp_get_current_user' ) )
                    require_once ABSPATH . WPINC . '/pluggable.php';
                $current_user = wp_get_current_user();
                $is_superadmin = ( false !== is_super_admin( $current_user->ID ) ) ? true : false;
                if ( false === user_can( $current_user, 'administrator' ) && false === $is_superadmin ) return false;
            }
            return true;
        }
        return false;
    }
    function do_security_settings() {
        # defaults sets errors to production settings
        $this->_set_error_level();
        # disable assert function in local scope
        # shouldn't be available to production websites
        ini_set( 'assert.active', '0' );
        # if open_basedir is not set in php.ini then set it in the local scope
        $this->setOpenBaseDir();
        # Send secure headers
        $this->x_secure_headers();
        
        if ( false !== $this->is_wp() ) {
            $this->settings_field = 'pareto_security_settings_options';
            $this->options = get_option( $this->settings_field );
        }
        $this->ps_icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAACXBIWXMAAAsSAAALEgHS3X78AAAHkElEQVR4nO3aW1MaaRoH8PkSe7e3c7u1tZdblUrUUVOzmamtGfGAZqICTeMRUWMwnBVoRE6CZwl4yDg4QtydqMMaVjRG8IByEEU5KGDwEGcS5AvsBTuk7SZKtCdK1Tz1v3pvnv5Vv89L09WfRdO8PrvuC7hq/QG47sIMEDp4Ez44Dr0+2ts/9IUOt4OHnuDRVujI5d/XajTqgYGenh6VSqVSKg16PVZNo1gBDt78+jmef4sAZRKhDCL09zLorw+gz0ugP+OhP+GFPDaLzXoftVqNSdN4YQM4PP4lGxDlguJ47oLiu6A4FxRnkdv+RhBxzwIG+vsxaRovbACvj06+IL0HwCXZIBLQ19eHSdN4YQbISgbIBcVfUkQcBKC3F5Om8cJoBo5/ySAmB/wjPQBvfv1LCf82QXiHIMwkCDMIwkwiFE8uIEQA+m/gFopGoxu+sGsnaN8KrLh8Fvt2IrMWO4vBuFlD3Pvjf6uFQ5QWDZGjLmX0FdO7Cxo78xtUeTQlOoX1Cg7rht0BpkqfdLsnzb2KNvQMhMPhqcnJ6d9qanJyf38/bQC9PT329fXqqqrampp4qiornU5n2gC6OjvXbLY6KrWeRouHWltrX19PG4BKqVxZWUEAbKurnw5Al49lEKAUgz5GOxQKq9WKACwvL386gHd3f9Xltdq3F2xbc8sbJovTuGCfnLP9ZE4Sg3GRxTxzjMplslevXiEAFovl9wI8eTZHl+uaZD80SEZp4qe1ohGqaKQWGqkWDlXyB8EW7fmp4A1wWEw4QCaVzs/PIwALCwsnJyeRSCQcDu/t7QWDwYODA2wArC5D6js+lRmQSaWzs7MIwPz8fHdXFxkAiAQCkUAAyeQOheLmAl68eIEAmM1mmVRKBoBE+K2t2AA43dgDjEYjAmAymUQQBAcwGQxsAC29E5gDpqemEICZmRkBnw8HND18iA2gtW8iiwhdOnfJUIoAHo8HB9Dq6qLRaCQSCYVCu7u7gUAgEol8BOD09DQWi8VisRmLq1NnunRUT6fZzDOnkFQiSQpgMBhwQHVVld/vLykuzsfh8nG4woICSCi8AOAJhDldBk6XgaEcfyQfeyQfa5KPMZTjrE7DpcNU6tislABNDx/CARQQdG9s5ONw+KKieBobGi4AWB07t8sE2UAbhvkSRP4j+xCgsaEBDgDJ5LW1NVxeXgJAAcELAEtObyYRusrIpjLEUolkenr6QgAZAJaWluCA+yUl7969SxsAQCJZFhfhgMKCghsBkEmlP6cAIBGJaMDbt28vmoFyQTbQlk1uywXbYRGjVtpzQHEOOX6V7xezyW1oAJfN4sAil8n+YzTW19U10Gjx1FFrTSZTY0M9CACJAESi1WqFD3HRhQBPIPy448dHcl21QHuPyLpHYt0jsb4isb+t5FfwBr4GOP8EuYngaZLyZtW3lYJvKvn/T0VrRctAfg0ET2GtkEbn1dG5v4XHgRSaH/5VQWOAVDpYSwep9Ara45HxyUoa4wGZCo/u3zOFpRTcfSCewlLKy9XNFZfX7Q0mB8QrFou5nI4CXF5xUWFxUWExvohEJKyv2QhlpSBASkTZoRgf0zXW1zfU0+Kh1lS7nE42k8FlsxJhMNlfkNtzwPfJJouzSCL4Sg7Yjl6JL+ZS2nMpknhywPYMIpRJhG6XCc4DRKPR9fV1+OYryM+3Wq3lZWXwPapQKAYHBxP7uJ5Gq62pcToczLMvUZoZ7BxMhyoXFGcDbRcAEAfwhwBarRYBcNwUgM2W3gCHw5HSFkIBbsoW2nS7EQfwUmqApHcg4woPs0lzp/yiIfZ6vbi8vPhjYD4OV4zHLy8tpTLEaIBAIFzbCq66dy+dTf9rX+jAG4x49177Qwd7+4fhg+MLAEdHR98/fTo4OKjVaIaHh58/f+5wONCAoaGhlO4AAUq8rP7Y3Crlj04tJr3I8wDoctjtlwZcZQaySCLd9HlvXFIF2JMBhlEAp9N5QwEbGxsIgLKjA30HXC4X5oAJ0woGgO3t7e/u3yeUlyeSFOB2uzEHGBfsGAAODw9HR0f1ev3Es2d6vX5Mp7NaLOgfss3NTQSAzmDfSflFKjq3SvlzK24MAOiKxWJqtRoB8Hg86GPU5g7Y3P5zsrYZsG/tOj27rp095/aec3vPvRPc9IU8/vB2YP/w+OR3AZyenj5BAXZ2dhCAx0zOV9Xyr2tk6HxTp8hvVBU/6n7A6CNyBigtmopW7fkbBktANBpFA7xeL/zqP3YGskii0clXnw6g0WgQAL/fz+Vw0gYwhHqUCAQCLTxe2gB0Ol0znZ5IU2NjKBjkt7amDSBpCQUCBCD1Y/RWKX/kp5fXDBBBEBzA5wuMCw7jgh2dmUXnC4vTvLzx0rZpsXtWXN41ty8cObpmgFgshgOYLG4ZayARAltNadXWQMP17d+zVBh8uoU9QCKRpDgD+Kbuq7fDHiCXydIboFAoUgR814zBh0PYA5RKZYoAgPvk6u2wB3R1dp4FcD70l7KSr716O+wB3V1dj5ubE+FwWzQT82qDud9g7tPP9o7P9uln+w1mtcE8Obd29XbYAwKBgAdWPp8P8xbw+uPT4+uu/wEGULwcmNYlVgAAAABJRU5ErkJggg==";
    }
    function set_safe_request() {
        global $_REQUEST, $_ENV, $_GET, $_POST;
        $this_request = array_merge( $_ENV, $_GET, $_POST );
        # remove cookies from the local scope of _REQUEST
        if ( isset( $this_request[ 'HTTP_COOKIE' ] ) ) unset( $this_request[ 'HTTP_COOKIE' ] );
        # Merge $_REQUEST excluding _COOKIE data
        $_REQUEST = $this_request;
        return;
    }
    function set_timestamp() {
        return ( false !== $this->is_wp() ) ? date_i18n( 'd-m-Y', ( $this->updated( time(), ( int ) get_option( 'gmt_offset' ) ) ) ) . "<br>" .
                                              date_i18n( 'h:i:sA', ( $this->updated( time(), ( int ) get_option( 'gmt_offset' ) ) ) ) : date( "d.m.y-G:i" );
    }
    function advanced_mode( $mode = 0 ) {
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
if ( false!== strpos( basename( realpath( $_SERVER[ 'SCRIPT_FILENAME' ] ) ), 'pareto_' ) ) {
        $status   = '403 Access Denied';
        $protocol = ( isset( $_SERVER[ 'SERVER_PROTOCOL' ] ) ? substr( $_SERVER[ 'SERVER_PROTOCOL' ], 0, 8 ) : 'HTTP/1.1' ) . ' ';
        $header   = array(
             $protocol . $status,
            'Status: ' . $status,
            'Content-Length: 0' 
        );
        foreach ( $header as $sent ) {
            header( $sent );
        }
        exit();
}
?>
