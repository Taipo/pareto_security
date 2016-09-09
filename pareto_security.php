<?php
/*
Plugin Name: Pareto Security
Plugin URI: http://hokioisec7agisc4.onion/?p=25
Description: Core Security Class - Defense against a range of common attacks such as database injection
Author: Te_Taipo
Version: 1.3.1
Requirements: Requires at least PHP version 5.2.0
Author URI: http://hokioisec7agisc4.onion
BTC:1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX
*/

/*
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

See: See http://www.gnu.org/licenses/gpl-3.0.txt

*/

if ( defined( 'WP_PLUGIN_DIR' ) ) {
	// don't load directly
	if ( !function_exists( 'is_admin' ) ) {
		$header = array(
			'HTTP/1.1 403 Access Denied',
			'Status: 403 Access Denied',
			'Content-Length: 0' 
		);
		foreach ( $header as $sent ) {
			header( $sent );
		}
		exit();
	}
	# Set Pareto Security as the first plugin loaded
	add_action( "activated_plugin", "load_pareto_first" );
	
	define( 'PARETO_VERSION', '1.3.1' );
	define( 'PARETO_RELEASE_DATE', date_i18n( 'F j, Y', '1473239854' ) );
	define( 'PARETO_DIR', plugin_dir_path( __FILE__ ) );
	define( 'PARETO_URL', plugin_dir_url( __FILE__ ) );
}

class ParetoSecurity {
	# protect from non-standard request types
	protected $_nonGETPOSTReqs = 0;
	# if open_basedir is not set in php.ini. Leave disabled unless you are sure about using this.
	protected $_open_basedir = 0;
	# activate _SPIDER_SHIELD()
	protected $_spider_block = 0;
	# ban attack ip address to the root /.htaccess file. Leave this disabled if you are hosting a website using TOR's Hidden Services
	protected $_banip = 0;
	# path to the root directory of the site, e.g /home/user/public_html
	public $_doc_root = '';
	# Correct Production Server Settings = 0, prevent any errors from displaying = 1, Show all errors = 2 ( depends on the php.ini settings )
	protected $_quietscript = 0;
	# Custom set a number of above settings all at once
	protected $_adv_mode = 0;
	
	# Other
	protected $_bypassbanip = false;
	protected $_ip = '';
	protected $_get_all = array();
	protected $_post_all = array();
	
	public function __construct() {
		
		if ( defined( 'WP_PLUGIN_DIR' ) ) {
			require( PARETO_DIR . 'pareto-settings.php' );
			$ParetoSettings = new Pareto_Security_Settings();
			
			register_activation_hook( __FILE__, array(
				 $this,
				'activate' 
			) );
			register_deactivation_hook( __FILE__, array(
				 $this,
				'deactivate' 
			) );
			
			$this->_adv_mode = isset( $ParetoSettings->advmode ) ? $ParetoSettings->advmode : $this->_adv_mode;
		}
		$this->advanced_mode();
		$this->_set_error_level();
		# if open_basedir is not set in php.ini then set it in the local scope
		$this->setOpenBaseDir();
		# Send secure headers
		$this->x_secure_headers();
		# Set IP
		$this->_ip = $this->getRealIP();
		# Merge $_REQUEST with _GET and _POST excluding _COOKIE data
		$_REQUEST = array_merge( $_GET, $_POST );
		# Shields Up
		$this->_QUERYSTRING_SHIELD();
		$this->_POST_SHIELD();
		$this->_REQUEST_SHIELD();
		$this->_COOKIE_SHIELD();
		$this->_REQUESTTYPE_SHIELD();
		$this->_SPIDER_SHIELD();
		$this->__destruct();
	}
	public function __destruct() {
		if ( false === empty( $this->_get_all ) ) unset( $this->_get_all );
		if ( false === empty( $this->_post_all ) ) unset( $this->_post_all );
	}
	
	function network_propagate( $pfunction, $networkwide ) {
		global $wpdb;
		
		if ( function_exists( 'is_multisite' ) && is_multisite() ) {
			// check if it is a network activation - if so, run the activation function 
			// for each blog id
			if ( $networkwide ) {
				$old_blog = $wpdb->blogid;
				// Get all blog ids
				$blogids  = array();
				$blogids  = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs}" );
				foreach ( $blogids as $blog_id ) {
					switch_to_blog( $blog_id );
					call_user_func( $pfunction, $networkwide );
				}
				switch_to_blog( $old_blog );
				return;
			}
		}
		call_user_func( $pfunction, $networkwide );
	}
	
	function activate( $networkwide ) {
		$this->network_propagate( array(
			 $this,
			'_activate' 
		), $networkwide );
	}
	
	function deactivate( $networkwide ) {
		$this->network_propagate( array(
			 $this,
			'_deactivate' 
		), $networkwide );
	}
	
	function _activate() {
	}
	function _deactivate() {
	}
	
	protected function _set_error_level() {
		$val = ( false !== $this->integ_prop( $this->_quietscript ) || false !== ctype_digit( $this->_quietscript ) ) ? ( int ) $this->_quietscript : 0;
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
				break;
			default:
				error_reporting( 6135 );
		}
	}
	/**
	 * send403()
	 * 
	 * @return
	 */
	function send403() {
		$status = '403 Access Denied';
		$header = array(
			'HTTP/1.1 ' . $status,
			'Status:  ' . $status,
			'Content-Length: 0' 
		);
		foreach ( $header as $sent ) {
			header( $sent );
		}
		exit();
	}
	
	/**
	 * karo()
	 * 
	 * @return
	 */
	
	function karo( $t = false ) {
		if ( false === ( bool ) $this->_banip || false !== $this->_bypassbanip )
			$this->send403();

		if ( ( false !== $this->get_file_perms( $this->getDir() . DIRECTORY_SEPARATOR . '.htaccess', TRUE, TRUE ) ) && ( false !== ( bool ) $t ) && ( false === ( bool ) $this->_bypassbanip ) ) {
			$this->htaccessbanip( $this->_ip );
		}
		$this->send403();
	}
	/**
	 * injectMatch()
	 * 
	 * @param mixed $string
	 * @return
	 */
	protected function injectMatch( $string ) {
		$string  = $this->url_decoder( strtolower( $string ) );
		$kickoff = false;
		# these are the triggers to engage the rest of this function.
		$vartrig = "\/\/|\.\.\/|%0d%0a|0x|a(?:ll|lert|scii\()|b(?:ase64|enchmark|y)|
				   c(?:ase|har|olumn|onvert|ookie|reate)|d(?:eclare|ata|ate|elete|rop)|concat|
				   e(?:rror|tc|val|xec)|f(?:rom|tp)|g(?:rant|roup)|having|i(?:f|nsert|snull|nto)|
				   j(?:s|json)|l(?:ength\(|oad)|master|onmouse|null|php|s(?:chema|elect|et|hell|
				   how|leep)|table|u(?:nion|pdate|ser|tf)|var|w(?:aitfor|hen|here|hile)";
		$vartrig = preg_replace( "/[\s]/i", "", $vartrig );
		for ( $x = 1; $x <= 5; $x++ ) {
			$string = $this->cleanString( $x, $string );
			if ( false !== ( bool ) preg_match( "/$vartrig/i", $string ) ) {
				$kickoff = true;
				break;
			}
		}
		if ( false === $kickoff ) {
			return false; // if false then we are not interested in this query.
		} else { // else we are very interested in this query.
			$j				= 1;
			# toggle through 6 different filters
			$sqlmatchlist = "(?:abs|ascii|base64|bin|cast|chr|char|charset|
					collation|concat|conv|convert|count|curdate|database|date|
					decode|diff|distinct|else|elt|end||encode|encrypt|extract|field|
					_file|floor|format|hex|if|inner|insert|instr|interval|join|lcase|
					left|length|like|load_file|locate|lock|log|lower|lpad|ltrim|max|
					md5|mid|mod|name|now|null|ord|password|position|quote|rand|
					repeat|replace|reverse|right|rlike|round|row_count|rpad|rtrim|
					_set|schema|select|sha1|sha2|serverproperty|soundex|
					space|strcmp|substr|substr_index|substring|sum|time|trim|
					truncate|ucase|unhex|upper|_user|user|values|varchar|
					version|while|ws|xor)\(|\(0x|@@|cast|integer";
			
			$sqlupdatelist	= "\bcolumn\b|\bdata\b|concat\(|\bemail\b|\blogin\b|
					\bname\b|\bpass\b|sha1|sha2|\btable\b|table|\bwhere\b|\buser\b|
					\bval\b|0x|--";
			
			$sqlfilematchlist = 'access_|access.|\balias\b|apache|\/bin|win.|
					\bboot\b|config|\benviron\b|error_|error.|\/etc|httpd|
					_log|\.(?:js|txt|exe|ht|ini|bat|log)|\blib\b|\bproc\b|
					\bsql\b|tmp|tmp\/sess|\busr\b|\bvar\b|\/(?:uploa|passw)d';
			
			$sqlmatchlist2	= '@@|_and|ascii|b(?:enchmark|etween|in|itlength|
					ulk)|c(?:ast|har|ookie|ollate|olumn|oncat|urrent)|\bdate\b|
					dump|e(?:lt|xport)|false|\bfield\b|fetch|format|function|
					\bhaving\b|i(?:dentity|nforma|nstr)|\bif\b|\bin\b|inner|insert|
					l(?:case|eft|ength|ike|imit|oad|ocate|ower|pad|trim)|join|
					m(:?ade by|ake|atch|d5|id)|not_like|not_regexp|null|\bon\b|
					order|outfile|p(?:ass|ost|osition|riv)|\bquote\b|\br(?:egexp\b|
					ename\b|epeat\b|eplace\b|equest\b|everse\b|eturn\b|ight\b|
					like\b|pad\b|trim\b)|\bs(?:ql\b|hell\b|leep\b|trcmp\b|ubstr\b)|
					\bt(?:able\b|rim\b|rue\b|runcate\b)|u(?:case|nhex|pdate|
					pper|ser)|values|varchar|\bwhen\b|where|with|\(0x|
					_(?:decrypt|encrypt|get|post|server|cookie|global|or|
					request|xor)|(?:column|db|load|not|octet|sql|table|xp)_|
					version|auto_prepend_file|allow_url_include|0x3c62723e';
			
			while ( $j <= 6 ) {
				$string = $this->cleanString( $j, $string );
				
				$sqlmatchlist	 = preg_replace( "/[\s]/i", '', $sqlmatchlist );
				$sqlupdatelist	= preg_replace( "/[\s]/i", '', $sqlupdatelist );
				$sqlfilematchlist = preg_replace( "/[\s]/i", '', $sqlfilematchlist );
				$sqlmatchlist2	= preg_replace( "/[\s]/i", '', $sqlmatchlist2 );
				
				if ( false !== ( bool ) preg_match( "/\bdrop\b/i", $string ) && false !== ( bool ) preg_match( "/\btable\b|\buser\b/i", $string ) && false !== ( bool ) preg_match( "/--|and|\//i", $string ) ) {
					return true;
				} elseif ( ( false !== strpos( $string, 'grant' ) ) && ( false !== strpos( $string, 'all' ) ) && ( false !== strpos( $string, 'privileges' ) ) ) {
					return true;
				} elseif ( false !== ( bool ) preg_match( "/(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\)))/i", $string ) ) {
					return true;
				} elseif ( false !== preg_match_all( "/\bload\b|\bdata\b|\binfile\b|\btable\b|\bterminated\b/i", $string, $matches ) > 3 ) {
					return true;
				} elseif ( ( ( false !== ( bool ) preg_match( "/select|sleep|isnull|declare|ascii\(substring|length\(/i", $string ) ) && ( false !== ( bool ) preg_match( "/\band\b|\bif\b|group_|_ws|load_|exec|when|then|concat\(|\bfrom\b/i", $string ) ) && ( false !== ( bool ) preg_match( "/$sqlmatchlist/i", $string ) ) ) ) {
					return true;
				} elseif ( false !== preg_match_all( "/$sqlmatchlist/i", $string, $matches ) > 2 ) {
					return true;
				} elseif ( false !== strpos( $string, 'update' ) && false !== ( bool ) preg_match( "/\bset\b/i", $string ) && false !== ( bool ) preg_match( "/$sqlupdatelist/i", $string ) ) {
					return true;
				} elseif ( false !== strpos( $string, 'having' ) && false !== ( bool ) preg_match( "/\bor\b|\band\b/i", $string ) && false !== ( bool ) preg_match( "/$sqlupdatelist/i", $string ) ) {
					return true;
					# tackle the noDB / js issue
				} elseif ( ( $this->substri_count( $string, 'var' ) > 1 ) && false !== ( bool ) preg_match( "/date\(|while\(|sleep\(/i", $string ) ) {
					return true;
					# reflected download attack
				} elseif ( ( substr_count( $string, '|' ) > 2 ) && false !== ( bool ) preg_match( "/json/i", $string ) ) {
					return true;
				}
				# run through a set of filters to find specific attack vectors
				$thenode = $this->cleanString( $j, $this->getREQUEST_URI() );
				
				if ( ( false !== ( bool ) preg_match( "/onmouse(?:down|over)/i", $string ) ) && ( 2 < ( int ) preg_match_all( "/c(?:path|tthis|t\(this)|http:|(?:forgotte|admi)n|sqlpatch|,,|ftp:|(?:aler|promp)t/i", $thenode, $matches ) ) ) {
					return true;
				} elseif ( ( ( false !== strpos( $thenode, 'ftp:' ) ) && ( $this->substri_count( $thenode, 'ftp' ) > 1 ) ) && ( 2 < ( int ) preg_match_all( "/@|\/\/|:/i", $thenode, $matches ) ) ) {
					return true;
				} elseif ( ( substr_count( $string, '../' ) > 3 ) || ( substr_count( $string, '..//' ) > 3 ) || ( $this->substri_count( $string, '0x2e0x2e/' ) > 1 ) ) {
					if ( false !== ( bool ) preg_match( "/$sqlfilematchlist/i", $string ) ) {
						return true;
					}
				} elseif ( ( substr_count( $string, '/' ) > 1 ) && ( 2 <= ( int ) preg_match_all( "/$sqlfilematchlist/i", $thenode, $matches ) ) ) {
					return true;
				} elseif ( ( false !== ( bool ) preg_match( "/%0D%0A/i", $thenode ) ) && ( false !== strpos( $thenode, 'utf-7' ) ) ) {
					return true;
				} elseif ( false !== ( bool ) preg_match( "/php:\/\/filter|convert.base64-(?:encode|decode)|zlib.(?:inflate|deflate)/i", $string ) || false !== ( bool ) preg_match( "/data:\/\/filter|text\/plain|http:\/\/(?:127.0.0.1|localhost)/i", $string ) ) {
					return true;
				}
				
				if ( 5 <= substr_count( $string, '%' ) )
					$string = str_replace( '%', '', $string );
				
				if ( ( false !== ( bool ) preg_match( "/\border by\b|\bgroup by\b/i", $string ) ) && ( false !== ( bool ) preg_match( "/\bcolumn\b|\bdesc\b|\berror\b|\bfrom\b|hav|\blimit\b|offset|\btable\b|\/|--/i", $string ) || ( false !== ( bool ) preg_match( "/\b[0-9]\b/i", $string ) ) ) ) {
					return true;
				} elseif ( ( false !== ( bool ) preg_match( "/\btable\b|\bcolumn\b/i", $string ) ) && false !== strpos( $string, 'exists' ) && false !== ( bool ) preg_match( "/\bif\b|\berror\b|\buser\b|\bno\b/i", $string ) ) {
					return true;
				} elseif ( ( false !== strpos( $string, 'waitfor' ) && false !== strpos( $string, 'delay' ) && ( ( bool ) preg_match( "/(:)/i", $string ) ) ) || ( false !== strpos( $string, 'nowait' ) && false !== strpos( $string, 'with' ) && ( false !== ( bool ) preg_match( "/--|\/|\blimit\b|\bshutdown\b|\bupdate\b|\bdesc\b/i", $string ) ) ) ) {
					return true;
				} elseif ( false !== ( bool ) preg_match( "/\binto\b/i", $string ) && ( false !== ( bool ) preg_match( "/\boutfile\b/i", $string ) ) ) {
					return true;
				} elseif ( false !== ( bool ) preg_match( "/\bdrop\b/i", $string ) && ( false !== ( bool ) preg_match( "/\buser\b/i", $string ) ) ) {
					return true;
				} elseif ( ( ( false !== strpos( $string, 'create' ) && false !== ( bool ) preg_match( "/\btable\b|\buser\b|\bselect\b/i", $string ) ) || ( false !== strpos( $string, 'delete' ) && false !== strpos( $string, 'from' ) ) || ( false !== strpos( $string, 'insert' ) && ( false !== ( bool ) preg_match( "/\bexec\b|\binto\b|from/i", $string ) ) ) || ( false !== strpos( $string, 'select' ) && ( false !== ( bool ) preg_match( "/\bby\b|\bcase\b|extract|from|\bif\b|\binto\b|\bord\b|union/i", $string ) ) ) ) && ( ( false !== ( bool ) preg_match( "/$sqlmatchlist2/i", $string ) ) ) ) {
					return true;
				} elseif ( ( false !== strpos( $string, 'union' ) ) && ( false !== strpos( $string, 'select' ) ) && ( false !== strpos( $string, 'from' ) ) ) {
					return true;
				} elseif ( false !== strpos( $string, 'etc/passwd' ) ) {
					return true;
				} elseif ( false !== strpos( $string, 'null' ) ) {
					$nstring = preg_replace( "/[^a-z]/i", '', $this->url_decoder( $string ) );
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
	protected function datalist( $val, $list = 0 ) {
		# although we try not to do this, arbitrary blacklisting of certain request variables
		# cannot be avoided. however I will attempt to keep this list short.

		$_datalist	  = array();
		$val = preg_replace( "/[\s]/i", '', strtolower( $this->decode_code( str_replace( "'", '', ( $val ) ) ) ) );
		# _REQUEST[]
		$_datalist[ 1 ] = array( "php/login","eval(","base64_","@eval","extractvalue(",
				"}catch(e","allow_url_include","safe_mode","disable_functions","phpinfo(",
				"shell_exec(","open_basedir","auto_prepend_file","php://input",")limit",
				"string.fromcharcode","prompt(","onerror=alert(","/var/lib/php","4294967296",
				"get[cmd","><script","\$_request[cmd","usr/bin/perl",
				"javascript:alert(","pwtoken_get","php_uname","passthru(","sha1(","sha2(",
				"<?php","/iframe","\$_get","@@version","ob_starting","../cmd","document.",
				"onload=","mysql_query","window.location","/frameset","utl_http.request",
				"location.replace(","()}","@@datadir","_start_","php_self","%c2%bf","}if(",
				"[link=http://","[/link]","ywxlcnqo","\$_session","\$_request","\$_env",
				"\$_server",";!--=","substr(","\$_post","hex_ent","inurl:","replace(",
				".php/admin","mosconfig_","<@replace(","/iframe>","=alert(","localhost",
				"php/password_for","unhex(","error_reporting(","http_cmd","127.0.0.1:",
				"set-cookie","{\$","http/1.","print@@variable","xp_cmdshell","globals[",
				"xp_availablemedia","sp_password","/etc/","file_get_contents(","<base",
				"*(|(objectclass=|||","../wp-",".htaccess",";echo","system(","zxzhbcg=",
				"rush=","znjvbunoyxjdb2rl","fsockopen","u0vmrunulyoqlw==","ki9xsevsrs8q",
				"expect://[cmd]",":;};","wget","script>" );
		
		# _POST[]
		$_datalist[ 2 ] = array( "zxzhbcg","eval(", "base64_","fromcharcode","allow_url_include",
				"@eval","php://input","concat(","suhosin.simulation=","usr/bin/perl","shell_exec(",
				"string.fromcharcode","/etc/passwd","file_get_contents(","fopen(","get[cmd","><script",
				"/bin/cat","passthru(","><javas","ywxlcnqo","znjvbunoyxjdb2rl", "\$_request[cmd",
				"system(" );
		
		# 'User-Agent'
		$_datalist[ 3 ] = array( "usr/bin/perl",":;};","system(","curl","python","base64_","phpinfo",
				"wget","eval(","getconfig(",".chr(","passthru","shell_exec","popen(","exec(", "onerror",
				"document.location" );
		
		$_datalist[ 4 ] = array( "mozilla","android","windows","chrome","safari","opera","apple","google" );
		
		for( $x=0; $x < count( $_datalist[ ( int ) $list ] ); $x++ ) {
			if ( false !== strpos( $val, $this->decode_code( $_datalist[ ( int ) $list ][ $x ] ) ) ) {
				return true;
			}
		}
		return false;		
	}
	
	/**
	 * _REQUEST_Shield()
	 * 
	 * @return
	 */
	protected function _REQUEST_SHIELD() {
		
		$_get_server = $_SERVER;
		$_get_post = $_POST;
		
		# specific attacks that do not necessarily
		# involve query_string manipulation
		$req = strtolower( $this->url_decoder( $this->getREQUEST_URI() ) );

		# short $_SERVER[ 'SERVER_NAME' ] can indicate server hack
		# see http://bit.ly/1UeGu0W
		if ( strlen( $this->get_http_host() ) < 4 )
			$this->karo( false );
			
		# Reflected File Download Attack
		if ( false !== ( bool ) preg_match( "/\.(?:bat|cmd|ini|htac|htpa|passwd)/i", $req ) )
			$this->karo( true );

		# osCommerce specific exploit
		if ( false !== strpos( $req, '.php/admin' ) )
			$this->karo( true );
		
		# if empty then the rest of no interest to us
		if ( false !== empty( $_REQUEST ) ) return;

		# prevent arbitrary file includes/uploads
		if ( false !== ( bool ) @ini_get( 'allow_url_include' ) ) {
				if (  false !== $this->instr_url( $req ) ) {
					preg_match( "/(?:http:|https:|ftp:|file:|php:)/i", $req, $matches );
					if ( false === stripos( $req, $this->get_http_host() ) && count( $matches ) == 1 ) {
						$this->karo( false );
					} elseif ( false !== stripos( $req, $this->get_http_host() ) && count( $matches ) > 1 ) {
						$this->karo( false );
					}
				}
		}

		# prevent command injection
		if ( false !== in_array( "'cmd'", $this->_get_all ) || false !== in_array( "'system'", $this->_get_all ) )
			$this->karo( false );

		# Detect HTTP Parameter Pollution
		# i.e when devs mistakenly use $_REQUEST to return values
		$dup_check_get = array();
		$qs_arr = explode( '&', $this->getQUERY_STRING() );
		for( $x = 0; $x < count( $qs_arr ); $x++ ) {
			$this_key = strtolower( $this->decode_code( substr( $qs_arr[ $x ], 0, strpos( $qs_arr[ $x ], '=' ) ), false, true ) );
			if ( false !== $this->string_prop( $this_key, 1 ) && false === $this->cmpstr( '[]', substr( $this_key, -2 ) ) ) {
				$dup_check_get[ $x ] = escapeshellarg( str_replace( "'", '', $this_key ) );
			}
		}
		$dup_check_get = array_unique( $dup_check_get );
		
		if ( false !== $this->cmpstr( 'POST', $_get_server[ 'REQUEST_METHOD' ] ) && false === empty( $_get_post ) ) {
			# while we're checking _POST, prevent attempts to esculate user privileges in WP
			if ( ( false !== function_exists( 'is_admin' ) && false === is_admin() ) && false !== $this->cmpstr( 'admin-ajax.php', $this->get_filename() ) && ( false !== in_array( 'default_role' , $_get_post ) && false !== $this->cmpstr( 'administrator', $_get_post[ 'default_role' ] ) ) ) $this->karo( false );

			$dup_check_post = array();
			for( $x = 0; $x < count( $this->_post_all ); $x++ ) {
				$this_key = strtolower( $this->decode_code( $this->_post_all[ $x ], false, true ) );
				if ( $this->string_prop( $this_key, 1 ) && false === $this->cmpstr( '[]', substr( $this_key, -2 ) ) ) {
					$dup_check_post[ $x ] = $this_key;
				}
			}
			if ( false === empty( $dup_check_post ) ) $dup_check_post = array_unique( $dup_check_post );

			# We only test for duplicate keys that appear in both QUERY_STRING and POST global.
			if ( count( array_intersect( $dup_check_get, $dup_check_post ) ) > 0 ) {
				header( "Location: " . ( getenv( "HTTPS" ) ? 'https://' : 'http://' ) . $this->get_http_host() . $this->decode_code( substr( $req, 0, strpos( $req, '?' ) ) ) );
				exit();
			}
		}
		
		# WP Author Discovery
		$ref = isset( $_get_server[ 'HTTP_REFERER' ] ) ? strtolower( $this->url_decoder( $_get_server[ 'HTTP_REFERER' ] ) ) : NULL;
		if ( false === is_null( $ref ) ) {
			if ( false !== strpos( $req, '?author=' ) ) {
				$this->karo( false );
			}
			if ( false !== strpos( $ref, 'result' ) ) {
				if ( ( false !== strpos( $ref, 'chosen' ) ) && ( false !== strpos( $ref, 'nickname' ) ) ) {
					$this->karo( false );
				}
			}
		}

		if ( false !== strpos( $req, '?' ) ) {
			$v = $this->decode_code( substr( $req, strpos( $req, '?' ), ( strlen( $req ) - strpos( $req, '?' ) ) ) );
			if ( false !== strpos( $v, '-' ) && ( ( false !== strpos( $v, '?-' ) ) || ( false !== strpos( $v, '?+-' ) ) ) && ( ( false !== stripos( $v, '-s' ) ) || ( false !== stripos( $v, '-t' ) ) || ( false !== stripos( $v, '-n' ) ) || ( false !== stripos( $v, '-d' ) ) ) ) {
				$this->karo( true );
			}
		}
		# this occurence of these many slashes etc are always an attack attempt
		if ( substr_count( $req, '/' ) > 20 )
			$this->karo( true );
		if ( substr_count( $req, '\\' ) > 20 )
			$this->karo( true );
		if ( substr_count( $req, '|' ) > 20 )
			$this->karo( true );
	}

	/**
	 * get_filter()
	 * 
	 * @return
	 */
	protected function querystring_filter( $val, $key ) {
		$this->_get_all[] =  strtolower( $this->decode_code( $key, true ) );
		if ( false !== ( bool ) $this->string_prop( $val, 1 ) ) {
			$val = strtolower( $this->decode_code( $val ) );
			if ( false !== $this->injectMatch( $val ) || false !== ( bool ) $this->datalist( $val, 1 ) ) {
				$this->karo( true );
			}
		}
	}
	/**
	 * _QUERYSTRING_SHIELD()
	 * 
	 * @return
	 */
	protected function _QUERYSTRING_SHIELD() {
		if ( false !== empty( $_REQUEST ) || false === $this->cmpstr( 'GET', $_SERVER[ 'REQUEST_METHOD' ] ) || false === ( bool ) $this->string_prop( $this->getQUERY_STRING(), 1 ) ) {
			return; // of no interest to us
		} else {
			# run $_GET through filters
			array_walk_recursive( $_GET, array( $this, 'querystring_filter' ) );
		}
		return;
	}

	/**
	 * post_filter()
	 * 
	 * @return
	 */
	protected function post_filter( $val, $key ) {
		$this->_post_all[] = strtolower( $this->decode_code( $key, true ) );
		if ( false !== $this->datalist( $this->decode_code( $val ), 2 ) ) {
			# while some post content can be attacks, its best to 403.
			$this->karo( false );
		}
	}
	
	/**
	 * _POST_SHIELD()
	 */
	protected function _POST_SHIELD() {
		if ( false === $this->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ] ) )
			 return; // of no interest to us
		if ( count( $_POST, COUNT_RECURSIVE ) >= 10000 )
			 $this->karo( true ); // very likely a denial of service attack

		array_walk_recursive( $_POST, array( $this, 'post_filter' ) );
	}
	/**
	 * cookie_filter()
	 * 
	 * @return
	 */
	protected function cookie_filter( $val, $key ) {
		if ( false !== ( bool ) $this->datalist( $this->decode_code( $key ), 1 ) || false !== ( bool ) $this->datalist( $this->decode_code( $val ), 1 ) ) {
			$this->karo( true );
		}
		if ( false !== ( bool ) $this->injectMatch( $key ) || false !== ( bool ) $this->injectMatch( $val ) ) {
			$this->karo( true );
		}
	}
	
	/**
	 * _COOKIE_SHIELD()
	 * 
	 * @return
	 */
	protected function _COOKIE_SHIELD() {
		if ( false !== empty( $_COOKIE ) )
			return; // of no interest to us

		array_walk_recursive( $_COOKIE, array( $this, 'cookie_filter' ) );
	}
	/**
	 * _REQUESTTYPE_SHIELD()
	 * 
	 * @return
	 */
	protected function _REQUESTTYPE_SHIELD() {
		if ( false === ( bool ) $this->_nonGETPOSTReqs )
			return;
		$req		   = $_SERVER[ 'REQUEST_METHOD' ];
		$req_whitelist = array(
			'GET',
			'POST',
			'HEAD'
		);
		# is at least a 3 char string, is uppercase, has no numbers, is not longer than 4, is in whitelist
		if ( false !== $this->string_prop( $req, 3 ) && false !== ctype_upper( $req ) && false !== ( bool ) ( strcspn( $req, '0123456789' ) === strlen( $req ) ) && ( false !== strlen( $req ) <= 4 ) && false !== in_array( $req, $req_whitelist ) ) {
			# of no interest to us
			return;
		} else
		# is of interest to us
			$this->karo( false ); // soft block
		return;
	}

	/**
	 * _SPIDER_SHIELD()
	 * Basic whitelist
	 * Bad Spider Block / UA filter
	 */
	protected function _SPIDER_SHIELD() {
		$val = strtolower( $this->decode_code( $_SERVER[ 'HTTP_USER_AGENT' ], true ) );
		if ( false !== ( bool ) $this->string_prop( $val, 1 ) ) {
			# mandatory filtering
			if ( false !== $this->injectMatch( $val ) || false !== ( bool ) $this->datalist( $val, 3 ) ) {
				$this->karo( true );
			}
			if ( false !== ( bool ) $this->_spider_block && false === ( bool ) $this->datalist( $val, 4 ) ) {
				$this->karo( false );
			}
		} else $this->karo( false );
	}

   /**
    * checkfilename()
    * 
    * @param mixed $fname
    * @return
    */
   protected function checkfilename( $fname ) {
     if ( false === empty( $fname ) && ( $this->substri_count( $fname, '.php' ) == 1 && false !== $this->cmpstr( '.php', substr( $fname, - 4 ) ) ) ) {
               return true;
     } else return false;
   }
   
   /**
    * getPHP_SELF()
    * 
    * @return
    */
   protected function get_filename() {
		$filename = '';
		$_get_server = $_SERVER;
		$filename = ( ( ( strlen( @ini_get( 'cgi.fix_pathinfo' ) ) > 0 ) && ( false === ( bool ) @ini_get( 'cgi.fix_pathinfo' ) ) ) || ( false === isset( $_get_server[ 'SCRIPT_FILENAME' ] ) && false !== isset( $_get_server[ 'PHP_SELF' ] ) && false !== $this->string_prop( basename( $_get_server[ 'PHP_SELF' ] ), 1 ) ) ) ? basename( $_get_server[ 'PHP_SELF' ] ) : basename( realpath( $_get_server[ 'SCRIPT_FILENAME' ] ) );
		preg_match( "@[a-z0-9_-]+\.php@i", $filename, $matches );
		if ( is_array( $matches ) && array_key_exists( 0, $matches ) && false !== $this->cmpstr( '.php', substr( $matches[ 0 ], -4, 4 ) ) && ( false !== $this->checkfilename( $matches[ 0 ] ) ) && ( $this->get_file_perms( $matches[ 0 ], true ) ) ) {
			   $filename = $matches[ 0 ];
		}
		return $filename;
   }
	
	protected function cleanString( $b, $s ) {
		$s = strtolower( $this->url_decoder( $s ) );
		switch ( $b ) {
			case ( 1 ):
				return preg_replace( "/[^\s{}a-z0-9_?,()=@%:{}\/\.\-]/i", '', $s );
				break;
			case ( 2 ):
				return preg_replace( "/[^\s{}a-z0-9_?,=@%:{}\/\.\-]/i", '', $s );
				break;
			case ( 3 ):
				return preg_replace( "/[^\s=a-z0-9]/i", '', $s );
				break;
			case ( 4 ): // fwr_security pro
				return preg_replace( "/[^\s{}a-z0-9_\.\-]/i", "", $s );
				break;
			case ( 5 ):
				return str_replace( '//', '/', $s );
				break;
			case ( 6 ):
				return str_replace( '/**/', ' ', $s );
				break;
			default:
				return $this->url_decoder( $s );
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
		if ( false !== empty( $banip ) || ( $banip < 7 ) || ( false === $this->get_file_perms( $this->getDir() . DIRECTORY_SEPARATOR . '.htaccess', true, true ) ) ) {
			return $this->send403();
		} else {
			$limitend = "# End of " . $this->get_http_host() . " Pareto Security Ban\n";
			$newline  = "deny from $banip\n";
			$mybans   = file( $this->getDir() . DIRECTORY_SEPARATOR . '.htaccess' );
			$lastline = "";
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
				array_push( $mybans, "\r\n# " . $this->get_http_host() . " Pareto Security Ban\n", "order allow,deny\n", $newline, "allow from all\n", $limitend );
			}
			
			$myfile = fopen( $this->getDir() . DIRECTORY_SEPARATOR . '.htaccess', 'w' );
			fwrite( $myfile, implode( $mybans, '' ) );
			fclose( $myfile );
		}
	}
	/**
	 * get_file_perms()
	 * 
	 * @return boolean
	 */
	protected function get_file_perms( $f = NULL, $r = false, $w = false ) {
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
	protected function get_http_host( $encoding = 'UTF-8' ) {
		$servername = htmlspecialchars( preg_replace( "/^(?:([^\.]+)\.)?domain\.com$/", '\1', $_SERVER[ 'SERVER_NAME' ] ), ( ( version_compare( phpversion(), '5.4', '>=') ) ? ENT_HTML5 : ENT_QUOTES ), $encoding );
		if ( false !== filter_has_var( INPUT_SERVER, $servername ) ) {
			return filter_input( INPUT_SERVER, $servername, FILTER_UNSAFE_RAW, FILTER_NULL_ON_FAILURE );
		} else {
			return filter_var( $servername, FILTER_UNSAFE_RAW, FILTER_NULL_ON_FAILURE );
		}
	}
	
	/**
	 * getDir()
	 * 
	 * @return
	 */
	function getDir() {
		$get_root = '';
		$_get_server = $_SERVER;
		$subdir  = $this->getREQUEST_URI();
		if ( false !== strpos( $subdir, DIRECTORY_SEPARATOR ) ) {
			# first we need to find if webroot is a sub directory
			# this can screw things up, if so manually set $_doc_root
			if ( false !== ( bool ) $this->string_prop( $subdir, 2 ) && false !== $this->cmpstr( $subdir[ 0 ], DIRECTORY_SEPARATOR ) ) {
				$subdir = ( ( substr_count( $subdir, DIRECTORY_SEPARATOR ) > 1 ) ) ? substr( $subdir, 1 ) : substr( $subdir, 0 );
				$pos	 = strpos( strtolower( $subdir ), DIRECTORY_SEPARATOR );
				$pos += strlen( '.' ) - 1;
				$subdir = substr( $subdir, 0, $pos );
				if ( strpos( $subdir, '.php' ) || ( strlen( $subdir ) == 1 ) && false !== $this->cmpstr( $subdir, DIRECTORY_SEPARATOR ) || false !== empty( $subdir ) )
					$subdir = '';
				if ( false !== ( bool ) $this->string_prop( $subdir, 2 ) ) {
					if ( ( substr_count( $subdir, DIRECTORY_SEPARATOR ) == 0 ) ) {
						$subdir = DIRECTORY_SEPARATOR . $subdir;
					}
				}
			}
		}
		if ( isset( $this->_doc_root ) && ( false !== ( bool ) $this->string_prop( $this->_doc_root, 2 ) ) ) {
			# is set by the user
			$get_root = $this->_doc_root;
		} elseif ( false !== defined( 'ABSPATH' ) ) {
			$get_root = ABSPATH;
		} elseif ( false !== strpos( $_get_server[ 'DOCUMENT_ROOT' ], 'usr/local' ) || empty( $_get_server[ 'DOCUMENT_ROOT' ] ) || strlen( $_get_server[ 'DOCUMENT_ROOT' ] ) < 4 ) {
			# if for some reason there is a problem with DOCUMENT_ROOT, then do this the bad way
			$f	 = dirname( __FILE__ );
			$sf	= realpath( $_get_server[ 'SCRIPT_FILENAME' ] );
			$fbits = explode( DIRECTORY_SEPARATOR, $f );
			foreach ( $fbits as $a => $b ) {
				if ( false === empty( $b ) && ( false === strpos( $sf, $b ) ) ) {
					$f = str_replace( $b, '', $f );
					$f = str_replace( '//', '', $f );
				}
			}
			$get_root = realpath( $f );
		} else {
			$get_root = ( false === empty( $subdir ) ) ? realpath( $_get_server[ 'DOCUMENT_ROOT' ] ) . $subdir : realpath( $_get_server[ 'DOCUMENT_ROOT' ] );
		}
		return preg_replace( "/wp-admin\/|wp-content\/|wp-include\//i", '', $get_root );
	}
	/**
	 * is_server()
	 * @return bool
	 */
	protected function is_server( $ip ) {
		# tests if ip address accessing webserver
		# is either server ip ( localhost access )
		# or is 127.0.0.1 ( i.e onion visitors )
		
		if ( false === isset( $ip ) ) $ip = $this->getREMOTE_ADDR();
		if ( false !== $this->cmpstr( $ip, $_SERVER[ 'SERVER_ADDR' ] ) || false !== $this->cmpstr( $ip, '127.0.0.1' ) ) {
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
	protected function check_ip( $ip ) {

		$check = false;
		if ( function_exists( 'filter_var' ) && defined( 'FILTER_VALIDATE_IP' ) && defined( 'FILTER_FLAG_IPV4' ) && defined( 'FILTER_FLAG_IPV6' ) ) {
			if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 || FILTER_FLAG_IPV6 ) ) {
				$this->send403();
			}
			if ( false !== $this->is_server( $ip ) ) {
				$this->_bypassbanip = true;
			}
			return true;
		} else {
			# this section should not be necessary in later versions of PHP
			if ( false !== preg_match( "/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/i", $ip ) ) {
				$parts = explode( '.', $ip );
				$x	 = 0;
				while ( $x < count( $parts ) ) {
					if ( false === $this->integ_prop( ( int ) $parts[ $x ] ) || ( int ) $parts[ $x ] > 255 ) {
						$this->send403();
					}
					$x++;
				}
				if ( ( count( $parts ) <> 4 ) || ( ( int ) $parts[ 0 ] < 1 ) )
						$this->send403();
				if ( false !== $this->is_server( $ip ) ) {
						$this->_bypassbanip = true;
				}
				return true;
			} else
				$this->send403();
		}
	}
	/**
	 * getRealIP()
	 * 
	 * @return
	 */
	protected function getRealIP() {
		$_get_server = $_SERVER;
		$svars = array(
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
				$the_header = strpos( $the_header, ',' ) ? str_replace( ' ', '', $the_header ) : str_replace( ' ', ',', $the_header );
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
		# for TorHS to prevent banning of server IP
		if ( false !== $this->is_server( $this->getREMOTE_ADDR() ) )
				$this->_bypassbanip = true;
		
		# never trust any ip headers except REMOTE_ADDR
		return $this->getREMOTE_ADDR();
	}
	
	protected function setOpenBaseDir() {
		if ( false === ( bool ) $this->_open_basedir )
			return;
		if ( strlen( @ini_get( 'open_basedir' ) == 0 ) ) {
			return @ini_set( 'open_basedir', $this->getDir() );
		}
	}
	/**
	 * x_secure_headers()
	 */
	protected function x_secure_headers() {
		$errlevel = @ini_get( 'error_reporting' );
		error_reporting( 0 );
		header( "strict-transport-security: max-age=31536000; includeSubDomains; preload" );
		header( "access-control-allow-methods: GET, POST, HEAD" );
		header( "x-frame-options: SAMEORIGIN" );
		header( "x-content-type-options: nosniff" );
		header( "x-xss-protection: 1; mode=block" );
		header( "x-download-options: noopen" );
		header( "x-permitted-cross-domain-policies: master-only" );
		header( "x-content-security-policy: default-src 'self'; script-src 'self';" );

		if ( false !== ( bool ) @ini_get( 'expose_php' ) || false !== $this->cmpstr( 'on', @ini_get( 'expose_php' ), true ) ) {
			header( "x-powered-by: Pareto Security - http://hokioisec7agisc4.onion" );
		}
		
		error_reporting( $errlevel );
		return;
	}
    protected function tor2web_block() {
		if ( false !== $this->is_server( $this->getREMOTE_ADDR() ) && array_key_exists( "HTTP_X_TOR2WEB", $_SERVER ) ) $this->karo( false );
	}
	/**
	 * substri_count()
	 */
	function substri_count( $hs, $n )	{
		return substr_count( strtoupper( $hs ), strtoupper( $n ) );
	}
	/**
	 * decode_code()
	 * @return
	 */
	protected function decode_code( $code, $escapeshell=false, $filter=false ) {
		$code = ( $this->substri_count( $code, '\u00' ) > 0 ) ? str_ireplace( '\u00', '%', $code ) : $code;
		$code = ( $this->substri_count( $code, '&#x' ) > 0 && substr_count( $code, ';' ) > 0 ) ? str_replace( ';', '%', str_replace( '&#x', '%', $code ) ) : $code;
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
	protected function url_decoder( $var ) {
		return rawurldecode( urldecode( str_replace( chr( 0 ), '', $var ) ) );
	}
	/**
	 * getREQUEST_URI()
	 */
	protected function getREQUEST_URI() {
		if ( false !== getenv( 'REQUEST_URI' ) && ( false !== ( bool ) $this->string_prop( getenv( 'REQUEST_URI' ), 2 ) ) ) {
			return getenv( 'REQUEST_URI' );
		} else {
			return $_SERVER[ 'REQUEST_URI' ];
		}
	}
	/**
	 * getREMOTE_ADDR()
	 */
	protected function getREMOTE_ADDR() {
		if ( false !== getenv( 'REMOTE_ADDR' ) && ( false !== ( bool ) $this->string_prop( getenv( 'REMOTE_ADDR' ), 7 ) ) && false !== $this->check_ip( getenv( 'REMOTE_ADDR' ) ) ) {
			return getenv( 'REMOTE_ADDR' );
		} elseif ( false !== $_SERVER( 'REMOTE_ADDR' ) && ( false !== ( bool ) $this->string_prop( $_SERVER( 'REMOTE_ADDR' ), 6 ) ) && false !== $this->check_ip( $_SERVER( 'REMOTE_ADDR' ) ) ) {
			return $_SERVER[ 'REMOTE_ADDR' ];
		}
	}
	/**
	 * getQUERY_STRING()
	 */
	protected function getQUERY_STRING() {
		if ( false !== getenv( 'QUERY_STRING' ) ) {
			return strtolower( $this->decode_code( getenv( 'QUERY_STRING' ) ) );
		} else {
			return strtolower( $this->decode_code( $_SERVER[ 'QUERY_STRING' ] ) );
		}
	}
	/**
	 * string_prop()
	 */
	protected function string_prop( $str, $len = 0 ) {
		# is not an array, is a string, is of at least a specified length ( default is 0 )
		if ( false !== is_array( $str ) )
			return false;
		$x = ( is_string( $str ) ) ? ( ( strlen( $str ) >= ( int ) $len ) ? true : false ) : false;
		return ( bool ) $x;
	}
	/**
	 * integ_prop()
	 */
	protected function integ_prop( $integ ) {
		# is an integer, is not a float, is not negative
		# PHP_INT_MAX
		if ( $integ <= PHP_INT_MAX && false !== is_int( $integ ) && false !== preg_match( '/^\d+$/D', $integ ) && ( int ) $integ >= 0 && false !== filter_var( $integ, FILTER_VALIDATE_INT ) ) {
			return true;
		} else {
			return false;
		}
	}
	/**
	 * cmpstr()
	 * @return bool
	 */
	protected function cmpstr( $s, $c, $ci = false ) {
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
	
	protected function instr_url( $string ) {
		return preg_match( "/(?:(?:https?|ftp|file):\/\/|www\.|ftp\.)(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\/%=~_|$])/i", $string );
	}
	
	protected function advanced_mode() {
		if ( false !== ( bool ) $this->_adv_mode ) {
			$this->_banip = 1;
			$this->_nonGETPOSTReqs = 1;
			$this->_spider_block = 1;
			$this->tor2web_block();
		}
	}
} // end of class

// Initialize our plugin object.
global $ParetoSecurity;
if ( class_exists( 'ParetoSecurity' ) && !$ParetoSecurity ) {
	$ParetoSecurity = new ParetoSecurity();
}

function load_pareto_first() {
	$wp_path_to_this_file = preg_replace( '/(.*)plugins\/(.*)$/', WP_PLUGIN_DIR . "/$2", __FILE__ );
	$this_plugin		  = plugin_basename( trim( $wp_path_to_this_file ) );
	$active_plugins		  = get_option( 'active_plugins' );
	$this_plugin_key	  = array_search( $this_plugin, $active_plugins );
	if ( $this_plugin_key ) {
		array_splice( $active_plugins, $this_plugin_key, 1 );
		array_unshift( $active_plugins, $this_plugin );
		update_option( 'active_plugins', $active_plugins );
	}
}
?>
