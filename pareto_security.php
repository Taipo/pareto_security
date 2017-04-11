<?php
/*
Plugin Name: Pareto Security
Plugin URI: https://hokioisecurity.com/?p=17
Description: Core Security Class - Defense against a range of common attacks such as database injection
Author: Te_Taipo
Version: 1.4.0
Requirements: Requires at least PHP version 5.2.0
Author URI: https://hokioisecurity.com
BTC:1Ae77P7W3BrHJozD4J5awmHJM18LAereGT
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

	spl_autoload_register(
			function ( $class_name ) {
					include( $class_name . '.php' );
			}
	);
	$pfunk = new pareto_functions();
	
	if ( defined( 'WP_PLUGIN_DIR' ) ) {
		if ( !function_exists( 'is_admin' ) ) $pfunk->send403();
		# Set Pareto Security as the first plugin loaded
		add_action( "activated_plugin", "load_pareto_first" );
		$ParetoSettings = new pareto_settings();
		$pfunk->_adv_mode = isset( $ParetoSettings->advmode ) ? $ParetoSettings->advmode : $pfunk->_adv_mode;
		if ( ( false !== function_exists( 'is_admin' ) && false !== is_admin() ) && false !== $pfunk->cmpstr( 'POST', $_SERVER[ 'REQUEST_METHOD' ] ) && false === ( bool ) $pfunk->_adv_mode && $pfunk->get_filename() == 'options.php' ) $pfunk->htaccess_unbanip();
	}
	$pfunk->advanced_mode();
	$pfunk->_set_error_level();
	# if open_basedir is not set in php.ini then set it in the local scope
	$pfunk->setOpenBaseDir();
	# Send secure headers
	$pfunk->x_secure_headers();
	# Set IP
	$pfunk->_ip = $pfunk->getRealIP();
	# Merge $_REQUEST with _GET and _POST excluding _COOKIE data
	$_REQUEST = array_merge( $_GET, $_POST );
	# Shields Up
	$pfunk->_QUERYSTRING_SHIELD();
	$pfunk->_POST_SHIELD();
	$pfunk->_REQUEST_SHIELD();
	$pfunk->_COOKIE_SHIELD();
	$pfunk->_REQUESTTYPE_SHIELD();
	$pfunk->_SPIDER_SHIELD();
?>
