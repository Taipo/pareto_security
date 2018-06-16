<?php
/*
Plugin Name: Pareto Security
Plugin URI: https://hokioisecurity.com/?p=17
Description: Core Security Class - Defense against a range of common attacks such as database injection
Author: Te_Taipo
Version: 2.1.0
Requirements: Requires at least PHP version 5.2.0
Author URI: https://hokioisecurity.com
Bitcoin: 1HnQtSEXZXvL6sfgXRZ8sAhVmtMtwXfSyf
ZCASH Address: t1Lnmn4r9jVxhjhTLix8sRfyoqqsJVbShQ1
Vericoin: VRsjYZmjpYxXmhRxGzYcECfpNUksvBr25v
Ethereum: 0xb9f7a75530ef6b4b21c721a81fe54c548492f9bf
Paypal Address: pareto-security@protonmail.com
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
require_once( 'pareto_functions.php' );
$ParetoSecurity = new pareto_functions();
if ( false !== $ParetoSecurity->is_wp( false ) ) {
    require_once( 'pareto_settings.php' );
    $ParetoSecurity = new pareto_settings();

    register_activation_hook( __FILE__, array(
         $ParetoSecurity,
        '_activate' 
    ) );
    register_activation_hook( __FILE__, array(
         $ParetoSecurity,
        '_deactivate' 
    ) );
}

$ParetoSecurity->advanced_mode( $ParetoSecurity->_adv_mode );
$ParetoSecurity->do_security_settings();
# Shields Up
$ParetoSecurity->_QUERYSTRING_SHIELD();
$ParetoSecurity->_POST_SHIELD();
$ParetoSecurity->_REQUEST_SHIELD();
$ParetoSecurity->_LOGIN_SHIELD();
$ParetoSecurity->_HTTPHOST_SHIELD();
$ParetoSecurity->_COOKIE_SHIELD();
$ParetoSecurity->_SPIDER_SHIELD();
?>
