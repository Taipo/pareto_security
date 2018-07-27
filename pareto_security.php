<?php
/*
Plugin Name: Pareto Security
Plugin URI: https://hokioisecurity.com/?p=17
Description: Core Security - Protection from a range of attacks against Content Management Systems (CMS)
Author: Te_Taipo
Version: 2.1.2
Requirements: Requires at least PHP version 5.2.0
Author URI: https://hokioisecurity.com
Donations via: https://hokioisecurity.com/donations/
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

if ( false !== $ParetoSecurity->is_wp() ) {
    register_activation_hook( __FILE__, array(
         $ParetoSecurity,
        '_activate' 
    ) );
    register_deactivation_hook( __FILE__, array(
         $ParetoSecurity,
        '_deactivate' 
    ) );
    require_once( 'pareto_settings.php' );
    $ParetoSecurity = new pareto_settings();
    $ParetoSecurity->_time_offset = ( int ) get_option( 'gmt_offset' );
}

$ParetoSecurity->advanced_mode( $ParetoSecurity->_adv_mode );
$ParetoSecurity->do_security_settings();
# load data from XML
$ParetoSecurity->load_lists( true, true );
# Shields Up
$ParetoSecurity->_QUERYSTRING_SHIELD();
$ParetoSecurity->_POST_SHIELD();
$ParetoSecurity->_REQUEST_SHIELD();
$ParetoSecurity->_LOGIN_SHIELD();
$ParetoSecurity->_HTTPHOST_SHIELD();
$ParetoSecurity->_COOKIE_SHIELD();
$ParetoSecurity->_SPIDER_SHIELD();
