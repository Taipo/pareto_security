<?php
/**
 * uninstall version 2.1.0
 */
require_once( 'pareto_functions.php' );
$ParetoSecurity = new pareto_functions();
if ( !defined( 'WP_UNINSTALL_PLUGIN' ) || !WP_UNINSTALL_PLUGIN || dirname( WP_UNINSTALL_PLUGIN ) != dirname( plugin_basename( __FILE__ ) ) ) {
    $ParetoSecurity->send444();
}
if ( !is_user_logged_in() ) {
    wp_die( 'You must be logged in to run this script.' );
	$ParetoSecurity->send444();
}
if ( !current_user_can( 'install_plugins' ) ) {
    wp_die( 'You do not have permission to run this script.' );
	$ParetoSecurity->send444();
}

if ( false !== $ParetoSecurity->is_wp( true ) ) {
    if ( false !== $ParetoSecurity->get_file_perms( $ParetoSecurity->htapath(), true, true ) )
        $ParetoSecurity->htaccess_unbanip();
} else
    $ParetoSecurity->send444();
?>
