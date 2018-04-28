<?php
	/**
	 * uninstall version 1.8.7
	 */
	require_once( 'pareto_functions.php' );
	$ParetoSecurity = new pareto_functions();
	if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) || ! WP_UNINSTALL_PLUGIN ||
	       dirname( WP_UNINSTALL_PLUGIN ) != dirname( plugin_basename( __FILE__ ) ) ) {
		   $ParetoSecurity->send444();  	   
	}	
	if ( false !== $ParetoSecurity->is_wp( true ) ) {
		if ( false !== $ParetoSecurity->get_file_perms( $ParetoSecurity->htapath(), true, true ) ) $ParetoSecurity->htaccess_unbanip();
	} else $ParetoSecurity->send444();
?>
