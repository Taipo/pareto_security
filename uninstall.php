<?php

	require_once( 'pareto_functions.php' );
	$ParetoSecurity = new pareto_functions();
	if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) || ! WP_UNINSTALL_PLUGIN ||
	       dirname( WP_UNINSTALL_PLUGIN ) != dirname( plugin_basename( __FILE__ ) ) ) {
		   $ParetoSecurity->send444();  	   
	}	
	if ( function_exists( 'is_admin' ) && false !== is_admin() ) {
		# reset custom settings to off
		# delete log files
		if ( false !== $ParetoSecurity->get_file_perms( $ParetoSecurity->htapath(), true, true ) ) $ParetoSecurity->htaccess_unbanip();
	} else $ParetoSecurity->send444();
?>
