<?php

	if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) || ! WP_UNINSTALL_PLUGIN ||
	       dirname( WP_UNINSTALL_PLUGIN ) != dirname( plugin_basename( __FILE__ ) ) ) {
		   header( 'Status: 403 Forbidden' );
		   header( 'HTTP/1.1 403 Forbidden' );
		   exit();
	}

	require_once( 'pareto_security.php' );
	
	$fpath =  str_replace( "wp-content/", "", $ParetoSecurity->getDir() . DIRECTORY_SEPARATOR . '.htaccess' );
	
	if ( false !== $ParetoSecurity->get_file_perms( $fpath, true, true ) ) remove_htaccess_bans( $fpath );

	function remove_htaccess_bans( $fpath ) {
		$mybans = file( $fpath );
		
		while( strpos( implode( $mybans, '' ), 'Pareto Security Ban' ) ) {
			foreach( $mybans as $key => $val ) {
				if ( false !== strpos( $val, "Pareto Security Ban" ) && false !== strpos( $val, "# " ) && ( false === strpos( $val, " End of" ) ) ) {
					$srem = $key;
				}
				if ( false !== strpos( $val, " End of" ) && false !== strpos( $val, "Pareto Security Ban" ) ) {
					$erem = $key;
				}
			};
			foreach( $mybans as $key => $val ) {
				if ( ( $key >= $srem ) && ( $key <= $erem ) ) {
					if ( false !== strpos( $val, "Pareto Security Ban" ) ||
						 false !== strpos( $val, "order allow,deny" ) ||
						 false !== strpos( $val, "deny from " ) ||
						 false !== strpos( $val, "allow from all" ) ) {
						 unset( $mybans[ $key ] );
					}
				} else continue;
			}
		}
		$mybans = array_values( $mybans );

		$myfile = fopen( $fpath, 'w' );
		fwrite( $myfile, implode( $mybans, '' ) );
		fclose( $myfile );
	}
?>
