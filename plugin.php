<?php
/**
 * Plugin Name: Not Vulnerable Plugin
 * Version: 1.0.0
 * Plugin URI: https://github.com/davidsword/not-vulnerable-plugin/
 * Description: My take on securing the Intentionally Vulnerable Plugin (a plugin authored for education)
 * Author: David Sword, Jon Cave
 * Author URI: https://davidsword.ca/, http://joncave.co.uk/
 * License: GPLv3+
 * License URI:  https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 4.0.0
 * Tested up to: 4.9.7
 * Text Domain: notv8e
 *
 * See `README.md` for full info.
 *
 * @package Not_Vulnerable_Plugin
 */

/**
 * ✅🔒 SECURE: Prevent direct access.
 *
 * This file may eventually contains some I/O operations which could be
 * triggered by an attacker which might cause unexpected behaviour.
 */
defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'Not_V8e' ) ) {

	/**
	 * Not_V8e
	 */
	class Not_V8e {

		/**
		 * Load the plugin
		 */
		public function __construct() {

			// Install this plugin on activation, this is done before `init`, so no hooks.
			register_activation_hook( __FILE__, array( $this, 'dvp_install' ) );

			require dirname( __FILE__ ) . '/inc/class-not-v8e-admin.php';
			require dirname( __FILE__ ) . '/inc/class-not-v8e-logger.php';

			add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
		}

		/**
		 * Install the plugin by creating a new table if none exists.
		 */
		public function dvp_install() {
			global $wpdb;

			$table_name = $wpdb->prefix . 'login_audit';
			$charset    = $wpdb->get_charset_collate();

			$sql = "CREATE TABLE $table_name (
				ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				login varchar(200) NOT NULL default '',
				ip varchar(39) NOT NULL default '',
				time datetime NOT NULL default '0000-00-00 00:00:00',
				PRIMARY KEY (ID)
			) $charset;";

			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			dbDelta( $sql );

			if ( ! get_option( 'dvp_unknown_logins' ) ) {
				update_option( 'dvp_unknown_logins', 1 );
			}
		}

		/**
		 * Install the plugin by creating a new table if none exists.
		 */
		public function load_textdomain() {
			load_plugin_textdomain( 'notv8e', false, basename( dirname( __FILE__ ) ) . '/languages' );
		}
	}

	// Self loading class.
	new Not_V8e();
}
