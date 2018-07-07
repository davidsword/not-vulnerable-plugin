<?php
/**
 * Logger for plugin: watch for failed log ins and store them
 *
 * @since 1.0.0
 * @package Not_Vulnerable_Plugin
 */

/**
 * ✅🔒 SECURE 16: Prevent direct access.
 *
 * Prevents Security Misconfiguration.
 *
 * This file currently doesn't, but may eventually contains some
 * I/O operations when accessed directly via the URL, ie:
 *
 * `example.com/wordpress/wp-content/plugins/not-vulnerable-plugin/inc/class-not-v8e-logger.php`
 *
 * These operations may cause unexpected behaviour which may be
 * exploited by an attacker.
 *
 * (This was not included in the original code).
 */
defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'Not_V8e_Logger' ) ) {

	/**
	 * Watch for failed log ins and store them.
	 */
	class Not_V8e_Logger {

		/**
		 * Hook into WordPress.
		 */
		public function __construct() {
			add_action( 'wp_login_failed', array( $this, 'dvp_check_login' ), 10, 2 );
		}

		/**
		 * Log failed authentication attempts.
		 *
		 * @param string $user email or username of failed log in attempt.
		 */
		public function dvp_check_login( $user ) {

			$user       = esc_html( $user );
			$known_user = false;
			$log_all    = ( '1' === get_option( 'dvp_unknown_logins' ) ) ? true : false;

			if ( ! $log_all ) {
				$type       = ( is_email( $user ) ) ? 'email' : 'slug';
				$known_user = get_user_by( $type, $user );
			}

			if ( $log_all || $known_user ) {
				$this->dvp_log_failed_login( $user );
			}
		}

		/**
		 * Add a log record for a failed login attempt.
		 *
		 * @param string $user email or username of failed log in attempt.
		 */
		public function dvp_log_failed_login( $user ) {
			global $wpdb;

			$ip   = $this->dvp_get_ip();
			$time = current_time( 'mysql' );

			/**
			 * ✅🔒 SECURE 17: Use ->insert() method instead of ->query()
			 *
			 * Prevents Injection (and XSS attacks).
			 *
			 * The code formerly had ->prepare() but used it incorrectly. The method
			 * works like a sprint_f function, the variables are place held, then
			 * passed as arguments. Regardless, ->query() is not the best method for
			 * inserting data.
			 *
			 * ->insert() used instead.
			 *
			 * @see https://gist.github.com/joncave/5348689#file-vulnerable-php-L42
			 */
			$wpdb->insert(
				$wpdb->prefix . 'login_audit',
				array(
					'login' => $user,
					'ip'    => $ip,
					'time'  => $time,
				),
				array(
					'%s',
					'%s',
					'%s',
				)
			);
		}

		/**
		 * Retrieve the IP address of the current user
		 *
		 * @return string IP address of current user, or a blank one
		 */
		public function dvp_get_ip() {
			/**
			 * ✅🔒 SECURE 18: Validate IP Address
			 *
			 * Prevents Injection (and XSS).
			 *
			 * This User supplied value is being put into queries and the
			 * database, it has to be cleaned and verified that its an IP
			 * address. We will escape it again later, but good to verify
			 * it right away.
			 *
			 * Do not use HTTP_X_FORWARDED_FOR as it can easily be dubbed.
			 *
			 * @see https://gist.github.com/joncave/5348689#file-vulnerable-php-L159
			 */
			if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
				$ip = esc_html( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ); // Input var okay.
			}

			$valid_ip = inet_pton( $ip );

			return ( $valid_ip ) ? $ip : '0.0.0.0';

		}

	}

	// Self loading class.
	new Not_V8e_Logger();
}
