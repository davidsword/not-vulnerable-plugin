<?php
/**
 * The admin settings screen: view and controller for plugin.
 *
 * Adds Dashboard menu, list of logs, single logs, plugin settings, and handles log deletion.
 *
 * @since 1.0.0
 * @package Not_Vulnerable_Plugin
 */

/**
 * ✅🔒 SECURE 1: Prevent direct access.
 *
 * Prevents Security Misconfiguration.
 *
 * This file currently doesn't, but may eventually contains some
 * I/O operations when accessed directly via the URL, ie:
 *
 * `example.com/wordpress/wp-content/plugins/not-vulnerable-plugin/inc/class-not-v8e-admin.php`
 *
 * These operations may cause unexpected behaviour which may be
 * exploited by an attacker.
 *
 * (This was not included in the original code).
 */
defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'Not_V8e_Admin' ) ) {

	/**
	 * Views, Controllers, and Models for this plugins settings screen.
	 */
	class Not_V8e_Admin {

		/**
		 * Hook these functions into WordPress at various points.
		 */
		public function __construct() {
			add_action( 'admin_notices', array( $this, 'dvp_admin_msg' ) );
			add_action( 'admin_menu', array( $this, 'dvp_menu' ) );
			add_action( 'admin_post_dvp_settings', array( $this, 'dvp_change_settings' ) );
			add_action( 'admin_post_dvp_delete_log', array( $this, 'dvp_delete_log' ) );
		}

		/**
		 * Add a settings page into the wp-admin dashboard.
		 */
		public function dvp_menu() {
			add_submenu_page(
				'tools.php',
				'Failed Logins',
				'Failed Logins',
				'manage_options',
				'failed-logins',
				array( &$this, 'dvp_admin' )
			);
		}

		/**
		 * Display the failed login(s) in HTML.
		 */
		public function dvp_admin() {
			/**
			 * ✅🔒 SECURE 2: Verify and sanitize user supplied `$_GET` value.
			 *
			 * This function may receive `get=x` query in the address bar, although
			 * this number isn't being used in our database until later. Sanitizing
			 * in here as we validate that it exists and that it is a number is good
			 * practice incase its missed later.
			 *
			 * If not sanitized this number could eventually end up in a unsafe
			 * database query. If the value was set to something like:
			 *
			 * `..&id=1';UPDATE wp_users SET password='5f4dc...cf99' WHERE id=1;`
			 *
			 * We do not need nonce verification on the ID value in this case.
			 *
			 * Prevents Database Injection, XSS attacks, and general misuse.
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L54
			 */
			$log_id = ( isset( $_GET['id'] ) && absint( $_GET['id'] ) ) ? intval( $_GET['id'] ) : false; // Input var okay.

			echo '<div class="wrap">';
			if ( $log_id ) {
				$this->dvp_view_log( $log_id );
			} else {
				$this->dvp_view_all_logs();
			}
			echo '</div>';
		}

		/**
		 * Display all failed login attempts + options form.
		 */
		public function dvp_view_all_logs() {
			global $wpdb;

			$logs = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}login_audit", ARRAY_A );

			echo '<h2>';
			/**
			 * ✅🔒 SECURE 3: Added i11n and escape the string incase translator is compromised.
			 *
			 * Prevents XSS attacks.
			 *
			 * The text was not using translation functions, typically `_*()` is used, however
			 * if the translator was hacked the `_*()` functions could inject HTML and you'd
			 * have a XSS vulnerability. For example, if the translation for 'Failed logins'
			 * was set to:
			 *
			 * `Echec des connexions<script>alert("French Attack!")</script>`
			 *
			 * To stop this, `esc_html_*()` has been added to this and all translatable
			 * strings on the rest of the plugin.
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L66
			 */
			esc_html_e( 'Failed logins', 'notv8e' );
			echo '</h2>';

			if ( empty( $logs ) ) {
				echo '<p>';
				esc_html_e( 'None yet', 'notv8e' );
				echo '</p>';
			} else {
				?>
				<table>
					<thead>
						<tr>
							<td><?php esc_html_e( 'Username', 'notv8e' ); ?></td>
							<td><?php esc_html_e( 'IP address', 'notv8e' ); ?></td>
							<td><?php esc_html_e( 'Time', 'notv8e' ); ?></td>
						</tr>
					</thead>
					<tbody>
				<?php

				foreach ( $logs as $log ) {

					// Below will be escaped later, closer to output.
					$url = add_query_arg( 'id', intval( $log['ID'] ), menu_page_url( 'failed-logins', false ) );
					?>
					<tr>
						<?php
						/**
						 * ✅🔒 SECURE 4: escape database supplied values.
						 *
						 * Prevents XSS attacks.
						 *
						 * Although its assumed things from the database are safe, if the database
						 * ever gets compromised, the values therein could all be compromised
						 *
						 * For example, expecting a string like "Tom" back, but the compromised
						 * database has `<script>alert("Attack!")</script>` appended to all text
						 * values.
						 *
						 * To stop this, again using `esc_html()` to escape any malicious HTML
						 *
						 * Used here and on the rest of the plugin.
						 *
						 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L75
						 */
						?>
						<td><?php echo esc_html( $log['login'] ); ?></td>
						<td><?php echo esc_html( $log['ip'] ); ?></td>
						<td>
							<a href="
							<?php
							/**
							 * ✅🔒 SECURE 5: add nonce token to the source location
							 *
							 * Prevents CSRF attacks.
							 *
							 * When URL is changed, or when posting/getting data from A to B
							 * within our plugin, we need to make sure we truly came from location
							 * A, and didn't just fake it and arrive at B with fake-malicous-data
							 *
							 * Basically a token that authenticates the source to the destination.
							 *
							 * Adding WordPress nonce's to our URLs and forms, then verifying them
							 * at the destination, it prevents any CSRF attacks.
							 *
							 * Although it's a bit overkill here for simply viewing a log, the data
							 * may later contain more sensitive info, andor, the view log page may
							 * loose its caps or other proper authorization check.
							 *
							 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L78
							 */
							$complete_url = wp_nonce_url( $url, 'view-log_' . intval( $log['ID'] ) );

							/**
							 * ✅🔒 SECURE 6: escape `add_query_arg()`
							 *
							 * Prevents XSS attacks.
							 *
							 * `add_query_arg()` be exploited because of the PHP_SELF variable.
							 * PHP_SELF can be hacked with a request similar to:
							 *
							 * `..php/%22%3E%3Cscript%3Ealert('attack!')%3C/script%3E%3Cfoo%22`
							 *
							 * Although we're using this $url as an attribute, using
							 * `esc_url()` is safer than `esc_attr()` for URLs
							 *
							 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L78
							 */
							echo esc_url( $url );
							?>
							"><?php echo esc_html( $log['time'] ); ?></a>
						</td>
					</tr>
					<?php
				}
				?>
					</tbody>
				</table>
				<?php
			}
			?>
			<hr />
			<h3>Settings</h3>
			<form action="admin-post.php?action=dvp_settings" method="post">
				<?php
					wp_nonce_field( 'dvp_settings' );
				?>
				<input
					type="checkbox"
					id="dvp_unknown_logins"
					name="dvp_unknown_logins"
					value="1"
					<?php
						/**
						 * ✅🔒 SECURE 7: escape Core WordPress API values.
						 *
						 * Prevents XSS attacks.
						 *
						 * It's important to escape everything, even database values you
						 * believe would never be touched by anything except your code.
						 *
						 * See above "SECURE 4" for info.
						 *
						 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L92
						 */
						$dvp_unknown_logins = esc_html( get_option( 'dvp_unknown_logins' ) );
						echo checked( 1, $dvp_unknown_logins, false );
					?>
				>
				<label for="dvp_unknown_logins">
					<?php esc_html_e( 'Should login attempts for unknown usernames be logged?', 'notv8e' ); ?>
				</label>

				<?php
					$btn_text = esc_html__( 'Update', 'notv8e' );
					submit_button( $btn_text, 'secondary' );
				?>
			</form>
			<?php
		}


		/**
		 * Update plugin options handler.
		 */
		public function dvp_change_settings() {

			/**
			 * ✅🔒 SECURE 8: verify nonce token at the destination
			 *
			 * Prevents CSRF attacks.
			 *
			 * See "SECURE 5" for more info.
			 *
			 * Use `wp_verify_nonce()` instead of `check_admin_referer()` as the
			 * latter doesn't use nonce names, and may return `false` instead of
			 * `exit`ing the process.
			 *
			 * Failure to add this a admin user could change this setting without
			 * viewing the form it originates from.
			 *
			 * `$_REQUEST['_wpnonce']` should not be checked with !isset(), not
			 * including it would then bypass the nonce completely
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L137
			 */
			if ( ! wp_verify_nonce( $_REQUEST['_wpnonce'], 'dvp_settings' ) ) { // Input var okay.
				// Trigger a specific error for helping user understand their error point.
				return new WP_Error( 'nonce_failure' );
			}

			/**
			 * ✅🔒 SECURE 9: ensure user is authorized
			 *
			 * Prevents Broken Access Control and Sensitive Data Exposure.
			 *
			 * Failure to add this a admin user, as low as subscriber, could change
			 * this setting without viewing the form it originates from.
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L138
			 */
			if ( ! current_user_can( 'manage_options' ) ) {
				wp_safe_redirect( admin_url( 'tools.php?page=failed-logins' ) );
				exit;
			}

			/**
			 * ✅🔒 SECURE 10: Verify and sanitize form fields. Do not insert variable data.
			 *
			 * Prevents Injection, XSS, Sensitive Data Exposure, and a lot more.
			 *
			 * Previously this looped through a `$_POST[options]` array and inserted whatever
			 * user supplied dynamic directly as `key => value` pairs using the `option_update`
			 * method:
			 *
			 * // foreach ( $_POST['option'] as $name => $value )
			 * //  update_option( $name, $value );
			 *
			 * This gave an opportunity to exploit every single value in the _options table`,
			 * a post request with:
			 *
			 * `['option']['site_url'] => 'http://example.com/#attack!'`
			 * `['option']['home_url'] => 'http://example.com/#attack!'`
			 * `['option']['admin_email'] => 'attack@example.com'`
			 *
			 * would break the site in many ways, and direct visitors to attackers site.
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L147
			 */
			$name  = 'dvp_unknown_logins';
			$value = ( ! isset( $_POST[ $name ] ) ) ? 0 : intval( $_POST[ $name ] ); // Input var okay.

			// Update options.
			update_option( $name, $value );

			wp_safe_redirect( admin_url( 'tools.php?page=failed-logins&msg=settings' ) );
		}

		/**
		 * Display a single failed attempt with a form to delete the entry.
		 *
		 * @param int $id The ID of the users log to view.
		 */
		public function dvp_view_log( $id ) {
			global $wpdb;

			/**
			 * ✅🔒 SECURE 11: Ensure $id is sanitized.
			 *
			 * Prevents Injection, XSS, and general miss-use.
			 *
			 * Even though we expect it to be, doing it again incase any other developer
			 * changes anything, we want to escaped as close to the output as possible.
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L101
			 */
			$id = intval( $id );

			/**
			 * ✅🔒 SECURE 12: Use `$wpdb->prepare` to sanitize & escape query
			 *
			 * Prevents Injection (and XSS) attacks, and prevents Sensitive Data Exposure.
			 *
			 * $wpdb->prepare is the standard for escaping data for queries.
			 *
			 * The original code used `esc_sql($id)` instead. `esc_sql()`
			 * does not prevent against injection when quotes are used around it
			 * in a query. So this left it vulnerable to injection. It could be
			 * exploited with a URL like:
			 *
			 * `..&id=1';UPDATE wp_users SET password='5f4dc...cf99' WHERE id=1;`
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L102
			 */
			$log = $wpdb->get_row( $wpdb->prepare( "
				SELECT * FROM {$wpdb->prefix}login_audit
				WHERE ID = %d",
				$id
			), ARRAY_A );

			/*
			 * We're not doing a nonce check here as 1) direct access: admins may share the
			 * URL to each other for referencing. 2) There's functional here to exploit
			 * 3) The caps settings on dvp_admin() prevents non-admins from accessing
			 */
			?>

			<h2>Failed login #<?php echo intval( $id ); ?></h2>
			<div>
				<?php
				$feilds = array(
					'login' => __( 'Username:', 'notv8e' ),
					'ip'    => __( 'IP address:', 'notv8e' ),
					'time'  => __( 'Time of event:', 'notv8e' ),
				);
				foreach ( $feilds as $name => $label ) {
					?>
					<strong><?php echo esc_html( $label ); ?></strong> <?php echo esc_html( $log[ $name ] ); ?><br />
					<?php
				}
				?>
			</div>

			<form action="admin-post.php?action=dvp_delete_log" method="post">
				<?php
					// Properly sets up the action.
					wp_nonce_field( 'dvp_delete_log_' . intval( $id ) );
				?>

				<input type="hidden" name="id" value="<?php echo intval( $id ); ?>" />
				<?php
					$btn_text = esc_html__( 'Delete entry', 'notv8e' );
					submit_button( $btn_text, 'delete' );
				?>
			</form>
			<?php
		}


		/**
		 * Delete entry handler.
		 */
		public function dvp_delete_log() {

			/**
			 * ✅🔒 SECURE 13: use `wp_verify_none()` instead of `check_admin_referer()`
			 *
			 * Prevents CSRF attacks.
			 *
			 * `check_admin_referer()` is not as fool-proof it would only return
			 * `false` if `_wpnonce` wasn't set properly which means the code would
			 * continue to run regardless.
			 *
			 * See "SECURE 8" for more info.
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L123
			 */
			$nonce_action = 'dvp_delete_log_' . intval( $_POST['id'] ); // Input var okay.
			if ( ! wp_verify_nonce( $_REQUEST['_wpnonce'], $nonce_action ) ) { // Input var okay.
				return new WP_Error( 'nonce_failure' );
			}

			/**
			 * ✅🔒 SECURE 14: ensure user is authorized
			 *
			 * See "SECURE 9" for more info
			 *
			 * https://gist.github.com/joncave/5348689#file-vulnerable-php-L124
			 */
			if ( ! current_user_can( 'manage_options' ) ) {
				wp_safe_redirect( admin_url( 'tools.php?page=failed-logins' ) );
				exit;
			}

			$admin_notice = '';

			$log_id = ( isset( $_POST['id'] ) && absint( $_POST['id'] ) ) ? intval( $_POST['id'] ) : false; // Input var okay.

			if ( $log_id ) {
				global $wpdb;
				/**
				* ✅🔒 SECURE 15: Delete row with ->delete() method instead of ->query()
				*
				* Prevents Injection (and XSS attacks).
				*
				* The ->delete() method offers much safer deletion than using ->query(). Much
				* like ->prepare(), the sanitizing of variables is handled by the method and
				* the risks of injection are eradicate.
				*
				* Sanitized ID with `intval()` instead of `esc_sql()`. Even though the method
				* will clean out values, we still want to sanitize them.
				*
				* See "SECURE 12" for more info.
				*
				* @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L127
				*/
				$wpdb->delete(
					$wpdb->prefix . 'login_audit',
					array( 'ID' => $log_id )
				);
				$admin_notice = '&msg=delete';
			}

			/**
			 * ✅🔒 SECURE 16: use `wp_safe_redirect()` instead of `wp_redirect()`
			 *
			 * Prevents XSS.
			 *
			 * Using a hard-coded redirect instead of the using the double-exploitable:
			 *
			 * `value='$_POST['redirect'] = $_SERVER['PHP_SELF']'`
			 *
			 * logic. It's twice as bad as $_SERVER[PHP_SELF] could be exploited
			 * in the address bar with a request like
			 *
			 * ``..php/%22%3E%3Cscript%3Ealert('attack!')%3C/script%3E%3Cfoo%22``
			 *
			 * While $_POST['redirect'] can be exploited by sending a POST request
			 *
			 * ['redirect'] => 'example.com" /><script>alert('attack!')</script><div'
			 *
			 * Added exit incase redirect fails to prevent code running.
			 *
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L130
			 * @link https://gist.github.com/joncave/5348689#file-vulnerable-php-L116
			 */
			wp_safe_redirect( admin_url( 'tools.php?page=failed-logins' . $admin_notice ) );
			exit;
		}

		/**
		 * Show admin notice after change and delete actions.
		 */
		public function dvp_admin_msg() {
			$msg = ( isset( $_GET['msg'] ) ) ? esc_html( $_GET['msg'] ) : false; // Input var okay.

			if ( false === $msg ) {
				return;
			}
			?>
			<div class="notice notice-success is-dismissible">
				<p>
				<?php
				if ( 'delete' === $msg ) {
					echo 'Log successfully deleted.';
				} elseif ( 'settings' === $msg ) {
					echo 'Settings successfully saved.';
				}
				?>
				</p>
			</div>
			<?php
		}

	}

	// Self loading class.
	new Not_V8e_Admin();
}
