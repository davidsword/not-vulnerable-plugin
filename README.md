# Not Vulnerable Plugin

This is my take on securing the [Intentionally Vulnerable Plugin](https://make.wordpress.org/plugins/2013/04/09/intentionally-vulnerable-plugin/). For anyone unaware, the Intentionally Vulnerable Plugin is a security code challenge from WordPress that highlights and showcases common security vulnerabilities and mis-steps that may occur in WordPress plugins and themes. I've gone through the plugin, cleaned up the code and fixed all the security holes.

## My Changes

Please keep in mind that I've edited this plugin as a _collaborator_ as well as a _security auditor_.

-   As a collaborator: I've made some structural changes intentionally to have a better codebase and keep up to WordPress standards.

-   As an auditor:  I've highlighted any critical security changes (the whole point of this challenge) with inline blockdoc with emoji symbols, like so:

```
/**
 * ✅🔒 SECURE (#reference number): (explanation)
 *
 * Prevents (category of security hole).
 *
 * (elaboration, and optional demo of how-to exploit if not done)
 *
 * @link (source code link to the original vulnerable code)
 */
(secured code)
```

All functions have kept their `dvp_` prefix for easier reference.

## Change Log

### 1.0.0

**SECURITY**

Cross-site scripting (XSS):
-   Added: Escaped all i11n strings with `esc_html_*` (incase translator compromised).
-   Added: Escaped all variables and output with `esc_*` (incase database, theme, or plugin compromised).
-   Added: Escape on `add_query_arg()` output (to prevent XSS attacks with `PHP_SELF`).
-   Added: Escaped, verified, and validated all user input.
-   Changed: Validated user supplied IP address for storage

SQL Injection:
-   Changed: Used `$wpdb->delete()` instead of vulnerable `$wpdb->query("DELETE ... esc_sql())`.
-   Changed: Use `$wpdb->prepare` instead of `esc_sql()` to properly escape values in `SELECT` query.
-   Changed: Improper database `->query("INSERT..` to use proper `->insert(..` method

Cross-site Request Forgery :
-   Changed: Used `wp_verify_none()` instead of `check_admin_referer()` as the later returns false and doesn't use custom nonce names which can result in coding mistakes that can lead to unintended access andor running of code.

Redirects:
-   Changed: Use `wp_safe_redirect()` instead of `wp_redirect()`.
-   Changed: Used hard coded redirect instead of doubly exploitable `input[name=redirect]{$_SERVER['PHP_SELF']}` value.

Bad Coding:
-   Changed: `dvp_change_settings()`'s' enormous security hole that made the entire `\_options` table vulnerable to injection and alteration (looping through user-supplied array dynamically - see inline doc for full details).
-   Changed: Uses `wp_login_failed` hook instead of `wp_authenticate_user` to process already-confirmed-failed log ins (instead of handling the plain-text password).
-   Removed: Plain text password logging and validating for plugin. Unnecessary and storing plain text password.

Misconfiguration:
-   Added: `index.php` with _"silence is golden"_ message to prevent directory exploit.
-   Added: `ABSPATH` constant check to insure files not loaded directly.
-   Added: `Requires PHP: 5.6` restriction to force users to upgrade their servers.

For full details of security changes and additions, please read inline doc in `\*.php` pages.

**CODE CHANGES & STANDARDS**

-   Added: `readme.txt` for proper WordPress plugin rendering.
-   Added: `README.md` file for Github presentation.
-   Added: Internationalization on all text strings, and `/languages/`.
-   Added: Completed functionality of "Ignore known users" settings in logger.
-   Added: Using `$wpdb`'s' `->prefix` &amp; `->get_charset_collate` in `dvp_install()` to properly name and character set the table.
-   Added: Names on blank instances of `wp_nonce_field()` for better understanding of what's where.
-   Added: Conditional check on `dvp_install()`'s initial `update_option` to not overwrite users setting if re-activated.
-   Added: admin_notices on Settings change and log delete.
-   Changed: `ip` database column to `39` character length in for IPv6 support.
-   Changed: Wrapped plugin in classes to prevent any name collisions, as this plugin may already be on reviewers setup.
-   Changed: `vulnerable.php` split into two classes for easier code structure.
-   Changed: All 8-character soft space tabbing to WPCS single hard tabs.
-   Changed: Most instances of repetitive single line `echo "{html}";` converted to actual html.
-   Changed: Code formatting throughout, for consistency and to meet WPCS.
-   Removed: `LOAD_INTENTIONAL_VULNS` constant as its no longer vulnerable.
-   Removed: `dvp_admin_safety_notice()` no need for admin notice, no longer vulnerable.

### 0.1

-   Jon Cave's [initial](https://make.wordpress.org/plugins/2013/04/09/intentionally-vulnerable-plugin/) [vulnerable source code](https://gist.github.com/joncave/5348689) (big shouts for starting this 🙏🏻!!!)


## The Bonus Challenge

> "with access to a subscriber level account can you find any ways of extracting the data from an option named secret_option?"

The line

```
$log = $wpdb->get_row( "SELECT * FROM login_audit WHERE ID = " . esc_sql( $id ), ARRAY_A );
```

is the best way to exploit the database. This function calls the database in `dvp_view_log()` which has no user caps check.

You would inject into the query, doing a `JOIN` for the `\_options` table, where you'd put the options `name` and `value` columns as if they were `login` and `ip` columns.

The data would display in the table as normal, and `secret_option` would be displayed.
