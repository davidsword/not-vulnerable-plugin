# Not Vulnerable Plugin

This is my take on securing the [Intentionally Vulnerable Plugin](https://make.wordpress.org/plugins/2013/04/09/intentionally-vulnerable-plugin/). For anyone unaware, the Intentionally Vulnerable Plugin is a security code challenge from WordPress that highlights and showcases common security vulnerabilities and missteps that may occur in WordPress plugins and themes.

For this challenge, I've gone through the original code, cleaned up the code, fixed all the security holes, and documented points of vulnerability.

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
-   Changed: Used `$wpdb->prepare` properly instead of `"SELECT ... ".esc_sql(` to properly escape values
-   Changed: Used `->insert()` method instead to sanitize and escape variables, instead of vulnerable `$wpdb->query( $wpdb->prepare( "INSERT.. '$var' ..")`.

Cross-Site Request Forgery (CSRF):
-   Changed: Used `wp_verify_none()` instead of `check_admin_referer()` as the later returns false and doesn't use custom nonce names which can result in coding mistakes that can lead to unintended access andor running of code.
-   Changed: logic of `!isset($_REQUEST['_wpnonce'])` conditional which made it bypass-able.

Redirects:
-   Added: `exit` or `return` after redirects to prevent unintended code execution.
-   Changed: Use `wp_safe_redirect()` instead of `wp_redirect()`.
-   Changed: Used hard coded redirect instead of the doubly-exploitable `input[name=redirect]{$_SERVER['PHP_SELF']}` value.

Bad Coding:
-   Changed: `dvp_change_settings()`'s' enormous security hole that made the entire `\_options` table vulnerable to injection and alteration (looping through user-supplied array dynamically - see inline doc for full details).
-   Changed: Uses `wp_login_failed` hook instead of `wp_authenticate_user` to process already-confirmed-failed log ins (instead of validating log in and handling the plain-text password).
-   Removed: Plain text password handling and logging (saving a plain text password can lead to sensitive data exposure with any breach, and violates the users privacy/rights).

Misconfiguration:
-   Added: `index.php` with _"silence is golden"_ message to prevent directory exploit.
-   Added: `ABSPATH` constant check to insure files not loaded directly.
-   Added: `Requires PHP: 5.6` requirement (although it'd be nice to force 7.x on everyone!).

For full details of security changes and additions, please read inline doc in `\*.php` pages.

**CODE CHANGES & STANDARDS**

-   Added: `readme.txt` for proper WordPress plugin rendering.
-   Added: `README.md` file for Github presentation.
-   Added: l10n support on all text strings, and `.pot` in `/languages/`.
-   Added: Completed functionality of "Ignore known users" settings in logger.
-   Added: Names on blank instances of `wp_nonce_field()` for better understanding of what's where.
-   Added: Conditional check on `dvp_install()`'s initial `update_option` to not overwrite users setting if re-activated.
-   Added: `admin_notices` on settings change and log deletion.
-   Changed: Using `$wpdb->prefix` &amp; `->get_charset_collate` in `dvp_install()` to properly name and character set the table.
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

[Line 102](https://gist.github.com/joncave/5348689#file-vulnerable-php-L102):

```
$log = $wpdb->get_row( "SELECT * FROM login_audit WHERE ID = " . esc_sql( $id ), ARRAY_A );
```

Is the vulnerability for a subscriber level account reading the `secrete_option`.

1) This function `dvp_view_log()` has no cap checks, so if the URL was known, a subscriber could access it without verification.

2) The `esc_sql()` function works when wrapped in quotes. It does not properly escape code when used without quotes.

3) The `esc_sql()` function contains `$id` which has a value of unescaped value of `$_GET['id']`.

These three factors, this now means injection is possible.

An attacker could create a request similar to:

```
&id=1 UNION SELECT option_id, option_name, option_value, autoload FROM wp_options
```

Which would create the query:

```
SELECT * FROM wp_login_audit WHERE ID = 1 UNION SELECT option_id, option_name, option_value, autoload FROM wp_options
```

Which would return all of the `options` table contents as if it were the `login_audit` table. The data is merged, returning with the login_audit's column names. The `secret_option` value would be visible in the audit log table in plain text, as if it were a time value.


Note This UNION method works in my case because I've removed the passwords column in `wp_login_audit` for other reasons, so the column counts match. If the column count wasn't the same, with a slightly different query the injection could still work.
