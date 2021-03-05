<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'mikkelbjoernsholm_nuwordpress' );

/** MySQL database username */
define( 'DB_USER', 'mikkelbjoernsholm_nuwordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', 'fjxFEr-SG64uvJXTsx5I' );

/** MySQL hostname */
define( 'DB_HOST', 'mikkelbjoernsholm.nu.mysql.service.one.com' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         's8k1mEqW3VpUvHrlpMYLURaq0SG8_V-sk1DR_xTq1c8=' );
define( 'SECURE_AUTH_KEY',  'lKKM-M9WvkA98Gk2003FLd1jcLsyeAI7iqpopbnteJE=' );
define( 'LOGGED_IN_KEY',    '24Q-nyZGBYqZUgok_Nwxd_2j86L4DvBp--PgLRQ3cUo=' );
define( 'NONCE_KEY',        'inao8dL6WnRgiP1ojCmCTf1kwXaRQzYGdg-K4KOiT8Y=' );
define( 'AUTH_SALT',        'FyefvKOXtIMJc1P4x70sz1pWH4MuvnqBzgZ6IJjNfvw=' );
define( 'SECURE_AUTH_SALT', 'QA4i6KvfYUW0_oOLL7It2Hqou1YuY9278I76ravBMDU=' );
define( 'LOGGED_IN_SALT',   'eIPRuqammTq7XTjlwKBmXglaBeHBfDYACHhMOkPI710=' );
define( 'NONCE_SALT',       'EbmIyAtoe1xwQNPEVqpgVH7GDbAR544ziFc7-z4m8sg=' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * WordPress Localized Language, defaults to English.
 *
 * Change this to localize WordPress. A corresponding MO file for the chosen
 * language must be installed to wp-content/languages. For example, install
 * de_DE.mo to wp-content/languages and set WPLANG to 'de_DE' to enable German
 * language support.
 */
define( 'WPLANG', 'da_DK' );

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the Codex.
 *
 * @link https://codex.wordpress.org/Debugging_in_WordPress
 */
define( 'WP_DEBUG', false );

/**
 * Prevent file editing from WP admin.
 * Just set to false if you want to edit templates and plugins from WP admin.
 */
define('DISALLOW_FILE_EDIT', false);

/**
 * API for One.com wordpress themes and plugins
 */
define('ONECOM_WP_ADDONS_API', 'https://wpapi.one.com');

/** 
 * Client IP for One.com logs
 */
if (getenv('HTTP_CLIENT_IP')){$_SERVER['ONECOM_CLIENT_IP'] = @getenv('HTTP_CLIENT_IP');}
else if(getenv('REMOTE_ADDR')){$_SERVER['ONECOM_CLIENT_IP'] = @getenv('REMOTE_ADDR');}
else{$_SERVER['ONECOM_CLIENT_IP']='0.0.0.0';}

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
