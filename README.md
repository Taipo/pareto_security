=== Pareto Security ===

Contributors: te_taipo

Donate link: http://hokioisec7agisc4.onion 

Tags: authentication bypass, CRLF, CSRF, cross-site scripting, database security, exploit, firewall security, hack, hacked, hacker, injection, local file inclusion, malware, phishing, rfi, remote file inclusion, scrapers, secure, secure login, security, SQL Injection, vulnerability, WAF, website security, wordpress, wordpress security, xss
Requires at least: 3.0.1
Tested up to: 4.5.2
Stable tag: 1.2.3
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

WordPress core security class: A Web Application Firewall to protect your Wordpress web portal

== Description ==

= Pareto Security Features =

Wordpress has been plagued by plugins that bring with them security vulnerabilities. Users depend on the security skills of 3rd party developers to check all user inputs and to escape all outputs from their plugin code.

However in many many cases this is not done correctly leading to vulnerabilities and often websites being attacked, malware code installed, and in worst cases, entire servers taken over.

Pareto Security class acts as a central security hub checking all inputs from users.

Using the principle of "Artificial Ignorance" with blacklists rather than arbitrary blacklists, Pareto Security method ignores requests it knows aren't interesting and processes the remaining requests that must then be of interest.

Any remaining user inputs/requests are most likely attempts to break rules and are tested against a list of rules, bad requests are prevented from completing their action.

This acts as a "temporary" shield during that period of time between when a vulnerability is discovered in Wordpress or 3rd party plugins, and when they are patched, and, when you update your Wordpress website.

Features:

* Full web application firewall preventing attacks from reaching Wordpress codex
* The most powerful input security plugin on Wordpress for protecting your Wordpress *.php files
* Automatically secures your Wordpress repository against unsecured inputs common in Wordpress 3rd party plugins
* No customisation needed, works silently in the background
* Protects against malicious database injections
* Using the principle of "Artificial Ignorance" with blacklists rather than arbitrary blacklists, processes and checks all user inputs, the REQUEST_URI, QUERY_STRING, _GET, _POST, _COOKIE and browser user-agents to detect known security threats.
* Pareto Security is 100% free
* Prevents uploading of backdoors, arbitrary file includes
* Locks down server error and information messages that can be used to assist attackers
* Scans inputs from content submitted by visitors in comments and posts.
* Block known bad crawlers.
* Checks against malicious Request Types
* Pareto Security is multi-site ready
* Options IP address banning 
* Works silently in the background blocking attacks

A Word on Security:
Keeping a Wordpress CMS secure is not easy. The very best thing you can do to prevent attacks is to always keep your website code, themes and plugins up to date, and remove any plugins and themes you are not using.

What Pareto Security cannot do ( as with any Web Application Firewall ) is save your website from really really badly written site, theme and/or plugin code, or save your site from attacks that result from when WP administrators do not follow basic security measures.

Footnote: Wordfence file scanner will flag pareto_security.php as possibly malicious. You can safely add pareto_security.php to the Wordfence ignore list to prevent future messages.

== Installation ==

* <strong>Automated Setup Steps</strong>

1. Upload `/pareto-security/` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress

== Frequently Asked Questions ==

= Where can I get more information? =

Using the Tor Browser, visit http://hokioisec7agisc4.onion/?p=25 for more information, including support requests

= How can I contribute to the cause =

Donations via Bitcoin to 1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX

= Do you have an email contact? =

Email me at hokioi-security@protonmail.ch

== Changelog ==

= 1.2.3 =
* prevent attempts to esculate user privileges in WP
* Updated functions: send403(), _QUERYSTRING_SHIELD(), _POST_SHIELD(), _REQUESTTYPE_SHIELD(), integ_prop(), get_http_host(), get_filename()

= 1.2.2 =
* Important update addressing arbitrary file includes/uploads
* Updated functions: htaccessbanip(), datalist(), _REQUEST_SHIELD()

= 1.2.1 =
* Updated functions: __construct(), _REQUEST_SHIELD(), _QUERYSTRING_SHIELD(), x_secure_headers()
* Fixed a bug in _SPIDER_SHIELD()

= 1.2.0 =
* Now allows users to enable/disable filtering of spiders/browser user-agents via Pareto Security Settings
* _SPIDER_SHIELD() now tests for database injection attempts

= 1.1.9 =
* Updated functions: _REQUEST_SHIELD(), get_filter(), decode_code(), blacklistMatch(), hCoreFileChk()

= 1.1.8 =
* Updated functions: injectMatch(), _REQUEST_SHIELD(), getDir()
* Fixed minor bug in is_server() and karo() functions

= 1.1.7 =
* Prevent denial of service POST attack on older versions of PHP where the attacker floods webservers with requests to create large multi-leafed arrays on the fly.
* Added ability to restrict the request method to GET or POST in Pareto Security Settings
* Employing a better method of walking through multidimentional arrays
* Removed functions: $PHP_SELF, setReq_uri(), setVars(), hexoctaldecode(), getPHP_SELF(), checkfilename()
* Updated functions: karo(), getDir(), getRealIP() and getPHP_SELF(), _REQUEST_SHIELD()
* Added functions: getREMOTE_ADDR(), string_prop() and integ_prop(), decode_code() 

= 1.1.6 =
* update file checking method
* updated _REQUESTTYPE_SHIELD()
* updated karo()
* updated byPass()
* removed getHTAccesspath(), bypass() and send404()

= 1.1.5 =
* adding in comments
* removed duplicate code (osCommerce admin bypass block)
* update to blacklists

= 1.1.4 =
* Updated blacklists

= 1.1.3 =
* Added 'X-Content-Type-Options: nosniff' security header
* Removed 'Quirky Wordpress Exploit' as it is no longer relevant
* Removed PHP 4.x code
* Updated blacklists
* Added pareto_security.php to the file bypass list

= 1.1.2 =
* Update to database injection filters
* Code rearrangement to lower server CPU usage
* Added further detection for SSRF attacks

= 1.1.1 =
* Fixed issue with settings loading incorrectly

= 1.1.0 =
* Added items to blacklists.
* Amended secure browser headers
* Fixed an issue in settings that caused issues with Avada theme.

= 1.0.9 =
* Make all preg_match case insensitive
* Prevent XSS via cookie authentication vulnerability in PHP ( see https://bugs.php.net/bug.php?id=69892 )

= 1.0.8 =
* Block access to Apache Server-Status
* Removed open_basedir() controls to avoid confusion

= 1.0.7 =
* Added items to the blacklist
* Removed an item from the _POST blacklist causing false positives

= 1.0.6 =
* Fixed a bug that might prevent the admin settings from being applied

= 1.0.5 =
* Removed the noHTML() function

= 1.0.4 =
* Fixed a bug in $this->getDir()

= 1.0.3 =
* Added settings to wp-admin/settings.

= 1.0.2 =
* Made Wordpress plugin compatible.

= 1.0.0 =
* Converted from osC_Sec to Pareto_Security.php

== Upgrade Notice ==

= 1.0 =
Upgrade notices describe the reason a user should upgrade.  No more than 300 characters.
