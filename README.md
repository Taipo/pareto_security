=== Pareto Security ===

Contributors: te_taipo

Donate link: http://hokioisec7agisc4.onion 

Tags: authentication bypass, CRLF, CSRF, command injection, cross-site scripting, database security, exploit, firewall security, hack, hacked, hacker, injection, local file inclusion, malware, phishing, rfi, remote file inclusion, scrapers, secure, secure login, security, SQL Injection, vulnerability, WAF, website security, wordpress, wordpress security, xss

Requires at least: 3.0.1

Tested up to: 4.6.1

Stable tag: 1.3.5

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
* Protects against malicious command and database injections
* Using the principle of "Artificial Ignorance" with blacklists rather than arbitrary blacklists, processes and checks all user inputs, the REQUEST_URI, QUERY_STRING, _GET, _POST, _COOKIE and browser user-agents to detect known security threats.
* Pareto Security is 100% free
* Prevents uploading of backdoors, arbitrary file includes
* Locks down server error and information messages that can be used to assist attackers
* Scans inputs from content submitted by visitors in comments and posts.
* Block known bad crawlers.
* Checks against malicious Request Types
* Pareto Security is multi-site ready
* Optional IP address banning 
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

Other contacts: https://github.com/Taipo/contact-details

== Changelog ==

= 1.3.5 =
* Updated blacklists

= 1.3.4 =
* Fixed a bug in updated injection filters

= 1.3.3 =
* Added 444 No Response header for bots
* No longer exit when UA is empty
* Major update to database injection filters

= 1.3.2 =
* Update to Tor2Web block for advanced mode fixing possible false positives.

= 1.3.1 =
* Added optional Tor2Web block for advanced mode

= 1.3.0 =
* Fixed potential bug where large post data could result in 500 error
