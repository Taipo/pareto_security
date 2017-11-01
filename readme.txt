=== Pareto Security ===
Contributors: te_taipo
Tags: wordpress security, hack, database security, xss, WAF, CRLF, CSRF, command injection, cross-site scripting, exploit, firewall security, hack, hacked, hacker, injection, authentication bypass, local file inclusion, malware, phishing, rfi, remote file inclusion, scrapers, secure, secure login, security, SQL Injection, vulnerability, WAF, website security, wordpress, security
Requires at least: 4.0.1
Tested up to: 4.8.3
Stable tag: 1.8.3
Donate link: https://hokioisecurity.com
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

WordPress Core Security: Secure your website with real security.

== Description ==

= Pareto Security Features =

Had enough of the security theatre presented by the raft of Wordpress security plugins? Time to put a stop to the attacks!

Firstly Wordpress and most other CMS's are built using PHP. PHP is a very insecure programming language, even worse in the hands of amateurs.

Wordpress has been plagued by plugins authored by amateurs that bring with them security vulnerabilities.

Wordpress users depend on the security skills of these 3rd party developers to check all user inputs and to escape all outputs from their plugin code.

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

See: https://hokioisecurity.com/?p=343 for further descriptions

A Word on Security:
Keeping any CMS as secure as possible is not easy. The very best thing you can do to prevent attacks is to always keep your website code, themes and plugins up to date, and remove any plugins and themes you are not using.

What Pareto Security cannot do ( as with any Web Application Firewall ) is save your website from really really badly written site, theme and/or plugin code, or save your site from attacks that result from when administrators do not follow basic security practices.

Pareto Security does not claim to prevent all PHP related attack vectors either. It does however attempt to do it better than most addons/plugins that do claim to be the end all of PHP security.

Pareto Security is written by an ex-attacker who intimately knows the mindset of attackers and therefore how to prevent them launching most attacks on Wordpress code.

Footnote 1: Wordfence file scanner may flag pareto_security.php as possibly malicious. You can safely add pareto_security.php to the Wordfence ignore list to prevent future messages.

== Installation ==

* <strong>Automated Setup Steps</strong>

1. Upload `/pareto-security/` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress

== Frequently Asked Questions ==

= Where can I get more information? =

Visit https://hokioisecurity.com/?p=17 or using the Tor Browser, visit http://hokioisec7agisc4.onion/?p=17 for more information, including support requests

= How can I contribute to the cause =

Donations via Bitcoin to 1LHiMXedmtyq4wcYLedk9i9gkk8A8Hk7qX

= Do you have an email contact? =

Email me at pareto-security@hokioisecurity.com

Other contacts: https://taipo.github.io/contact/

== Changelog ==

= 1.8.3 =
* Improve detection of WP administrator
* Detect and prevent attempts to bypass Mod_Security

= 1.8.2 =
* Fixed error in email report
* Protect admin from being banned

= 1.8.0 =
* Added a simple email alert for High Severity attacks
* Better prevention of Wordpress Admin's IP address from being banned
