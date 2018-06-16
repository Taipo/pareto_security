=== Pareto Security ===
Contributors: te_taipo
Tags: wordpress security, hack, database security, xss, WAF, CRLF, CSRF, command injection, cross-site scripting, exploit, firewall security, hack, hacked, hacker, injection, authentication bypass, local file inclusion, malware, phishing, rfi, remote file inclusion, scrapers, secure, secure login, security, SQL Injection, vulnerability, WAF, website security, wordpress, security
Requires at least: 4.7.2
Tested up to: 4.9.6
Stable tag: 2.1.0
Donate link: https://hokioisecurity.com
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

WordPress Core Security: Secure your website with real security.

== Description ==

#### PARETO SECURITY FEATURES

Had enough of the security theatre presented by the raft of Wordpress security plugins? Time to put a stop to the attacks!

Firstly Wordpress and most other CMS's are built using PHP. PHP is a very insecure programming language, even worse in the hands of amateurs.

Wordpress has been plagued by plugins authored by amateurs that bring with them security vulnerabilities.

Security plugin designers mostly focus on cleaning up attacks rather than stopping them dead in their tracks.

Pareto Security class acts as a Central Security Hub checking all inputs from users, preventing bad requests from executing on your website.

* Real Attack Prevention that can be achieved via a plugin
* Automatic Blacklist Management
* Easy-To-Use
* No customisation needed
* Works silently, you only get notified when you really want to be notified
* Completely Free
* and much more...

#### PARETO SECURITY PROTECTION
* Pareto Security Protection identifies and blocks malicious traffic.
* Pareto Security Protection dynamic IP Blacklist protects your site while reducing load.
* Protects your site at the entry-point, disabling attack peneration of your WordPress site.
* Extends Wordpress inbuilt security, defends your website against vulnerabilities added in via bad plugin coding.

#### PARETO SECURITY TOOLS
* Monitor blocked attack attempts
* Optionally receive notifications of *REAL* attack attempts that Pareto Security has blocked

= A Word on Security: =
By the very nature of plugins, no plugin should ever claim to be a Web Application Firewall.

No security plugin can save your website from really-really badly written site, theme and/or plugin code.

No security plugin can save your site from attacks that result from when administrators do not follow basic security practices.

Keeping any CMS as secure as possible is not easy. The very best thing you can do to prevent attacks is to always keep your website code, themes and plugins up to date, and remove any plugins and themes you are not using.

== Installation ==

* <strong>Automated Setup Steps</strong>

1. Upload `/pareto-security/` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress

== Frequently Asked Questions ==

= How does Pareto Security protect sites from attackers? =

The Pareto Security developers understand how PHP - the coding language in which Wordpress is written in, can be exploited. Pareto Security principles of protection stop these attacks at the entry point.

= How does the Pareto Security Protection work? =

* Pareto Security Protection stops you from getting hacked by identifying malicious requests before they can access your website.
* Unlike other very popular plugins, Pareto Security prevents malicious files from being uploaded into your Wordpress site
* Optionally prevents vulnerability scanners like WPScan from probing your websites defenses.

= What checks does the Pareto Security Scanner perform? =

* Scans all input requests (GET, POST, REQUEST, COOKIES) for malicious intent. If an input validation application  does this well, there is no need to then scan files in your website file repository - They should never be there in the first place!

= What security monitoring features does Pareto Security include? =

* A log of *real* attack attempts that were blocked by Pareto Security
* An optional log of medium and low risk attack that were prevented from executing on your Wordpress site

= How will I be alerted if my site has a security problem? =

Pareto Security sends attack alerts via email. Once you install Pareto Security you can enabled email notifications. You will never be flooded with notifications as Pareto Security only sends notifications of high r-sk attacks *that have been blocked*.

= Do I need other security plugins or cloud based firewalls? =

Pareto Security provides true entry-point security for your WordPress website. Pareto Security does not prevent or have conflict with other webserver security addons and hardware web application firewalls.

= What blocking features does Pareto Security include? =

* Real-time blocking of attackers and repeat attackers.
* Prevents vulnerability scanners from scanning your wordpress website

= What differentiates Pareto Security from other WordPress Security plugins? =

* Pareto Security provides real security minus the scare-ware techniques used by other plugins
* Pareto Security picks up security where Wordpress developers draw their line
* Pareto Security prevents attackers making changes to website code by securing all inputs from the start.
* Using the principle of "Artificial Ignorance" with blacklists rather than relying solely on arbitrary blacklists, Pareto Security method ignores requests it knows aren't interesting and processes the remaining requests that must then be of interest.
* Pareto Security fully supports WordPress Multi-Site 

= How can I contribute to the cause =

Donations via:
* Bitcoin: 1HnQtSEXZXvL6sfgXRZ8sAhVmtMtwXfSyf
* ZCASH Address: t1Lnmn4r9jVxhjhTLix8sRfyoqqsJVbShQ1
* Vericoin: VRsjYZmjpYxXmhRxGzYcECfpNUksvBr25v
* Ethereum: 0xb9f7a75530ef6b4b21c721a81fe54c548492f9bf
* Paypal Address: pareto-security@protonmail.com

= Do you have an email contact? =

Email me at pareto-security@hokioisecurity.com

Other contacts: https://taipo.github.io/contact/

== Changelog ==

= 2.1.0 =
* Update to POST Filters
* Extend length of log entry to 500 characters
* Fixed small bug in way the email report displays
* Added Settings link to WP plugin page
* Now checks for and filters $HTTP_RAW_POST_DATA raw post data for XMLRPC
* Better descriptions of attack types

= 2.0.9 =
* Update database injections to reduce false positives

= 2.0.8 =
* Enable XML-RPC Flood Protection
* Further work on HTTP_HOST filtering

= 2.0.7 =
* code cleanup

= 2.0.6 =
* Improve HTTP HOST detection
* Fixed a bug in flood controls for failed logins

= 2.0.5 =
* Reset error reporting to production settings

= 2.0.4 =
* Update the layout of the logfile
* Code cleanup
* Fix the way the email report displays in some email apps

= 2.0.3 =
* * Code cleanup

= 2.0.2 =
* Fixed reported error message for identifying the server ip address
