If you wish to use this outside of Wordpress just upload the files to their own folder (example /pareto_security/* and use the following code somewhere near the top of your code execution:

``require_once( 'pareto_security/pareto_security.php' );``

Note: the admin controls are only available when used in Wordpress as a plugin. Without Wordpress, Pareto Security fireall defenses still work as they do in Wordpress via the default settings, however other advanced features are not enabled by default.

To install in Wordpress just go to the plugin section and search for Pareto Security.

=== Pareto Security ===
Contributors: @te_taipo
Tags: wordpress security, hack, database security, xss, WAF, CRLF, CSRF, command injection, cross-site scripting, exploit, firewall security, hack, hacked, hacker, injection, authentication bypass, local file inclusion, malware, phishing, rfi, remote file inclusion, scrapers, secure, secure login, security, SQL Injection, vulnerability, WAF, website security, wordpress, security
Donate link: https://hokioisecurity.com/donations/
Requires at least: 5.2.0
Tested up to: 5.8.1
Requires PHP: 5.6.0
Stable tag: 2.9.7.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

WordPress Core Security: Secure your website with real security.

== Description ==
#### PARETO SECURITY FEATURES

Had enough of the security theatre presented by the raft of Wordpress security plugins? Time to put a stop to the attacks!

Firstly Wordpress and most other CMS\'s are built using PHP. PHP is a very insecure programming language, even worse in the hands of amateurs.

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
* [disabled] Optionally prevent Tor users/bots from interacting with login forms and search functions of your site while still allowing them to *view* your site.
* Optionally only allow standard web clients and trusted crawlers to access your website, discouraging others from doing so.

#### PARETO SECURITY TOOLS
* Monitor blocked attack attempts
* Optionally receive notifications of *REAL* attack attempts that Pareto Security has blocked

= A Word on Security: =
By the very nature of plugins, no plugin should ever claim to be a Web Application Firewall.

No security plugin can save your website from really-really badly written site, theme and/or plugin code.

No security plugin can save your site from attacks that result from when administrators do not follow basic security practices.

Keeping any CMS as secure as possible is not easy. The very best thing you can do to prevent attacks is to always keep your website code, themes and plugins up to date, and remove any plugins and themes you are not using.

== Installation ==
* Automated Setup Steps

1. Upload `/pareto-security/` to the `/wp-content/plugins/` directory
2. Activate the plugin through the \'Plugins\' menu in WordPress

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

Pareto Security sends attack alerts via email. Once you install Pareto Security you can enabled email notifications. You will never be flooded with notifications as Pareto Security only sends notifications of high risk attacks *that have been blocked*.

= Do I need other security plugins or cloud based firewalls? =

Pareto Security provides true entry-point security for your WordPress website. Pareto Security does not prevent or have conflict with other webserver security addons and hardware web application firewalls.

= What blocking features does Pareto Security include? =

* Real-time blocking of attackers and repeat attackers.
* Prevents vulnerability scanners from scanning your wordpress website

= What differentiates Pareto Security from other WordPress Security plugins? =

* Pareto Security provides real security minus the scare-ware techniques used by other plugins
* Pareto Security picks up security where Wordpress developers draw their line
* Pareto Security prevents attackers making changes to website code by securing all inputs from the start.
* Using the principle of \"Artificial Ignorance\" with blacklists rather than relying solely on arbitrary blacklists, Pareto Security method ignores requests it knows aren\'t interesting and processes the remaining requests that must then be of interest.
* Pareto Security fully supports WordPress Multi-Site 

= How can I contribute to the cause =

Donations via:
Go to https://hokioisecurity.com/donations/

= Do you have an email contact? =

Email me at pareto-security@hokioisecurity.com

Other contacts: https://taipo.github.io/contact/

== Changelog ==

== 2.9.7.1
* Bug fix for when either Cloudflare or Quick Cloud are unable to be reached, causing logfile errors
* Added IPv6 support for Cloudflare ip addresses

== 2.9.7 ==
* Added extra protection to prevent server ip address bans
* Updated QuicCloud ip list
* Added function to manually disable writing ip addresses to the htaccess file

== 2.9.6 ==
* added post filters for reverse powershell injection code
* added post filters for exploit CVE-2021-26084
* small bug causing PS to detect Tor when the tor switch was not enabled in settings

== 2.9.5 ==
* Filter for new controlcharacter attacks
* Trim down the non-wp logging function
* Removed SAMEORIGIN from X-Frame-Options header 

== 2.9.4 ==
* Improve htaccess formatting

== 2.9.3 ==
* Improve the cleanup when PS is deactivated

== 2.9.2 ==
* Fixed issues when using multisites and the TOR Check
* FIxed issue where Tor_Check was incorrectly triggered

== 2.9.1 ==
* Pareto Security will now ban attack attempts against wp-admin/* files (whereas prior to this it blocked such requests without banning the IP address)
* Fixed a bug that would prevent IP addresses from being banned, leaving the request blocked only (attack is still prevented)
* On DNS timeout of the Tor Check now redirects to the homepage
* Update cloudflare and quic-cloud server IP lists

== 2.9.0 ==
* Add more Tor Checks
* Improve detection of authorised users to prevent false positives
