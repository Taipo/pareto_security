=== Pareto Security ===

Contributors: @te_taipo

Tags: wordpress security, hack, database security, xss, WAF, CRLF, CSRF, command injection, cross-site scripting, exploit, firewall security, hack, hacked, hacker, injection, authentication bypass, local file inclusion, malware, phishing, rfi, remote file inclusion, scrapers, secure, secure login, security, SQL Injection, vulnerability, website security, wordpress, security

Donate link: https://hokioisecurity.com/donations/
Requires at least: 4.7.2
Tested up to: 5.0.3
Requires PHP: 5.3
Stable tag: 2.2.6
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
* Using the principle of \"Artificial Ignorance\" with blacklists rather than relying solely on arbitrary blacklists, Pareto Security method ignores requests it knows aren\'t interesting and processes the remaining requests that must then be of interest.
* Pareto Security fully supports WordPress Multi-Site 

= How can I contribute to the cause =

Donations via:

Go to https://hokioisecurity.com/donations/

= Do you have an email contact? =

Email me at pareto-security@hokioisecurity.com

Other contacts: https://taipo.github.io/contact/

== Changelog ==
= 2.2.6 =
* Improve the logging mechanism
* Workaround for plugin conflict with plugin-load-filter

= 2.2.5 =
* Fixed bugs in the way Pareto Security deactivates

= 2.2.4 =
* Fixed a bug in Hard Core Mode where a crontab request could result in the server IP being blocked

= 2.2.3 =
* Prevent the exploit of Unauthenticated Call Any Action or Update Any Option

= 2.2.2 =
* Fixed issue with the way ip addresses are counted in the htaccess file which could result in an incorrect count
* Fixed a reported bug in the way Pareto Security writes to the htaccess file dealing with appended code

= 2.2.1 =
* Fix issue with cleaning up logfile when disabling hard ban mode
* Update injector list

= 2.2.0 =
* Change the Advanced Mode and Hard Ban Mode philosophy.
* In advanced mode this now allows preventing malicious attacks via user-agents without filtering all user-agents
* This allows users to safely run Pareto Security in Advanced Mode
* Prevent SQLi Without Quotes attack

= 2.1.9 =
* Adjust filtering for XML-RPC to further avoid false positives
* Harden UUID for non-WP websites
* Fixed bug in get_dir() affecting non-WP websites 

= 2.1.8 =
* Fixed a bug in the email report where the date was not being converted from unixtime
* Fixed an issue with Google IPs being banned.

= 2.1.7 =
* Updates to crawler filtering to expressly permit 3rd party payment processors to access WP when users use Pareto Security is in Advanced Mode

= 2.1.6 =
* Bugfix: False positive ban when users with less credentials than administrators delete files
* No longer bans IPs of registered users with access less than administrator

= 2.1.5 =
* More backward compatibility to PHP 5.3
* Compatibility check with WP 4.9.8
* Detect incorrect server IP connection attempts
* Allow w3c_validator

= 2.1.1 =
* XML database for blacklists
* Change email report regularity to every 5 serious events
* Update [RFI] Filters
* Banned IP addresses now removed if app is deactivated
* For improved performance, Pareto Security now restricts HTACCESS to the last 500 banned IP addresses
* Fixed non-critical bug in plugin deactivation
* Improved logfile layout with ability to manually remove entries

= 2.1.0 =
* Update to POST Filters
* Extend length of log entry to 500 characters
* Fixed small bug in way the email report displays
* Added Settings link to WP plugin page
* Now checks for and filters $HTTP_RAW_POST_DATA raw post data for XMLRPC
* Better descriptions of attack types
