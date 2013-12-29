Pareto_Security
===============

Pareto Security

Designed as a broadbased PHP security fixer class for CMS such as Wordpress, Joomla, osCommerce and other content management systems.

Written in PHP 5

This class can filter requests to recognise malicious values and either call a 403 access denied ( default ), or optionally add the offending IP address to the banned list in the root htaccess file of a website.

It processes the REQUEST_URI, QUERY_STRING, _GET, _POST, _COOKIE and browser user-agents to detect values with a blacklisted format.
