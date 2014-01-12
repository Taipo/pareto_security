Pareto_Security
===============

Pareto Security

Designed as a broadbased PHP security fixer class for CMS such as Wordpress, Joomla, osCommerce and other content management systems.

Written in PHP 5

This class can filter requests to recognise malicious values and either call a 403 access denied ( default ), or optionally add the offending IP address to the banned list in the root htaccess file of a website.

It processes the REQUEST_URI, QUERY_STRING, _GET, _POST, _COOKIE and browser user-agents to detect values with a blacklisted format.

Installation:
```
require( 'pareto_security.php' );
```

Change these settings at the tops of the class file:
```
   protected $_nonGETPOSTReqs = o;
   protected $_open_basedir = o;
   protected $_banip = o;
   protected $_quietscript = 0;
   protected $_doc_root = '';
```

Or leave them in their default settings.
