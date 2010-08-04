=== Plugin Name ===
Contributors: GizzmoAsus
Donate link: http://matthewkellett.co.uk/portfolio/soap-auth.php
Tags: soap, authentication, register
Requires at least: 3.0
Tested up to: 3.1
Stable tag: trunk

A plugin for SOAP authentication using an external webservice

== Description ==

This plugin allows the use of an external SOAP based webservice to overwrite the default authentication of users within a Wordpress installation. Users are authenticated using the external webservice then added to the local Wordpress database based on the values in the plugin settings. This is done to allow for the role mapping of permissions from an external system to the Wordpress roles.


== Installation ==

1. Edit the `admin.js` file within the `soap-auth` folder to set the correct image path for the help image
2. Upload the `soap-auth` folder to the `/wp-content/plugins/` directory
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Visit the `Soap Authentication` settings and fill out the details of your webservice and role mappings

== Frequently Asked Questions ==

= I need to add additional parameters to the SOAP call, how do I do this? =

Edit the `soap_auth.php` file and add the additional parameters to line 334 (I am working on a better method at the moment)
i.e. `<?php $response = $client->$method($username, $password2, $additional_param1, $additional_param2); ?>`

= Help!, I can't get it to work =

In the event you have problems then please visit the plugin website and contact me using the contact form and I will get in touch to help debug the problem

== Screenshots ==

1. The settings page
2. This login screen with a custom message

== Changelog ==

= 1.0 =
Latest Release - No recent changes

== Upgrade Notice ==

= 1.0 =
Latest Release - No upgrades available
