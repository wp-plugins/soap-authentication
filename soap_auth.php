<?php
/*
	Plugin Name: SOAP Authentication
	Plugin URI: http://matthewkellett.co.uk/developments/wordpress/soap-auth.php
	Description: Used to externally authenticate WP users using a SOAP Service
	Version: 1.0
	Author: Matthew Kellett
	Author URI: http://matthewkellett.co.uk
	License: GNU General Public License (GPL) version 2

	Copyright 2010  Matthew Kellett  (email : email@matthewkellett.co.uk)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License, version 2, as
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

function is_wpmu_enabled(){
	# check if we can detect the version (not always available though)
	global $wmpu_version;
	if (isset($wpmu_version) && $wpmu_version != "") {
		return true;
	}
	# check for the WMPU plugins directory
	if (is_dir(ABSPATH.'wp-content/mu-plugins')) {
		return true;
	}

	#not a WPMU installtion so return false
	return false;
}


/**
 * Soap_Auth
 *
 * A class to authenticate wordpress users using an external SOAP service
 *
 * @author Matthew Kellett <email@matthewkellett.co.uk>
 *
 */
class Soap_Auth {
	function getOptions() {
		$options = get_option('soap_auth_options');
		if (!is_array($options)) {
			$options['soap_wsdl_path'] 		= '';
			$options['auth_function'] 		= '';
			$options['enc_method'] 			= '';
			$options['response_auth']		= '';
			$options['response_exp']		= '';
			$options['response_msg']		= '';
			$options['auth_port'] 			= '';
			$options['auth_user_dets'] 		= '';
			$options['auth_first_name'] 	= '';
			$options['auth_last_name'] 		= '';
			$options['auth_display_name'] 	= '';
			$options['auth_email'] 			= '';
			$options['auth_url'] 			= '';
			$options['login_message'] 		= '';
			$options['response_role'] 		= '';

			#add role options
			global $wp_roles;
			$roles = $wp_roles->get_names();
			foreach ($roles as $name => $display){
				$options['role_'.$name]	= '';
			}

			# if we have wpmu installed add the super admin role mapping fields
			if (is_wpmu_enabled()) {
				$options['role_super_admin'] = '';
			}

			update_option('soap_auth_options', $options);
		}
		return $options;
	}

	function updateOptions(){
		if(isset($_POST['save_soap_settings'])) {
			$options = Soap_Auth::getOptions();

			$options['soap_wsdl_path'] 		= stripslashes($_POST['soap_wsdl_path']);
			$options['auth_function'] 		= stripslashes($_POST['auth_function']);
			$options['enc_method'] 			= stripslashes($_POST['enc_method']);
			$options['response_auth']		= stripslashes($_POST['response_auth']);
			$options['response_exp']		= stripslashes($_POST['response_exp']);
			$options['response_msg']		= stripslashes($_POST['response_msg']);
			$options['auth_port'] 			= stripslashes($_POST['auth_port']);
			$options['auth_user_dets'] 		= stripslashes($_POST['auth_user_dets']);
			$options['auth_first_name'] 	= stripslashes($_POST['auth_first_name']);
			$options['auth_last_name'] 		= stripslashes($_POST['auth_last_name']);
			$options['auth_display_name'] 	= stripslashes($_POST['auth_display_name']);
			$options['auth_email'] 			= stripslashes($_POST['auth_email']);
			$options['auth_url'] 			= stripslashes($_POST['auth_url']);
			$options['login_message'] 		= stripslashes($_POST['login_message']);
			$options['response_role'] 		= stripslashes($_POST['response_role']);

			#add role options
			global $wp_roles;
			$roles = $wp_roles->get_names();
			foreach ($roles as $name => $display){
				$options['role_'.$name]	= stripslashes($_POST['role_'.$name]);
			}

			# if we have wpmu installed add the super admin role mapping fields
			if (is_wpmu_enabled()) {
				$options['role_super_admin'] = stripslashes($_POST['role_super_admin']);
			}

			update_option('soap_auth_options', $options);
		} else {
			Soap_Auth::getOptions();
		}

		#add styles
		$admin_style_url = WP_PLUGIN_URL . '/soap-auth/css/admin.css';
		wp_enqueue_style('soap_auth_styles', $admin_style_url, false, "1.0", "all");

		#add menu
		Soap_Auth::soap_auth_add_menu();

		#add styles
		wp_deregister_script('jquery');
		wp_register_script('jquery', WP_PLUGIN_URL . '/soap-auth/js/jquery-1.4.2.js');
		$admin_script_url = WP_PLUGIN_URL . '/soap-auth/js/admin.js';
		wp_enqueue_script('soap_auth_scripts', $admin_script_url, false, "1.0");
	}

	function soap_auth_add_menu() {
		if (is_wpmu_enabled()) {
			add_submenu_page('ms-admin.php',__('Soap Authentication', 'Soap_Auth'), __('Soap Authentication', 'Soap_Auth'), 'manage_options', basename(__FILE__), array('Soap_Auth', 'soap_auth_display_options'));
		} else {
			add_options_page(__('Soap Authentication', 'Soap_Auth'), __('Soap Authentication', 'Soap_Auth'), 'manage_options', basename(__FILE__), array('Soap_Auth', 'soap_auth_display_options'));
		}
	}

	function soap_auth_display_options() {
		# initialise global objects
		global $wp_roles;
		$roles = $wp_roles->get_names();
		$options = Soap_Auth::getOptions();
		?>
		<div class="wrap">
			<h2>SOAP Authentication Settings</h2>
			<form method="post" action="" id="soap_auth_settings_form">
			<?php settings_fields('soap_auth_options'); ?>
				<div class="webservice_auth_opts">
			        <h3>Webservice Settings</h3>
					<p>The core settings for the SOAP service and includes options for encryption, authentication and response codes</p>
					<ul>
						<li>
							<label for="soap_wsdl_path">WSDL Path</label>
							<input type="text" name="soap_wsdl_path" id="soap_wsdl_path" value="<?php echo $options['soap_wsdl_path']; ?>" />
							<span class="help">This is the path to the SOAP WSDL that will process the authentication requests</span>
						</li>
						<li>
							<label for="auth_function">Auth Function</label>
							<input type="text" name="auth_function" id="auth_function" value="<?php echo $options['auth_function']; ?>" />
							<span class="help">The function that authenticates takes the username and password to authenticate against</span>
						</li>
						<li>
							<label for="enc_method">Encryption method</label>
							<select name="enc_method" id="enc_method">
		<?php
		switch($options['enc_method']) {
			case "SHA256 Hash" :
				echo '<option selected="selected">SHA256 Hash</option><option>SHA1</option><option>MD5</option><option>Plain Text (not advised)</option>';
			break;
			case "SHA1" :
				echo '<option>SHA256 Hash</option><option selected="selected">SHA1</option><option>MD5</option><option>Plain Text (not advised)</option>';
			break;
			case "MD5" :
				echo '<option>SHA256 Hash</option><option>SHA1</option><option selected="selected">MD5</option><option>Plain Text (not advised)</option>';
				break;
			case "Plain" :
				echo '<option>SHA256 Hash</option><option>SHA1</option><option selected="selected">MD5</option><option selected="seclected">Plain Text (not advised)</option>';
			break;
			default :
				echo '<option selected="selected">SHA256 Hash</option><option>SHA1</option><option>MD5</option><option>Plain Text (not advised)</option>';
			break;
		}
		?>
							</select>
							<span class="help">The method used to encrypt passwords with before passwords are sent over the internet (default: sha25)</span>
						</li>
						<li>
							<label for="response_auth">Auth Response Field</label>
							<input type="text" name="response_auth" id="response_auth" value="<?php echo $options['response_auth']; ?>" />
							<span class="help">The field in the response to authorise users i.e user_authenticated</span>
						</li>
						<li>
							<label for="response_exp">Expected Response</label>
							<input type="text" name="response_exp" id="response_exp" value="<?php echo $options['response_exp']; ?>" />
							<span class="help">The field in the response to check if a user is authenticated i.e yes / 1</span>
						</li>
						<li>
							<label for="response_msg">Response Message</label>
							<input type="text" name="response_msg" id="response_msg" value="<?php echo $options['response_msg']; ?>" />
							<span class="help">The field which contains the message to display on failure</span>
						</li>
						<li>
							<label for="auth_port">Port Number</label>
							<input type="text" name="auth_port" id="auth_port" value="<?php echo $options['auth_port']; ?>" />
							<span class="help">The port number to send the request over (default: 80)</span>
						</li>
					</ul>
				</div>
				<div class="webservice_auth_opts">
					<h3>Field Mappings</h3>
					<p>These options are for mapping the user details onto the responses from the SOAP service an covers the basic detail such as first name, surname and email address</p>
					<ul>
						<li>
							<label for="auth_user_dets">Response User Section</label>
							<input type="text" name="auth_user_dets" id="auth_user_dets" value="<?php echo $options['auth_user_dets']; ?>" />
							<span class="help">The field containing the user data i.e. if the user data is stored within an array then this is the key (default: root node)</span>
						</li>
						<li>
							<label for="auth_first_name">First Name</label>
							<input type="text" name="auth_first_name" id="auth_first_name" value="<?php echo $options['auth_first_name']; ?>" />
							<span class="help">The field containing a users first name</span>
						</li>
						<li>
							<label for="auth_last_name">Last Name</label>
							<input type="text" name="auth_last_name" id="auth_last_name" value="<?php echo $options['auth_last_name']; ?>" />
							<span class="help">The field containing a users last name</span>
						</li>
						<li>
							<label for="auth_display_name">Display Name</label>
							<input type="text" name="auth_display_name" id="auth_display_name" value="<?php echo $options['auth_display_name']; ?>" />
							<span class="help">The field containing a users display name (default: username)</span>
						</li>
						<li>
							<label for="auth_email">Email</label>
							<input type="text" name="auth_email" id="auth_email" value="<?php echo $options['auth_email']; ?>" />
							<span class="help">The field containing a users email address</span>
						</li>
						<li>
							<label for="auth_url">URL</label>
							<input type="text" name="auth_url" id="auth_url" value="<?php echo $options['auth_url']; ?>" />
							<span class="help">The field containing a users URL</span>
						</li>
					</ul>
				</div>
				<div class="webservice_auth_opts">
					<h3>Role Mappings</h3>
					<p>The options below allow you to map user permissions from your SOAP service onto the permissions with the Wordpress installation, to add multiple mappings to a single role the separate the mappings using a comma i.e. 1,2,3,4 etc.</p>
					<ul>
						<li>
							<label for="response_role">Response Role Field</label>
							<input type="text" name="response_role" id="response_role" value="<?php echo $options['response_role']; ?>" />
							<span class="help">The field containing the users permission to be mapped</span>
						</li>
		<?php
		foreach ($roles as $name => $display){ ?>
						<li>
							<label for="role_<?php echo $name; ?>"><?php echo $display; ?></label>
							<input type="text" name="role_<?php echo $name; ?>" id="role_<?php echo $name; ?>" value="<?php echo $options['role_'.$name]; ?>" />
							<span class="help">Map the role <?php echo $name; ?> onto what response permission?</span>
						</li>
		<?php
		}
		# if we have wpmu installed add the super admin role mapping fields
		if (is_wpmu_enabled()) { ?>
						<li>
							<label for="role_super_admin">Super Admin</label>
							<input type="text" name="role_super_admin" id="role_super_admin" value="<?php echo $options['role_super_admin']; ?>" />
							<span class="help">If WPMU is installed then this field allows for the mapping of super administrators</span>
						</li>
		<?php
		}
		?>
					</ul>
				</div>
				<div class="webservice_auth_opts">
					<h3>Custom Messages</h3>
					<p>These options allow the customisation of messages throughout the authentication system such as the message which can be seen on the login screen</p>
					<ul>
						<li>
							<label for="login_message">Message for Login</label>
							<textarea rows="3" cols="66" name="login_message" id="login_message"><?php echo htmlspecialchars($options['login_message']); ?></textarea>
							<span class="help">Enter a custom message to display on the login screen. This field supports HTML elements such as div's and p tags</span>
						</li>
					</ul>
				</div>
				<p class="submit">
					<input type="submit" name="save_soap_settings" id="sumbit" value="Save Changes" />
				</p>
			</form>
		</div>
		<?php
	}


	#actual meat of plugin - essentially, you're setting $username and $password to pass on to the system.
	#You check from your external system and insert/update users into the WP system just before WP actually
	#authenticates with its own database.
	function soap_auth_check_login($username, $password) {
		require_once(ABSPATH.'wp-includes/registration.php');

		$options = Soap_Auth::getOptions();
		$soap_url = ($options['soap_wsdl_path'] != "") ? $options['soap_wsdl_path'] : null;
		#if on same host have to use resource id to make sure you don't lose the wp db connection

		if (!is_null($soap_url)) {
			#do the password hash for comparing
			switch($options['enc_method']) {
				case "SHA256 Hash" :
					$password2 = hash('sha256',trim($password));
					break;
				case "SHA1" :
					$password2 = sha1(trim($password));
				break;
				case "MD5" :
					$password2 = md5(trim($password));
					break;
				case "Plain" :
					$password2 = $password;
					break;
			}

			try{
				$method = $options['auth_function'];
				$client = new SoapClient($options['soap_wsdl_path']);
				$response = $client->$method($username, $password2);
			} catch(SoapFault $e) {
				$response = $e;
				global $error_type;
				$error_type = "soap";
				global $error_msg;
				$error_msg = "There was a problem with the soap service: " . $e->getMessage();
			}

			if (is_object($response)) {
				$response = Soap_Auth::object2array($response);
			}
			if (is_object($response[$options['auth_user_dets']])) {
				$response['user'] = Soap_Auth::object2array($response['user']);
			}

			if (isset($response[$options['response_auth']]) && $response[$options['response_auth']] == $options['response_exp']) {
				# disable registration prevention for the current user:
				remove_action('user_register', array('Soap_Auth', 'disable_function'));
				# user has been authenticated against soap service so set up the required fields in the WP database
				$userdetails = $response[$options['auth_user_dets']];
				$userarray['user_login'] 	= $username;
				$userarray['user_pass'] 	= $password;
				$userarray['first_name'] 	= isset($userdetails[$options['auth_first_name']]) ? $userdetails[$options['auth_first_name']] : null;
				$userarray['last_name'] 	= isset($userdetails[$options['auth_last_name']]) ? $userdetails[$options['auth_last_name']] : null;
				$userarray['user_url'] 		= isset($userdetails[$options['auth_user_url']]) ? $userdetails[$options['auth_user_url']] : null;
				$userarray['user_email'] 	= isset($userdetails[$options['auth_email']]) ? $userdetails[$options['auth_email']] : null;
				$userarray['display_name'] 	= (
						isset($userdetails[$options['auth_display_name']]) && $userdetails[$options['auth_display_name']] != ""
					)
					? $userdetails[$options['auth_display_name']]
					: $username;

				#check if the user exists in the system, if they do then update it
				if($id = username_exists($username)) {
					$userarray['ID'] = $id;
					wp_update_user($userarray);
				} else {
					#otherwise create the user
					$user_id = wp_insert_user($userarray);
					$userarray['ID'] = $user_id;
				}
				# now the user exists update their permissions on the system
				$debug = array();
				$user_role = isset($response[$options['response_role']]) ? $response[$options['response_role']] : null;
				if (!is_null($user_role) && isset($userarray['ID'])) {
					# we have a role from the auth service so compare to system and update if necessary
					$userobj = new WP_User($userarray['ID']);
					$curr_roles = $userobj->roles;
					$wp_roles = new WP_Roles();
					$all_roles = $wp_roles->get_names();

					foreach ($all_roles as $name => $display){
						// $options['role_'.$name] == $user_role
						$role_match = false;
						if (isset($options['role_'.$name]) && stristr($options['role_'.$name], ",")) {
							# multiple role maps so set them up
							$mappings = explode(",",$options['role_'.$name]);
							foreach ($mappings as $map){
								if ($map == $user_role) {
									$role_match = true;
								}
							}
						} else if (isset($options['role_'.$name]) && $options['role_'.$name] == $user_role) {
							$role_match = true;
						}
						# if we have a role match then set the role in the database
						if ($role_match === true) {
							$userobj->set_role($name);
						}
					}
					# if we have wpmu installed and user has the correct mapping id then add them as a super admin
					if (is_wpmu_enabled()) {
						$site_admins = get_site_option('site_admins');
						if ($options['role_super_admin'] == $user_role) {
							// the user has the approriate permissions so add them as a super admin
							if (is_array($site_admins) && !in_array($username, $site_admins)) {
								$site_admins[] = $username;
								$result = update_site_option('site_admins', $site_admins);
							}
						} else if (in_array($username, $site_admins)) {
							#user is currently in the database as a super admin but is not authorised so remove them
							$key = array_search($username, $site_admins);
							unset($site_admins[$key]);
							$result = update_site_option('site_admins', $site_admins);
						}
					}
					#trigger_error("Capability for ".$username." (".$userarray['ID'].") is: " . var_export($userobj->roles, true), E_USER_ERROR);
				}
			} else {
				global $error_msg;
				$error_msg = $response[$options['response_msg']];
				global $error_type;
				$error_type = "noauth";
			}
		}else{
			global $error_msg;
			$error_msg = "The authentication settings could not be found, please contact an administrator to update these so you can log in";
			global $error_type;
			$error_type = "nosoap";
		}
	}

	function object2array($object){
		if (is_array($object) || is_object($object)) {
			$array = array();
			foreach($object as $key => $value){
				$array[$key] = self::Object2Array($value);
			}
			return $array;
		}
		return $object;
	}

	//gives warning for login - where to get "source" login
	function soap_auth_warning() {
		$opts = Soap_Auth::getOptions();
		echo "<div class=\"message\">".$opts['login_message']."</div>";
	}

	function soap_errors() {
		global $error;
		global $error_type;
		global $error_msg;

		if ($error != "") {
			$error = "<br /><br />" . $error;
		}
		if ($error_msg != "") {
			$error_msg = "<br /><br />The error returned was: " . $error_msg;
		}

		switch($error_type){
			case 'noauth':
				$error_out = "There was an error authenticating your details.".$error_msg . $error;
				break;
			case 'soap':
				$error_out = $error_msg;
				break;
			case 'nosoap':
				$error_out = $error_msg;
				break;
			default:
				$error_out = "There was an error, contact an admin".$error_msg . $error;
				break;
		} // switch

		return $error_out;
	}

	//hopefully grays stuff out.
	function soap_warning() {
		echo '<strong style="color:red;">Any changes made below WILL NOT be preserved when you login again. You have to change your personal information per instructions found in the <a href="../wp-login.php">login box</a>.</strong>';
	}

	//disables the (useless) password reset option in WP when this plugin is enabled.
	function soap_show_password_fields() {
		return 0;
	}


	/*
	 * Disable functions.  Idea taken from http auth plugin.
	 */
	function disable_function_register() {
		$errors = new WP_Error();
		$errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));
		?></form><br /><div id="login_error">User registration is not available from this site, so you can't create an account or retrieve your password from here. See the message above.</div>
				<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
			<?php
		exit();
	}

	function disable_function() {
		$errors = new WP_Error();
		$errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));
		login_header(__('Log In'), '', $errors);
		?>
			<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
			<?php
		exit();
	}
}

add_action('admin_menu', array('Soap_Auth', 'updateOptions'));
add_action('wp_authenticate', array('Soap_Auth', 'soap_auth_check_login'), 1, 2);
add_action('lost_password', array('Soap_Auth', 'disable_function'));
add_action('user_register', array('Soap_Auth', 'disable_function'));
add_action('wordp', array('Soap_Auth', 'disable_function_register'));
add_action('retrieve_password', array('Soap_Auth', 'disable_function'));
add_action('password_reset', array('Soap_Auth', 'disable_function'));
add_action('profile_personal_options', array('Soap_Auth', 'soap_warning'));
add_filter('login_errors', array('Soap_Auth', 'soap_errors'));
add_filter('show_password_fields', array('Soap_Auth', 'soap_show_password_fields'));
add_filter('login_message', array('Soap_Auth', 'soap_auth_warning'));