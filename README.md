Apache authorization module for SecurePass
==========================================

This is an Apache (2.2) module for authorizing SecurePass users.
SecurePass provides web single sign-on through the CAS protocol.
By using mod_auth_cas alone -however- will permit any logged-in user to access the resource.

This module is intended to restrict access to the published resource by:

* allowing only specific SecurePass realm(s) to access the Apache resource
* (in future) allowing only specific SecurePass group(s) to access the Apache resource

More on SecurePass: http://www.secure-pass.net
