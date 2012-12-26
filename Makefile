
## Build the securepass module
##





install_debian: mod_authz_securepass.c
	apxs2 -c mod_authz_securepass.c
	apxs2 -i -a mod_authz_securepass.la
	install -m 644 .libs/mod_authz_securepass.so /usr/lib/apache2/modules/
	install -m 644 securepass.load /etc/apache2/mods-available


install_redhat: mod_authz_securepass.c
	apxs -c mod_authz_securepass.c
	apxs -i -a mod_authz_securepass.la
	echo "LoadModule authz_securepass_module /etc/httpd/modules/mod_authz_securepass.so" > /etc/httpd/conf.d/mod_authz_securepass.conf

	
clean:
	rm -rf .libs
	rm mod_authz_securepass.lo  mod_authz_securepass.la  mod_authz_securepass.slo mod_authz_securepass.o

