##
## Build the securepass module
##

APXS=apxs2

build: mod_authz_securepass.la

mod_authz_securepass.la: mod_authz_securepass.c
	$(APXS) -c mod_authz_securepass.c

install: build
	install -m 644 .libs/mod_authz_securepass.so /usr/lib/apache2/modules/
	install -m 644 securepass.load /etc/apache2/mods-available

uninstall:
	rm -f /etc/apache2/mods-available/securepass.load 
	rm -f /usr/lib/apache2/modules/mod_authz_securepass.so

clean:
	rm -rf .libs
	rm mod_authz_securepass.lo  mod_authz_securepass.la  mod_authz_securepass.slo

