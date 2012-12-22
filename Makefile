##
## Build the securepass module
##

APXS=apxs2

build: mod_authz_securepass.la

mod_authz_securepass.la:
	$(APXS) -c mod_authz_securepass.c

clean:
	rm -rf .libs
	rm mod_authz_securepass.lo  mod_authz_securepass.la  mod_authz_securepass.slo
