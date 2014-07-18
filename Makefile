## Build the securepass module
##

#PREFIX = $(DESTDIR)/usr/local
#BINDIR = $(PREFIX)/bin




install_debian: mod_authz_securepass.c
	apxs2 -c mod_authz_securepass.c
	#apxs2 -i -a mod_authz_securepass.la
	install -m 644 .libs/mod_authz_securepass.so /usr/lib/apache2/modules/
	install -m 644 securepass.load /etc/apache2/mods-available


install_redhat: mod_authz_securepass.c
	apxs -c mod_authz_securepass.c
	install -m 755 .libs/mod_authz_securepass.so $(DESTDIR)/usr/lib64/httpd/modules/mod_authz_securepass.so
	install .libs/mod_authz_securepass.lai $(DESTDIR)/usr/lib64/httpd/modules/mod_authz_securepass.la
	install -m 644 .libs/mod_authz_securepass.a $(DESTDIR)/usr/lib64/httpd/modules/mod_authz_securepass.a
	ranlib $(DESTDIR)/usr/lib64/httpd/modules/mod_authz_securepass.a
	PATH="/sbin:/bin:/usr/sbin:/usr/bin:/sbin" ldconfig -n $(DESTDIR)/usr/lib64/httpd/modules
	
clean:
	rm -rf .libs
	rm -rf mod_authz_securepass.lo  mod_authz_securepass.la  mod_authz_securepass.slo mod_authz_securepass.o

