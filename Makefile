pam_propperpwnam.so: pam_propperpwnam.c
	$(CC) -shared -fPIC -o pam_propperpwnam.so pam_propperpwnam.c -lpam

.PHONY: clean

clean:
	rm -f pam_propperpwnam.so

install: pam_propperpwnam.so
	mkdir -p $(DESTDIR)/lib/security
	install -o root -g root -m 644 -t $(DESTDIR)/lib/security/ pam_propperpwnam.so

