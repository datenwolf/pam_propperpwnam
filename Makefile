pam_propperpwnam.so: pam_propperpwnam.c
	$(CC) -shared -fPIC -o pam_propperpwnam.so pam_propperpwnam.c -lpam

.PHONY: clean

clean:
	rm *.o *.so

install: pam_propperpwnam.so
	install -o root -g root -m 644 pam_propperpwnam.so /lib/security/

