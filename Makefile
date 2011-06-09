pam_propperpwnam.so: pam_propperpwnam.c
	$(CC) -shared -fPIC -o pam_propperpwnam.so pam_propperpwnam.c -lpam


.PHONY: clean

clean:
	rm *.o *.so

