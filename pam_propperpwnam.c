/*
* pam_propperpwnam 
*
* 2011-06-09
*
* Wolfgang Draxinger
* Wolfgang.Draxinger@physik.uni-muenchen.de
*
* a PAM module that sets the user loginname to the username
* stored in the user databased using the loginname passed
* as access key.
*
* Example usage scenario is adjusting the usernames' characters
* case in  environments where case sensitive and case insensitive
* services are mixed (the module was initially developed for
* this very usage scenario).
*/

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#if DEBUG
#include <stdio.h>
#endif

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(
	pam_handle_t *pamh,
	int flags,
	int argc,
	char const *argv[] )
{
	int error;
	char *entered_username;

	struct passwd pwd;
	struct passwd *pwd_result;
	char *pwd_buf;
	size_t pwd_bufsize;

#if DEBUG
	fprintf(stderr, "pam_propperpwnam called\n");
#endif

	error = pam_get_user(pamh, (char const **)&entered_username, 0);
	if(PAM_SUCCESS != error)
		return PAM_USER_UNKNOWN;

#if DEBUG	
	fprintf(stderr, "pam_propperpwnam entered username is %s\n", entered_username);
#endif

	pwd_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if( -1 == pwd_bufsize )          /* Value was indeterminate */
		pwd_bufsize = 16384;        /* Should be more than enough */

	pwd_buf = malloc( pwd_bufsize );
	if( !pwd_buf ) {
		return PAM_AUTH_ERR;
	}

	error = getpwnam_r(entered_username, &pwd, pwd_buf, pwd_bufsize, &pwd_result);
	if( !pwd_result ) {
		free(pwd_buf);
		if( !error )
			return PAM_USER_UNKNOWN;
		return PAM_AUTH_ERR;
	}

#if DEBUG
	fprintf(stderr, "pam_propperpwnam propper username is %s\n", pwd_result->pw_name);
#endif

	error = pam_set_item(pamh, PAM_USER, pwd_result->pw_name);
	free( pwd_buf );
	if( PAM_SUCCESS != error ) {
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}

