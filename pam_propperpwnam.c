/* pam_propperpwnam 
*
* Copyright 2011, 2023, Wolfgang Draxinger
* code+pam_propperpwnam@wolfgang-draxinger.net
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
* 
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
* 
* 3. Neither the name of the copyright holder nor the names of its contributors
* may be used to endorse or promote products derived from this software without
* specific prior written permission.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*******************************************************************************
*
* This PAM module sets the user login name to the username
* stored in the user database using the login name passed
* as an access key.
*
* Example usage scenario is adjusting the usernames' characters
* case in environments where case sensitive and case insensitive
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

