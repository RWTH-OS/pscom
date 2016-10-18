#
# ParaStation
#
# Copyright (C) 2012 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#
# Authors:      Thomas Moschny <moschny@par-tec.com>
#               Jens Hauke <hauke@par-tec.com>
#
include $(top_srcdir)/common.am

AM_LDFLAGS += -avoid-version
AM_CPPFLAGS += -DLIBDIR=\"$(libdir)\" -I$(top_srcdir)/lib/pscom

lib_LTLIBRARIES = libpscom4ivshmem.la

libpscom4ivshmem_la_SOURCES = pscom_ivshmem.c pscom_ivshmem.h psivshmem.c psivshmem.h metadata.h ##psivshmem_malloc.c psivshmem_malloc.h
libpscom4ivshmem_la_CPPFLAGS = $(AM_CPPFLAGS) $(IVSHMEM_CPPFLAGS)
libpscom4ivshmem_la_LDFLAGS = $(AM_LDFLAGS) $(IVSHMEM_LDFLAGS)
libpscom4ivshmem_la_LIBADD =  -lpthread $(top_builddir)/lib/pscom/libpscom.la


install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
