#
# ParaStation
#
# Copyright (C) 2014 ParTec Cluster Competence Center GmbH, Munich
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

lib_LTLIBRARIES = libpsmallocinterVM.la


libpsmallocinterVM_la_SOURCES = psmalloc_interVM.c psivshmem_malloc.h
libpsmallocinterVM_la_CPPFLAGS = $(AM_CPPFLAGS) $(PSM_CPPFLAGS)
libpsmallocinterVM_la_LDFLAGS = $(AM_LDFLAGS) $(PSM_LDFLAGS)
libpsmallocinterVM_la_LIBADD = $(top_builddir)/lib/pscom/libpscom.la

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
