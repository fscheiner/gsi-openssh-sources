/* $OpenBSD: version.h,v 1.84 2019/04/03 15:48:45 djm Exp $ */

#define SSH_VERSION	"OpenSSH_8.0"

#ifdef GSI
#define GSI_VERSION	" GSI"
#else
#define GSI_VERSION	""
#endif

#ifdef KRB5
#define KRB5_VERSION	" KRB5"
#else
#define KRB5_VERSION	""
#endif

#define SSH_PORTABLE	"p1"
#define GSI_PORTABLE	"c-GSI"
#define SSH_HPN         "-hpn14v19"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE GSI_PORTABLE \
			GSI_VERSION SSH_HPN KRB5_VERSION
