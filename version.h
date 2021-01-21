/* $OpenBSD: version.h,v 1.83 2018/10/10 16:43:49 deraadt Exp $ */

#define SSH_VERSION	"OpenSSH_7.9"

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
#define SSH_HPN         "-hpn14v18"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE GSI_PORTABLE \
			GSI_VERSION SSH_HPN KRB5_VERSION
