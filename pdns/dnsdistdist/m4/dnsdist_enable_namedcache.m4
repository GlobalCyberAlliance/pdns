AC_DEFUN([DNSDIST_ENABLE_NAMEDCACHE], [
  AC_MSG_CHECKING([whether to enable Named Cache support])
  AC_ARG_ENABLE([namedcache],
    AS_HELP_STRING([--enable-namedcache], [enable Named Cache support  @<:@default=no@:>@]),
    [enable_namedcache=$enableval],
    [enable_namedcache=no]
  )
  AC_MSG_RESULT([$enable_namedcache])
  AM_CONDITIONAL([NAMEDCACHE], [test "x$enable_namedcache" != "xno"])

  AM_COND_IF([NAMEDCACHE], [
      PDNS_CHECK_CDB
      AC_DEFINE([HAVE_NAMEDCACHE], [1], [Define to 1 if you have namedCache & libtinycdb])
  ])
])
