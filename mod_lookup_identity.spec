%{!?_httpd_mmn: %{expand: %%global _httpd_mmn %%(cat %{_includedir}/httpd/.mmn || echo 0-0)}}
%{!?_httpd_apxs:       %{expand: %%global _httpd_apxs       %%{_sbindir}/apxs}}
%{!?_httpd_confdir:    %{expand: %%global _httpd_confdir    %%{_sysconfdir}/httpd/conf.d}}
# /etc/httpd/conf.d with httpd < 2.4 and defined as /etc/httpd/conf.modules.d with httpd >= 2.4
%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:    %{expand: %%global _httpd_moddir    %%{_libdir}/httpd/modules}}

Summary: Apache module to retrieve additional information about the authenticated user
Name: mod_lookup_identity
Version: 1.0.0
Release: 8%{?dist}
License: ASL 2.0
Group: System Environment/Daemons
URL: http://www.adelton.com/apache/mod_lookup_identity/
Source0: http://www.adelton.com/apache/mod_lookup_identity/%{name}-%{version}.tar.gz
BuildRequires: gcc
BuildRequires: httpd-devel
BuildRequires: dbus-devel
BuildRequires: pkgconfig
Requires: httpd-mmn = %{_httpd_mmn}
%if 0%{?fedora} || 0%{?rhel} >= 8
Recommends: sssd-dbus
%endif

# Suppres auto-provides for module DSO per
# https://fedoraproject.org/wiki/Packaging:AutoProvidesAndRequiresFiltering#Summary
%{?filter_provides_in: %filter_provides_in %{_libdir}/httpd/modules/.*\.so$}
%{?filter_setup}

%description
mod_lookup_identity can retrieve additional pieces of information
about user authenticated in Apache httpd server and store these values
in notes/environment variables to be consumed by web applications.
Use of REMOTE_USER_* environment variables is recommended.

%prep
%setup -q -n %{name}-%{version}

%build
%{_httpd_apxs} -c -Wc,"%{optflags} -Wall -pedantic -std=c99 $(pkg-config --cflags dbus-1)" $(pkg-config --libs dbus-1) mod_lookup_identity.c
%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
echo > lookup_identity.confx
echo "# Load the module in %{_httpd_modconfdir}/55-lookup_identity.conf" >> lookup_identity.confx
cat lookup_identity.conf >> lookup_identity.confx
%else
cat lookup_identity.module > lookup_identity.confx
cat lookup_identity.conf >> lookup_identity.confx
%endif

%install
rm -rf $RPM_BUILD_ROOT
install -Dm 755 .libs/mod_lookup_identity.so $RPM_BUILD_ROOT%{_httpd_moddir}/mod_lookup_identity.so

%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
# httpd >= 2.4.x
install -Dp -m 0644 lookup_identity.module $RPM_BUILD_ROOT%{_httpd_modconfdir}/55-lookup_identity.conf
%endif
install -Dp -m 0644 lookup_identity.confx $RPM_BUILD_ROOT%{_httpd_confdir}/lookup_identity.conf

%files
%doc README LICENSE
%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
%config(noreplace) %{_httpd_modconfdir}/55-lookup_identity.conf
%endif
%config(noreplace) %{_httpd_confdir}/lookup_identity.conf
%{_httpd_moddir}/*.so

%changelog
* Sat Dec  1 2018 Peter Oliver <rpm@mavit.org.uk> - 1.0.0-8
- Recommend sssd-dbus.

* Fri Feb 23 2018 Jan Pazdziora <jpazdziora@redhat.com> - 1.0.0-6
- https://fedoraproject.org/wiki/Packaging:C_and_C%2B%2B#BuildRequires_and_Requires

* Tue Apr 04 2017 Jan Pazdziora <jpazdziora@redhat.com> - 1.0.0-1
- Make LookupUserGECOS optional (no default) to support non-POSIX
  user identities.

* Wed Mar 22 2017 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.9-1
- Add support for multiple users mapped to single certificate.

* Wed Nov 23 2016 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.8-1
- Logging improvements; lookup_user_by_certificate logging moved from
  notice to info level.

* Thu Jun 16 2016 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.7-1
- Ensure lookup_user_by_certificate runs after mod_nss as well.

* Mon Mar 21 2016 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.6-1
- 1319138 - the Requires(pre) httpd does not seem to be needed.

* Wed Jan 20 2016 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.5-1
- Fix LookupUserByCertificate httpd-2.2 compatibility issue.

* Wed Jan 20 2016 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.4-1
- Added LookupUserOutput headers and headers-base64.

* Mon Aug 03 2015 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.3-1
- Added LookupUserByCertificate.

* Fri Jun 27 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.2-1
- Fix error handling and reporting.
- Fix module loading/configuration for Apache 2.4.

* Tue May 13 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.1-1
- Address code issues revealed by coverity scan.
- Minor README fixes.

* Tue May 13 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.0-1
- Add support for '+'-prefixed note/variable names.
- Silence compile warnings by specifying C99.
- Fix format of logs of dbus calls.

* Sat Feb 01 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.8.3-1
- 1058812 - drop explicit dbus-libs dependency.

* Thu Jan 30 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.8.2-1
- 1058812 - .spec changes for Fedora package review.

* Fri Jan 17 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.8.1-1
- Ensure we run before mod_headers so that our result can be put to
  request headers for mod_proxy.

* Thu Jan 09 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.8-1
- Declare all functions static for proper isolation.

* Thu Nov 21 2013 Jan Pazdziora <jpazdziora@redhat.com> - 0.7.1-1
- Address segfault when no LookupUserAttrIter is set.

* Tue Nov 19 2013 Jan Pazdziora <jpazdziora@redhat.com> - 0.7-1
- Define lookup_identity_hook as optional function, callable from
  other modules.

* Mon Nov 18 2013 Jan Pazdziora <jpazdziora@redhat.com> - 0.6-1
- Use org.freedesktop.sssd.infopipe.GetUserGroups for group lists.
- Support new org.freedesktop.sssd.infopipe.GetUserAttr parameters /
  return values.
- Removed LookupOutputGroupsSeparator.
- LookupOutputGroups and LookupUserAttr now support separator as
  optional second parameter.
- Added LookupUserGroupsIter and LookupUserAttrIter.
- Added LookupDbusTimeout.

* Mon Oct 28 2013 Jan Pazdziora <jpazdziora@redhat.com> - 0.5-1
- Initial release.
