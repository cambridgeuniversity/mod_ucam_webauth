# Detect distribution
%if %(rpm --quiet -q suse-release && echo 1 || echo 0) == 1
  %define dist_tag %(rpm -q --queryformat='suse%{VERSION}' suse-release | sed -e's/\\.//g')
%endif
%if %(rpm --quiet -q redhat-release && echo 1 || echo 0) == 1
  %define dist_tag %(rpm -q --queryformat='rh%{VERSION}' redhat-release| sed -e's/\\.//g')
%endif
%if %(rpm --quiet -q fedora-release && echo 1 || echo 0) == 1
  %define dist_tag %(rpm -q --queryformat='fc%{VERSION}' fedora-release | sed -e's/\\.//g')}
%endif
%{!?dist_tag: %{error: ERROR: *** Unsupported distribution ***}}

%define _rpmfilename %%{arch}/%%{name}-%%{version}-%%{release}.%%{arch}.%{dist_tag}.rpm  

%define base mod_ucam_webauth

Summary: University of Cambridge Web Authentication system agent for Apache 1.3
Name: %{base}13
Version: 0.99_1.0.0rc1
Release: 1
Group: System Environment/Daemons
URL: http://raven.cam.ac.uk/
Source: %{base}-%{version}.tar.gz
License: GPL
BuildRoot: %{_tmppath}/%{name}-root
BuildPrereq: apache-devel, openssl-devel
Requires: apache, openssl

%description
mod_ucam_webauth13 provides an interface to the University of
Cambridge Web Authentication system for Apache v1.3 servers.

%prep
%setup -n %{base}-%{version}

%build
%{_sbindir}/apxs -c -lcrypto %{base}.c
%{__strip} -g %{base}.so

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/apache
%{_sbindir}/apxs -i -Wc,-DAPACHE_1_3 -lcrypto -SLIBEXECDIR=$RPM_BUILD_ROOT%{_libdir}/apache/ %{base}.so

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_libdir}/apache/%{base}.so
%doc CHANGES
%doc README
%doc NOTICE

%changelog
* Wed Jun 23 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc1
- Updated for 0.99_1.0.0rc1

* Sat Jun 12 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.45
- Updated to 0.45 - posible resolution of memory problems

* Tue May 04 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.44
- Update to 0.44
- Changes source to .tar.gz file

* Thu Mar 30 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.42
- Updated for 0.42 - fix GMT/Localtime bug

* Mon Mar 22 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.41
- Updated for 0.41

* Fri Mar 12 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.4-3
- Updated for ver 0.4, added INSTALL, CHANGES

* Mon Mar 08 2004 Jon Warbrick <jw35@cam.ac.uk>
- Updated to ver 0.3 - single codebase for Apache 1.3 and 2

* Mon Mar 08 2004 Jon Warbrick <jw35@cam.ac.uk>
- Created
