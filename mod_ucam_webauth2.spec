# Detect distribution
%if %(rpm --quiet -q suse-release && echo 1 || echo 0) == 1
  %define dist_tag %(rpm -q --queryformat='suse%{VERSION}' suse-release | sed -e's/\\.//g')
  %define apache2_package apache2
  %define apxs %{_sbindir}/apxs2
%endif
%if %(rpm --quiet -q redhat-release && echo 1 || echo 0) == 1
  %define dist_tag %(rpm -q --queryformat='rh%{VERSION}' redhat-release| sed -e's/\\.//g')
  %define apache2_package httpd
  %define apxs %{_sbindir}/apxs
%endif
%if %(rpm --quiet -q fedora-release && echo 1 || echo 0) == 1
  %define dist_tag %(rpm -q --queryformat='fc%{VERSION}' fedora-release | sed -e's/\\.//g')
  %define apache2_package httpd
  %define apxs %{_sbindir}/apxs
%endif
%{!?dist_tag: %{error: ERROR: *** Unsupported distribution ***}}
%{echo: Building for %{dist_tag}}

%define _rpmfilename %%{arch}/%%{name}-%%{version}-%%{release}.%%{arch}.%{dist_tag}.rpm  
%define apache_libexecdir %(%{apxs} -q LIBEXECDIR)

%define base mod_ucam_webauth

Summary: University of Cambridge Web Authentication system agent for Apache 2
Name: %{base}2
Version: 0.99_1.0.0rc2
Release: 1
Group: System Environment/Daemons
URL: http://raven.cam.ac.uk/
Source: %{base}-%{version}.tar.gz
License: GPL
BuildRoot: %{_tmppath}/%{name}-root
BuildPrereq: %{apache2_package}-devel, openssl-devel
Requires: %{apache2_package}, openssl

%description
mod_ucam_webauth2 provides an interface to the University of
Cambridge Web Authentication system for Apache v2 servers.

%prep
%setup -n %{base}-%{version}

%build
%{apxs} -c -lcrypto %{base}.c

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{apache_libexecdir}
%{apxs} -i -Wc,-DAPACHE_2 -lcrypto -S LIBEXECDIR=$RPM_BUILD_ROOT%{apache_libexecdir} %{base}.la

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{apache_libexecdir}/%{base}.so
%doc CHANGES
%doc NOTICE
%doc README

%changelog
* Wed Jun 23 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc2
- Updated for 0.99_1.0.0rc2

* Sat Jun 12 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.45
- Updated to 0.45 - posible resolution of memory problems

* Tue May 04 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.44
- Update to 0.44
- Changes source to .tar.gz file

* Tue Mar 30 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.42
- Updated for 0.42 - fix GMT/Localtime bug

* Tue Mar 23 2004 Jon Warbrick <jw35@cam.ac.uk>
- Updated for ver 0.41

* Fri Mar 12 2004 Jon Warbrick <jw35@cam.ac.uk>
- Updated for ver 0.4, added INSTALL, CHANGES

* Wed Mar 10 2004 Jon Warbrick <jw35@cam.ac.uk>
- Adapeted to work on SuSE

* Mon Mar 08 2004 Jon Warbrick <jw35@cam.ac.uk>
- Created

