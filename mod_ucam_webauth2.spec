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

Summary: University of Cambridge Web Authentication system agent for Apache 2
Name: mod_ucam_webauth2
Version: 1.0.2
Release: 1
Group: System Environment/Daemons
Vendor: University of Cambridge Computing Service
URL: http://raven.cam.ac.uk/
Source: mod_ucam_webauth-%{version}.tar.gz
License: GPL
BuildRoot: %{_tmppath}/%{name}-root
BuildPrereq: %{apache2_package}-devel, openssl-devel
Requires: %{apache2_package}, openssl

%description
mod_ucam_webauth2 provides an interface to the University of
Cambridge Web Authentication system for Apache v2 servers.

%prep
%setup -n mod_ucam_webauth-%{version}

%build
make APXS=%{apxs}

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{apache_libexecdir}
make install APXS=%{apxs} SUFFIX=la \
  OPT=-SLIBEXECDIR=$RPM_BUILD_ROOT%{apache_libexecdir}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{apache_libexecdir}/mod_ucam_webauth.so
%doc CHANGES
%doc README
%doc NOTICE
%doc mod_ucam_webauth.conf.skel

%changelog
* Fri Sep 10 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.2-1
- Updated for 1.0.2

* Wed Aug 25 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.0-1
- Updated to 1.0.0
- Added Vendor tag

* Mon Jul 12 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc6
- Updated for 0.99_1.0.0rc6
- Fixed following mess caused by last update

* Fri Jul 09 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc5
- Updated for 0.99_1.0.0rc5
- Updated to use Makefile by copying from mod_ucam_webauth13.spec

* Fri Jun 25 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc3
- Updated for 0.99_1.0.0rc3

* Wed Jun 23 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc2
- Updated for 0.99_1.0.0rc2

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
