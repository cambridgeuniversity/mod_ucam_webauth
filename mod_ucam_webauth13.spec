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
%{echo: Building for %{dist_tag}}

%define _rpmfilename %%{arch}/%%{name}-%%{version}-%%{release}.%%{arch}.%{dist_tag}.rpm  
%define apache_libexecdir %(/usr/sbin/apxs -q LIBEXECDIR)

Summary: University of Cambridge Web Authentication system agent for Apache 1.3
Name: mod_ucam_webauth13
Version: 0.99_1.0.0rc6
Release: 2
Group: System Environment/Daemons
URL: http://raven.cam.ac.uk/
Source: mod_ucam_webauth-%{version}.tar.gz
License: GPL
BuildRoot: %{_tmppath}/%{name}-root
BuildPrereq: apache-devel, openssl-devel
Requires: apache, openssl

%description
mod_ucam_webauth13 provides an interface to the University of
Cambridge Web Authentication system for Apache v1.3 servers.

%prep
%setup -n mod_ucam_webauth-%{version}

%build
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/apache
make install OPT=-SLIBEXECDIR=$RPM_BUILD_ROOT%{apache_libexecdir}

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
* Wed Jul 14 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc6-2
- Corrected path to apxs

* Mon Jul 12 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc6
- Updated for 0.99_1.0.0rc6
- Added echo of build target

* Fri Jul 09 2004 Jon Warbrick <jw35@cam.ac.uk> - 0.99_1.0.0rc5
- Updated for 0.99_1.0.0rc5
- Updated to use Makefile

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
