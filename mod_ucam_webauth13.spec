# Build parameters

# Defaults

%define keysdir         /etc/httpd/conf/webauth_keys

# Auto-detect distribution

%if %(rpm --quiet -q suse-release && echo 1 || echo 0) == 1
  %define dist suse
  %define ver %(rpm -q --queryformat='%{VERSION}' suse-release | sed -e's/\\.//g')
  %define keysdir /etc/httpd/webauth_keys
%endif
%if %(rpm --quiet -q redhat-release && echo 1 || echo 0) == 1
  %define dist rh	
  %define ver %(rpm -q --queryformat='%{VERSION}' redhat-release| sed -e's/\\.//g')
%endif
%if %(rpm --quiet -q fedora-release && echo 1 || echo 0) == 1
  %define dist fc
  %define ver %(rpm -q --queryformat='%{VERSION}' fedora-release | sed -e's/\\.//g')}
%endif
%{!?dist: %{error: ERROR: *** Unsupported distribution ***}}

%define dist_tag %{dist}%{ver}
%{echo: Building for %{dist_tag}}

%define _rpmfilename %%{arch}/%%{name}-%%{version}-%%{release}.%%{arch}.%{dist_tag}.rpm  
%define apache_libexecdir %(/usr/sbin/apxs -q LIBEXECDIR)

Summary: University of Cambridge Web Authentication system agent for Apache 1.3
Name: mod_ucam_webauth13
Version: 1.2.0
Release: 5
Group: System Environment/Daemons
Vendor: University of Cambridge Computing Service
URL: http://raven.cam.ac.uk/
Source: mod_ucam_webauth-%{version}.tar.gz
Source1: README.KEYS
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
mkdir -p $RPM_BUILD_ROOT%{keysdir}
cp $RPM_SOURCE_DIR/README.KEYS $RPM_BUILD_ROOT%{keysdir}

%post
%if %{dist} == "suse"
if [ ! -e /srv/www/conf/webauth_keys ]; then
  mkdir -p /srv/www/conf/
  ln -s %{keysdir} /srv/www/conf/webauth_keys
fi
%endif

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{apache_libexecdir}/mod_ucam_webauth.so
%{keysdir}/README.KEYS
%doc CHANGES
%doc README
%doc README.Platforms
%doc COPYING
%doc mod_ucam_webauth.conf.skel

%changelog
* Thu Jun 02 2005 Jon Warbrick <jw35@cam.ac.uk> - 1.2.0-5
- create empty keys directory if necessary

* Tue May 31 2005 Jon Warbrick <jw35@cam.ac.uk> - 1.2.0-1
- Updated for 1.2.0

* Tue Dec 07 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.7-1
- Updated for 1.0.7

* Mon Oct 18 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.6-1
- Updated for 1.0.6

* Fri Oct 15 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.5-1
- Updated for 1.0.5

* Thu Oct 14 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.4-1
- Updated for 1.0.4

* Fri Sep 10 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.2-1
- Updated for 1.0.2

* Wed Aug 25 2004 Jon Warbrick <jw35@cam.ac.uk> - 1.0.0-1
- Updated to 1.0.0
- Added Vendor tag

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
