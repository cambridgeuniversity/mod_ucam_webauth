##
##  Makefile -- Build procedure for mod_ucam_webauth
##  Loosely based on the Makefile Autogenerated via ``apxs -n bar -g''.
##

#   the used tools

APXS=/usr/bin/apxs    # Use 'make .... APXS=/path/to/apxs' if elsewhere
SUFFIX=la              # Use 'make .... SUFFIX=so for Apache 1

#   additional user defines, includes, libraries and options
#DEF=-Dmy_define=my_value
#INC=-Imy/include/dir
#LIB=-Lmy/lib/dir -lmylib
#OPT=-SLIBEXECDIR=$RPM_BUILD_ROOT%{_libdir}/apache/ -Wc,-Wall

#   the default target

all: mod_ucam_webauth.$(SUFFIX)

#   compile the DSO file

mod_ucam_webauth.$(SUFFIX): mod_ucam_webauth.c
	$(APXS) -c -lcrypto $(DEF) $(INC) $(LIB) $(OPT) \
	mod_ucam_webauth.c

#   install the DSO file into the Apache installation

install: all
	$(APXS) -i $(OPT) mod_ucam_webauth.$(SUFFIX)

# Build a distribution

dist:
	(ver=`grep '#define VERSION' mod_ucam_webauth.c |      \
	 sed -e s/\"//g | cut -d' ' -f3`; \
	 mkdir -p mod_ucam_webauth-$$ver; \
	 rm -rf mod_ucam_webauth-$$ver/*; \
	 cp `cat MANIFEST` mod_ucam_webauth-$$ver; \
	 mkdir -p mod_ucam_webauth-$$ver/rpm-build; \
	 (cd rpm-build; \
          cp `cat MANIFEST` ../mod_ucam_webauth-$$ver/rpm-build); \
	 tar zcf mod_ucam_webauth-$$ver.tar.gz mod_ucam_webauth-$$ver;\
         rm -rf mod_ucam_webauth-$$ver )

rpmdirs:
	mkdir -p ~/rpmdevel/BUILD
	mkdir -p ~/rpmdevel/RPMS
	mkdir -p ~/rpmdevel/SOURCES
	mkdir -p ~/rpmdevel/SPECS
	mkdir -p ~/rpmdevel/SRPMS

rpm2: dist rpmdirs
	(ver=`grep '#define VERSION' mod_ucam_webauth.c |      \
	 sed -e s/\"//g | cut -d' ' -f3`; \
	cp -v mod_ucam_webauth-$$ver.tar.gz ~/rpmdevel/SOURCES/)
	cp -v rpm-build/README.KEYS ~/rpmdevel/SOURCES
	cp -v rpm-build/mod_ucam_webauth2.spec ~/rpmdevel/SPECS
	rpmbuild --define "_topdir $(HOME)/rpmdevel/" -bs --nodeps /home/infosysansible/rpmdevel/SPECS/mod_ucam_webauth2.spec



windows:
	rm -f mod_ucam_webauth-`cat Windows/VERSION`.zip
	mkdir -p zip_build          zip_build/Apache13 \
	         zip_build/Apache20 zip_build/Apache22
	cp CHANGES                  zip_build/CHANGES.txt
	cp COPYING                  zip_build/COPYING.txt
	cp INSTALL                  zip_build/INSTALL.txt
	cp INSTALL.Platforms        zip_build/INSTALL_Platforms.txt
	cp README                   zip_build/README.txt
	cp README.Config            zip_build/README_Config.txt
	cp README.WIN32             zip_build/README_WIN32.txt
	cp Windows/vcredist_x86.exe zip_build/vcredist_x86.exe
	cp Windows/mod_ucam_webauth13-`cat Windows/VERSION`.so \
	                            zip_build/Apache13/mod_ucam_webauth.so
	cp Windows/mod_ucam_webauth20-`cat Windows/VERSION`.so \
	                            zip_build/Apache20/mod_ucam_webauth.so
	cp Windows/mod_ucam_webauth22-`cat Windows/VERSION`.so \
	                            zip_build/Apache22/mod_ucam_webauth.so
	(cd zip_build; \
	 zip    ../mod_ucam_webauth-`cat ../Windows/VERSION`.zip \
	                          Apache13/* Apache20/* Apache22/* *.exe; \
	 zip -l ../mod_ucam_webauth-`cat ../Windows/VERSION`.zip *.txt)
	rm -r zip_build/

clean:
	rm -f *~ *.o *.so *.la *.lo *.slo *.tar.gz *.zip


