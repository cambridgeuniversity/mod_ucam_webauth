

default:
	@echo "Try 'make dist' to build a distribution"

dist:
	(ver=`grep '#define VERSION' mod_ucam_webauth.c |      \
	 sed -e s/\"//g | cut -d' ' -f3`; \
	 mkdir -p mod_ucam_webauth-$$ver; \
	 rm -rf mod_ucam_webauth-$$ver/*; \
	 cp `cat MANIFEST` mod_ucam_webauth-$$ver; \
	 tar zcf mod_ucam_webauth-$$ver.tar.gz mod_ucam_webauth-$$ver;\
         rm -rf mod_ucam_webauth-$$ver )

clean:
	rm -f *~ *.o *.so *.tar.gz
