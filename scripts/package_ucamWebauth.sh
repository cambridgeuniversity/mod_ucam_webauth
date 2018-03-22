#!/bin/bash

sbuild -vd xenial libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~ubuntu-16.04'

sbuild -vd xenial libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~ubuntu-16.04' --arch=i386

sbuild -vd trusty libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~ubuntu-14.04'

sbuild -vd trusty libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~ubuntu-14.04' --arch=i386

sbuild -vd jessie libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~debian-8'

sbuild -vd jessie libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~debian-8' --arch=i386

sbuild -vd stretch libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~debian-9'

sbuild -vd stretch libapache2-mod-ucam-webauth_2.0.5apache24.dsc -m "UIS Package Builder" --append-to-version='~debian-9' --arch=i386