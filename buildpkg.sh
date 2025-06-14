#!/bin/bash
export RPMBUILD=$(which rpmbuild)
export ALIEN=$(which alien)

if ! test -r ./evlt
then
 echo "error : evlt executable not found"
 exit 1
fi

if [ "$RPMBUILD" = "" ]
then
 echo "error : rpmbuild not found"
 exit 1
fi

## Build the RPM
rm -rf ~/rpmbuild 2>/dev/null
rm -rf *.rpm 2>/dev/null
rm -rf *.deb 2>/dev/null
mkdir -p ~/rpmbuild/RPMS
cat evlt.spec.template | sed -e 's/__RELEASE__/'$(date "+%Y %j" | awk '{printf("%02d%03d\n",$(1)-2025,$2);}')'/' >evlt.spec
echo rpmbuild --define \"_sourcedir $(pwd)\" -bb evlt.spec
rpmbuild --define "_sourcedir $(pwd)" -bb evlt.spec
mv $(find ~/rpmbuild/RPMS -name '*.rpm'  | head -n1) . 2>/dev/null
rm -rf ~/rpmbuild 2>/dev/null
rm -rf evlt.spec 2>/dev/null

## Create a debian package via alien
if [ "$ALIEN" != "" ]
then
 echo fakeroot alien --scripts $(ls evlt*.rpm | sort | tail -n1)
 fakeroot alien --scripts $(ls evlt*.rpm | sort | tail -n1)
fi

echo "## Packages created :" >&2
ls *.rpm *.deb >&2

