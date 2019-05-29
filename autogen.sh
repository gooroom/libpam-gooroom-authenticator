#!/bin/sh

#gettextize --force
aclocal -I m4
libtoolize --force --copy
autoheader
automake --add-missing
autoconf
