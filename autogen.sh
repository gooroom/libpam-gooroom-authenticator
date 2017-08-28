#!/bin/sh

#gettextize --force
aclocal -I aclocal
libtoolize --force --copy
autoheader
automake --add-missing --foreign
autoconf
