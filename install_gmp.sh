#!/bin/bash

# Download GMP
VERSION=6.3.0
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz

# Install
gunzip gmp-$VERSION.tar.gz
tar xf gmp-$VERSION.tar
cd gmp-$VERSION
./configure --prefix=$HOME/sw
make
make check
make install

# Delete extra
rm -rf gmp-$VERSION.tar
rm -rf gmp-$VERSION