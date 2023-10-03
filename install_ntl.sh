#!/bin/bash

# Download NTL
VERSION=11.5.1
wget https://libntl.org/ntl-$VERSION.tar.gz

# Install NTL
gunzip ntl-$VERSION.tar.gz
tar xf ntl-$VERSION.tar
cd ntl-$VERSION/src
./configure 
make
make check
sudo make install

# Clean up
rm -rf ntl-$VERSION.tar
rm -rf ntl-$VERSION