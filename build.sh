#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

xcodebuild -configuration Debug

mkdir -p dist
rm -rf dist/*
cp -p lib/* dist
cp -p build/Debug/sambaclient dist

EXE=dist/sambaclient
otool -L $EXE

git log -n 5 > dist/git_status.txt

install_name_tool -change /usr/local/lib/libsmbclient.dylib.0 @executable_path/libsmbclient.dylib.0 $EXE
install_name_tool -change /usr/local/lib/libsmbsharemodes.dylib.0 @executable_path/libsmbsharemodes.dylib.0 $EXE
install_name_tool -change /usr/local/lib/libtalloc.dylib.2 @executable_path/libtalloc.dylib.2 $EXE

install_name_tool -change /usr/local/lib/libtalloc.dylib.2.0.5 @executable_path/libtalloc.dylib.2.0.5 $EXE
install_name_tool -change /usr/local/lib/libnetapi.dylib.0 @executable_path/libnetapi.dylib.0 $EXE
install_name_tool -change /usr/local/Cellar/samba/3.6.8/lib/libtalloc.dylib.2 @loader_path/libtalloc.dylib.2 dist/libsmbsharemodes.dylib.0
install_name_tool -change /usr/local/Cellar/samba/3.6.8/lib/libtalloc.dylib.2 @loader_path/libtalloc.dylib.2 dist/libsmbclient.dylib.0
install_name_tool -change /usr/local/Cellar/samba/3.6.8/lib/libtalloc.dylib.2 @loader_path/libtalloc.dylib.2 dist/libnetapi.dylib.0

install_name_tool -change /usr/local/Cellar/samba/3.6.8/lib/libtdb.dylib.1 @loader_path/libtdb.dylib.1 dist/libsmbsharemodes.dylib.0
install_name_tool -change /usr/local/Cellar/samba/3.6.8/lib/libtdb.dylib.1 @loader_path/libtdb.dylib.1 dist/libsmbclient.dylib.0
install_name_tool -change /usr/local/Cellar/samba/3.6.8/lib/libtdb.dylib.1 @loader_path/libtdb.dylib.1 dist/libnetapi.dylib.0

#install_name_tool -change /usr/local/lib/libnetapi.dylib.0 @loader_path/libnetapi.dylib.0 dist/libnetapi.dylib.0
# zip it up

rm -f sambaclient.zip

zip -j -u sambaclient.zip dist/*
