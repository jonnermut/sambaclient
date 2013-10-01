#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

xcodebuild -configuration Release 

mkdir -p dist
rm -rf dist/*
cp lib/* dist
cp build/Release/sambaclient dist

EXE=dist/sambaclient
otool -L $EXE

git log -n 5 > dist/git_status.txt

install_name_tool -change /usr/local/lib/libsmbclient.dylib.0 @executable_path/libsmbclient.dylib.0 $EXE
install_name_tool -change /usr/local/lib/libsmbsharemodes.dylib.0 @executable_path/libsmbsharemodes.dylib.0 $EXE
install_name_tool -change /usr/local/lib/libtalloc.dylib.2.0.5 @executable_path/libtalloc.dylib.2.0.5 $EXE
install_name_tool -change /usr/local/lib/libnetapi.dylib.0 @executable_path/libnetapi.dylib.0 $EXE


# zip it up

rm -f sambaclient.zip

zip -j -u sambaclient.zip dist/*
