#!/bin/bash

GAMEROOT=$(cd "${0%/*}" && echo $PWD)
UNAME=`uname`
if [ "$UNAME" == "Darwin" ]; then
	# macOS
	LINK_DIR="${GAMEROOT}/Z-steam.app/Contents/Game"
	if [ ! -e "$LINK_DIR" ] && [ ! -L "$LINK_DIR" ]; then
		ln -s "$GAMEROOT" "$LINK_DIR"
	fi
	exec ${GAMEROOT}/Z-steam.app/Contents/MacOS/shim
else
	# Linux
	export LD_LIBRARY_PATH="${GAMEROOT}/lib64":$LD_LIBRARY_PATH
	"${GAMEROOT}"/mkxp-z "$@"
fi
