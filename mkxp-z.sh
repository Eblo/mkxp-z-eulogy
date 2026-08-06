#!/bin/bash

GAMEROOT=$(cd "${0%/*}" && echo $PWD)
export LD_LIBRARY_PATH="${GAMEROOT}/lib64":$LD_LIBRARY_PATH
"${GAMEROOT}"/mkxp-z "$@"
