#!/bin/bash

GHIDRA_PATH="/home/pascal/Downloads/_ISEN/_MASTER_PROJECT/ghidra-master/ghidra_11.1_DEV"

if [ "$1" == "--clean" ]
then
    rm -rf tmp_ghidra_project*
    exit
fi

if [ "$#" -lt 2 ]
then 
    echo "$0 <binary path> <script path>"
    exit
fi



echo "Running Ghidra headless on $1 with script $2"
$GHIDRA_PATH/support/analyzeHeadless . tmp_ghidra_project \
-import "$1" \
-postscript "$2" \
-deleteProject \
-overwrite 