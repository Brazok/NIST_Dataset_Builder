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

if [ ! -f "$1" ]
then
    echo "File $1 does not exist"
    exit
fi


arg1=""
if [ -n "$3" ]
then
    arg1="$3"
fi

arg2=""
if [ -n "$4" ]
then
    arg2="$4"
fi



echo "Running Ghidra headless on $1 with script $2"
$GHIDRA_PATH/support/analyzeHeadless ./tmp tmp_ghidra_project \
-import "$1" \
-postscript $2 $arg1 $arg2 \
-deleteProject \
-overwrite