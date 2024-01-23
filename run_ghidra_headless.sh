#!/bin/bash

GHIDRA_PATH="/home/pascal/Downloads/_ISEN/_MASTER_PROJECT/ghidra-master/ghidra_11.1_DEV"

if [ "$#" -lt 2 ]
then 
    echo "$0 <binary path> <script path> [--noAnalysis] [--time]"
    exit
fi

NOANALYSIS=""
if [ "$3" = "--noAnalysis" ]
then
    NOANALYSIS="-noanalysis"
fi

TIME=""
if [ "$4" = "--time" ]
then
    TIME="time"
fi

#run ghidra
$TIME $GHIDRA_PATH/support/analyzeHeadless . tmp_ghidra_project \
-import "$1" \
-postscript "$2" \
-deleteProject \
-overwrite \
$NOANALYSIS