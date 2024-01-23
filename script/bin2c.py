#! /usr/bin/env python

import textwrap
import logging
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
import json
import os
import sys
import re
import ghidra
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, FunctionManager
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import DuplicateNameException
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI

import ghidra.app.decompiler

TIMEOUT = 1000

logging.info("Extracting decompiled functions...")
decomp = ghidra.app.decompiler.DecompInterface()
decomp.openProgram(currentProgram)
functions = list(currentProgram.functionManager.getFunctions(True))
failed_to_extract = []
count = 0
allFunc = ""

# Dossier de destination
output_dir = "decompiled"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Nom du fichier dans le dossier decompiled
file_name = currentProgram.getName().split(".")[0] + ".c"
output_file_path = os.path.join(output_dir, file_name)

with open(output_file_path, "w") as f:
    for function in functions:
        logging.info("Current address is at {currentAddress}".format(currentAddress=currentAddress.__str__()))
        logging.info("Decompiling function: {function_name} at {function_entrypoint}".format(
        
        function_name=function.getName(), function_entrypoint=function.getEntryPoint().__str__()))
        decomp = ghidra.app.decompiler.DecompInterface()
        decomp.openProgram(currentProgram)
        decomp_res = decomp.decompileFunction(function, TIMEOUT, monitor)

        if decomp_res.isTimedOut():
            logging.warning("Timed out while attempting to decompile '{function_name}'".format(function_name=function.getName()))
        elif not decomp_res.decompileCompleted():
            logging.error("Failed to decompile {function_name}".format(function_name=function.getName()))
            logging.error("    Error: " + decomp_res.getErrorMessage())
            
        decomp_src = decomp_res.getDecompiledFunction().getC()
        f.write(decomp_src)