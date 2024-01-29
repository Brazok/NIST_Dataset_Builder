# -*- coding: utf-8 -*-
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

import json
from binascii import hexlify
import os


args = getScriptArgs()

if len(args) < 1 and "asm" not in args and "decompile" not in args:
    print("You must choose at least one option between 'asm' and 'decompile' !")
    exit()


output_dir = "output"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)


file_name = currentProgram.getName().split(".exe")[0] + ".json"
output_file_path = os.path.join(output_dir, file_name)


decompinterface = DecompInterface()
decompinterface.openProgram(currentProgram);

listing = currentProgram.getListing()
functions = listing.getFunctions(True)




with open(output_file_path, "r") as f:
    try:
        json_content = json.load(f)
        print("File {} already exists, loading it...".format(output_file_path))
    except:
        pass

json_content["decompiled"] = json.loads("{}")
json_content["disassembled"] = json.loads("{}")

with open(output_file_path, "w") as f:

    for function in functions:
        asm_function_lines = []
        decompiled_c_code = ""

        function_name = function.getName()
        # print("Function: {}".format(function_name))

        # Decompilation
        if "decompile" in args:
            decompiled_function = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
            decompiled_c_code = decompiled_function.getDecompiledFunction().getC()

            json_content["decompiled"][function_name] = decompiled_c_code

        # Disassembly
        if "asm" in args:
            addrSet = function.getBody()
            codeUnits = listing.getCodeUnits(addrSet, True)

            for codeUnit in codeUnits:
                bytes_hex = hexlify(codeUnit.getBytes()).decode('utf-8')
                asm_function_lines.append("0x{} : {:16} {}\n".format(codeUnit.getAddress(), bytes_hex, codeUnit.toString()))

            json_content["disassembled"][function_name] = asm_function_lines
    
    f.write(json.dumps(json_content, indent=4))