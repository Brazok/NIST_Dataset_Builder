# -*- coding: utf-8 -*-
import os
from binascii import hexlify

# Obtenez le nom du programme
program_name = os.path.splitext(os.path.basename(currentProgram.getExecutablePath()))[0]

# Créez un dossier nommé d'après le programme dans le dossier 'assembly'
program_dir = os.path.join("assembly", program_name)
if not os.path.exists(program_dir):
    os.makedirs(program_dir)

listing = currentProgram.getListing()
functions = listing.getFunctions(True)

for function in functions:
    func_name = function.getName()
    print("Function: {}".format(func_name))

    # Nom de fichier pour la fonction actuelle, dans le dossier du programme
    func_filename = os.path.join(program_dir, func_name + ".asm")

    with open(func_filename, "w") as f:
        # Écrivez le nom de la fonction en haut du fichier assembleur
        f.write("Function: {}\n".format(func_name))

        addrSet = function.getBody()
        codeUnits = listing.getCodeUnits(addrSet, True)  # True signifie 'avancer'

        for codeUnit in codeUnits:
            # Convertissez les bytes en hexadécimal
            bytes_hex = hexlify(codeUnit.getBytes()).decode('utf-8')
            line = "0x{} : {:16} {}\n".format(codeUnit.getAddress(), bytes_hex, codeUnit.toString())
            f.write(line)