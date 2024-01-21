# NIST-Ghidra Dataset Builder

Ce guide détaille l'utilisation de plusieurs programmes pour générer un ensemble de données qui lie un code C, un code assembleur et un code décompilé, en exploitant l'API du [NIST](https://samate.nist.gov/SARD/).

## Prérequis

Avant de commencer, assurez-vous d'avoir installé :

- [Python3](https://www.python.org/downloads/)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases)

<!-- ## Installation

Pour installer ce programme, clonez ce dépôt :

```bash
git clone
``` -->

## Comment Utiliser

Pour utiliser ce programme, exécutez le fichier `NIST_Dataset_Builder.py` avec Python3 :

```bash
python3 NIST_Dataset_Builder.py
```

Dans l'interface, sélectionnez simplement le critère de votre dataset et indiquez le nombre de fichiers à télécharger. Cliquez ensuite sur le bouton `Download` et le programme s'occupe du reste.

## Détails du Programme

### Architecture

Le programme se compose de 4 fichiers :

- `NIST_Dataset_Builder.py` : le fichier principal pour exécuter le programme
- `run_ghidra_headless.sh` : le script qui permet d'exécuter Ghidra en mode sans tête
- `bin2asm.py` : le script qui convertit un fichier binaire en fichier assembleur
- `bin2c.py` : le script qui convertit un fichier binaire en fichier C

### Fonctionnement

Le programme récupère les informations sur les différents critères de recherche en utilisant l'API du NIST. Il télécharge ensuite les fichiers sources, les décompresse et les place dans un dossier. Une fois cela fait, il les compile.

Ensuite, il exécute l'exécutable dans Ghidra en mode sans tête pour récupérer le code assembleur et le code décompilé.

Enfin, il crée un fichier JSON contenant toutes les informations récupérées, place tous les fichiers nécessaires au dataset dans un dossier et supprime les fichiers temporaires.

## Contributeurs

Les personnes suivantes ont contribué à la création de ce projet :

- CRISPEL Esteban - [@EstebanbanC](https://github.com/EstebanbanC)
- VOLPELLIERE Anthony - [@yolker123](https://github.com/yolker123)
- DANIEL Aymeric - [@AyRickk](https://github.com/AyRickk)
- DEVAUX Baptiste - [@Brazok](https://github.com/Brazok)

<!-- ## License

[MIT](https://choosealicense.com/licenses/mit/) -->

