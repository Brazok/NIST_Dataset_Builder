# Makefile

# Require MinGW-w64
# sudo apt install g++-mingw-w64-x86-64 gcc-mingw-w64-x86-64

# Compilateurs
CC = x86_64-w64-mingw32-gcc
CXX = x86_64-w64-mingw32-g++

# Options de compilation
CFLAGS = -DINCLUDEMAIN -DOMITGOOD -DOMITBAD -I./src/testcasesupport -mconsole
CXXFLAGS = $(CFLAGS)

# Fonction pour rechercher récursivement des fichiers
rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

# Récupérer tous les fichiers .c et .cpp dans le répertoire src
CSOURCES = $(call rwildcard,./src/,*.c)
CXXSOURCES = $(call rwildcard,./src/,*.cpp)

# Objets
COBJECTS = $(CSOURCES:.c=.o)
CXXOBJECTS = $(CXXSOURCES:.cpp=.o)

# Nom du dossier courant
CURRENT_DIR = $(notdir $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST))))))

# Nom de l'exécutable basé sur le nom du dossier courant
OUTPUT = ../bin/$(CURRENT_DIR).exe

# La cible par défaut
all: $(OUTPUT)

# Règle pour créer l'exécutable
$(OUTPUT): $(COBJECTS) $(CXXOBJECTS)
	$(CXX) $(CXXFLAGS) $(COBJECTS) $(CXXOBJECTS) -o $(OUTPUT)

# Règles pour compiler les sources C et C++
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Nettoyer les fichiers générés
clean:
	rm -f $(OUTPUT) $(COBJECTS) $(CXXOBJECTS)

