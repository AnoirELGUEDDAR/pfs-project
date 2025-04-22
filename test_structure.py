# test_structure.py
import os
import sys

def check_directory(dir_path, required_files=None):
    """Vérifier l'existence d'un répertoire et de ses fichiers requis"""
    if not os.path.exists(dir_path):
        print(f"❌ Répertoire manquant: {dir_path}")
        return False
    
    print(f"✅ Répertoire existe: {dir_path}")
    
    if required_files:
        for file in required_files:
            file_path = os.path.join(dir_path, file)
            if os.path.exists(file_path):
                print(f"  ✅ Fichier existe: {file_path}")
            else:
                print(f"  ❌ Fichier manquant: {file_path}")
    
    return True

# Structure requise
structure = {
    "config": ["__init__.py"],
    "core": ["__init__.py"],
    "core/scanner": ["__init__.py"],
    "core/controllers": ["__init__.py"],
    "core/messaging": ["__init__.py"],
    "core/file_tools": ["__init__.py"],
    "core/monitoring": ["__init__.py"],
    "gui": ["__init__.py"],
    "utils": ["__init__.py"],
    "tests": ["__init__.py"]
}

print("Vérification de la structure du projet Network Scanner:")
print("-" * 50)

for directory, files in structure.items():
    check_directory(directory, files)

print("\nTest de structure terminé!")
input("\nAppuyez sur Entrée pour quitter...")