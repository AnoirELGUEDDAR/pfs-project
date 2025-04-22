# reset_application.py
import os
import shutil

def reset_app():
    """Réinitialiser l'application en supprimant tous les fichiers de données"""
    files_to_remove = [
        "devices.json", 
        "remote_devices.json",
        "settings.json"
    ]
    
    dirs_to_clean = [
        "__pycache__", 
        "gui/__pycache__", 
        "core/__pycache__", 
        "core/remote/__pycache__"
    ]
    
    # Supprimer les fichiers
    for file in files_to_remove:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"Fichier supprimé: {file}")
            except Exception as e:
                print(f"Erreur lors de la suppression de {file}: {str(e)}")
    
    # Nettoyer les répertoires de cache
    for dir_path in dirs_to_clean:
        if os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path)
                print(f"Répertoire nettoyé: {dir_path}")
            except Exception as e:
                print(f"Erreur lors du nettoyage de {dir_path}: {str(e)}")
    
    print("\nRéinitialisation terminée. Redémarrez l'application.")

if __name__ == "__main__":
    confirm = input("Cette action va supprimer toutes vos données enregistrées. Continuer? (o/n): ")
    if confirm.lower() == 'o':
        reset_app()
    else:
        print("Réinitialisation annulée.")