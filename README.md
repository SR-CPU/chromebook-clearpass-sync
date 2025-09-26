# Chromebook → ClearPass Sync

Script Python permettant de synchroniser automatiquement les Chromebooks de Google Workspace avec Aruba ClearPass.

Si une adresse MAC n’existe pas, elle est ajoutée comme endpoint Known avec l’attribut MDM Enabled: True.

Si une adresse MAC existe déjà mais que l’attribut MDM Enabled est absent, le script met à jour l’entrée pour corriger l’attribut.

---

## ⚙️ Fonctionnement
1. Récupère la liste des Chromebooks via **Google Admin SDK**.
2. Vérifie dans **ClearPass** si chaque endpoint existe déjà.
3. Ajoute les nouveaux endpoints avec l’attribut `"MDM Enabled": true`.

---

## 🚀 Installation

```bash
git clone https://github.com/votre-org/chromebook-clearpass-sync.git
cd chromebook-clearpass-sync
pip install -r requirements.txt

