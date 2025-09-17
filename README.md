# Chromebook → ClearPass Sync

Script Python permettant de **synchroniser automatiquement les Chromebooks Google Workspace** vers **Aruba ClearPass** en ajoutant leurs adresses MAC comme endpoints "Known".

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
