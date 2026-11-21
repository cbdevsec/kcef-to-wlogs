# Kaspersky_to_Wazuh.py 
petit script pythonn qui convertit les logs Kaspersky format CEF au format des logs wazuh.

## fonctionnement:
Lit les lignes CEF
Parse chaque ligne (HEADER + EXTENSION)
Transforme en format wazuh
Ecrit un fichier NDJSON pour envoyer en BULK par API
Le big push vers INDEXER de l'instance WAZUH

## Installation:
```bash
pip install -r requirements.txt
```

## Fichier .env:
copier le fichier .env.example et changes les valeurs des variables (.env doit rester dans le .gitignore sinn catastrophe de secu)

## Guide d'utilisation:
|Flag|Utilisation|
|----|-----------|
|--simulate N|génère N faux événements|
|--input FILE|lit un vrai fichier CEF|
|--out FILE|fichier NDJSON de sortie|
|--push|envoie vers l'indexer|
|--host / --user / --password|override le .env|
|--verify-tls|vérifie le certificat (off par défaut, because self-signed in the lab)|

### Simulation et output:
```bash
python kaspersky_to_wazuh.py --simulate 500 --out alerts.ndjson
```
### Importation d'un fichier + output:
```bash
python kaspersky_to_wazuh.py --input ksc_export.cef --out alerts.ndjson
```
### Importation + BIG PUSH:
```bash
python kaspersky_to_wazuh.py --input ksc_export.cef --push
```

## Verification:
```json
GET wazuh-alerts-4.x-*/_count
{ "query": { "match": { "location": "kaspersky-ksc" } } }
```

## Pourquoi NDJSON?
L'API _bulk veut une ligne d'action + une ligne de document, chacune sur sa propre ligne. Pas de tableau JSON, and le fichier doit finir par un retour à la ligne, sinon ça plante.