# Outil d'Analyse Forensique

Cet outil permet d'effectuer une analyse forensique complète de fichiers suspects en utilisant plusieurs outils spécialisés.

## Prérequis

- Docker
- Docker Compose (optionnel)

## Installation

1. Clonez ce dépôt :
```bash
git clone <url-du-repo>
cd <nom-du-dossier>
```

2. Rendez le script d'exécution exécutable :
```bash
chmod +x run_analysis.sh
```

3. Créez les dossiers nécessaires :
```bash
mkdir -p input output logs
```

## Utilisation

1. Placez le fichier à analyser dans le dossier `input/`

2. Exécutez l'analyse :
```bash
./run_analysis.sh <fichier> [options]
```

Options disponibles :
- `--yara-rules <fichier>` : Spécifie un fichier de règles YARA
- `--output-dir <dossier>` : Spécifie un dossier de sortie personnalisé
- `--no-upload` : Désactive l'envoi du rapport à l'API

Exemple :
```bash
./run_analysis.sh malware.exe --yara-rules rules.yar --output-dir malware_analysis
```

## Structure des dossiers

- `input/` : Contient les fichiers à analyser
- `output/` : Contient les rapports d'analyse
- `logs/` : Contient les logs d'exécution

## Fonctionnalités

L'outil effectue les analyses suivantes :
- Calcul des hashs (MD5, SHA256)
- Extraction des métadonnées
- Analyse antivirus (ClamAV)
- Analyse avec YARA
- Analyse mémoire (Volatility)
- Analyse système de fichiers (SleuthKit)
- Extraction d'informations (Bulk Extractor)

## Résultats

Les résultats sont disponibles dans le dossier `output/` sous forme de :
- Rapport JSON
- Archive ZIP contenant tous les résultats

## Support

Pour toute question ou problème, veuillez ouvrir une issue sur le dépôt. 