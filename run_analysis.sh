#!/bin/bash

# Nom du conteneur
CONTAINER_NAME="forensic-analyzer"

# Vérification si le conteneur existe déjà
if [ "$(docker ps -a -q -f name=$CONTAINER_NAME)" ]; then
    echo "Le conteneur $CONTAINER_NAME existe déjà. Suppression..."
    docker rm -f $CONTAINER_NAME
fi

# Construction de l'image si elle n'existe pas
if [ -z "$(docker images -q forensic-analyzer:latest)" ]; then
    echo "Construction de l'image Docker..."
    docker build -t forensic-analyzer .
fi

# Création et démarrage du conteneur
echo "Démarrage du conteneur..."
docker run -d \
    --name $CONTAINER_NAME \
    -v "$(pwd)/input:/app/input" \
    -v "$(pwd)/output:/app/output" \
    -v "$(pwd)/logs:/app/logs" \
    forensic-analyzer

# Fonction pour exécuter l'analyse
run_analysis() {
    local file=$1
    local yara_rules=$2
    local output_dir=$3
    local no_upload=$4

    # Vérification que le fichier existe
    if [ ! -f "input/$file" ]; then
        echo "Erreur: Le fichier $file n'existe pas dans le dossier input/"
        return 1
    fi

    # Construction de la commande
    cmd="python forensic_analyzer.py /app/input/$file"
    
    if [ ! -z "$yara_rules" ]; then
        cmd="$cmd --yara-rules /app/input/$yara_rules"
    fi
    
    if [ ! -z "$output_dir" ]; then
        cmd="$cmd --output-dir /app/output/$output_dir"
    fi
    
    if [ "$no_upload" = true ]; then
        cmd="$cmd --no-upload"
    fi

    # Exécution de l'analyse
    echo "Exécution de l'analyse..."
    docker exec $CONTAINER_NAME $cmd
}

# Exemple d'utilisation
echo "Outil d'analyse forensique"
echo "------------------------"
echo "1. Placez vos fichiers à analyser dans le dossier 'input/'"
echo "2. Pour exécuter une analyse, utilisez la commande :"
echo "   ./run_analysis.sh <fichier> [--yara-rules <fichier_règles>] [--output-dir <dossier>] [--no-upload]"
echo ""
echo "Exemple : ./run_analysis.sh malware.exe --yara-rules rules.yar --output-dir malware_analysis" 
