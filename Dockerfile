# Utilisation d'une image Python officielle
FROM python:3.9-slim

# Installation des dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    yara \
    exiftool \
    sleuthkit \
    libmagic1 \
    python3-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Création du répertoire de travail
WORKDIR /app

# Copie des fichiers nécessaires
COPY requirements.txt .
COPY forensic_analyzer.py .

# Installation des dépendances Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir requests python-magic && \
    pip install --no-cache-dir yara-python

# Création des répertoires nécessaires
RUN mkdir -p /app/logs /app/output /app/input

# Configuration de ClamAV
RUN freshclam

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Commande par défaut (au lieu de ENTRYPOINT)
CMD ["python", "forensic_analyzer.py"]
