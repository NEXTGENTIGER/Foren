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
    wget \
    gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# Installation des dépendances pour bulk-extractor
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    libewf-dev \
    libtre-dev \
    libafflib-dev \
    libexpat1-dev \
    libxml2-dev \
    libbz2-dev \
    libzip-dev \
    libsqlite3-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Installation de bulk-extractor depuis le code source
RUN git clone https://github.com/simsong/bulk_extractor.git \
    && cd bulk_extractor \
    && git checkout v2.0.3 \
    && autoreconf -i \
    && ./configure \
    && make \
    && make install \
    && cd .. \
    && rm -rf bulk_extractor

# Création du répertoire de travail
WORKDIR /app

# Copie des fichiers nécessaires
COPY requirements.txt .
COPY forensic_analyzer.py .

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Création des répertoires nécessaires
RUN mkdir -p /app/logs /app/output /app/input

# Configuration de ClamAV
RUN freshclam

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Point d'entrée
ENTRYPOINT ["python", "forensic_analyzer.py"]
