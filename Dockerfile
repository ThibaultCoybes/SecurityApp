# Image de base Python
FROM python:3

# Définir le dossier de travail
WORKDIR /app

# Installer les dépendances système nécessaires pour mysqlclient
RUN apt-get update && apt-get install -y \
    pkg-config \
    default-libmysqlclient-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers nécessaires
COPY requirements.txt requirements.txt

# Installer les dépendances Python
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copier le reste du projet
COPY . .

# Exposer le port Flask
EXPOSE 5000

# Lancer l'application
CMD ["python", "app.py"]
