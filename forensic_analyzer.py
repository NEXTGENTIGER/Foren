#!/usr/bin/env python3
import os
import json
import hashlib
import subprocess
import requests
import magic
import yara
import clamd
import tempfile
import shutil
import logging
import zipfile
import platform
import sys
from datetime import datetime
from typing import Dict, Any, Optional, List, Set
from json import JSONEncoder
from pathlib import Path

# Détection du système d'exploitation
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

# Configuration des logs
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = logging.INFO
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "forensic_analyzer.log"

# Extensions de fichiers
MEMORY_EXTENSIONS = {'.dmp', '.mem', '.raw', '.img', '.dump'}
DISK_EXTENSIONS = {'.dd', '.img', '.raw', '.vmdk', '.vhd', '.vhdx'}

# Niveaux de risque
RISK_LEVELS = {
    'LOW': 0,
    'MEDIUM': 1,
    'HIGH': 2,
    'CRITICAL': 3
}

# Configuration des outils selon l'OS
TOOLS = {
    'clamav': {
        'commands': {
            'Windows': ['clamd.exe', 'clamdscan.exe'],
            'Linux': ['clamd', 'clamdscan'],
            'Darwin': ['clamd', 'clamdscan']
        },
        'required': True
    },
    'yara': {
        'commands': {
            'Windows': ['yara.exe'],
            'Linux': ['yara'],
            'Darwin': ['yara']
        },
        'required': True
    },
    'volatility': {
        'commands': {
            'Windows': ['volatility3.exe', 'vol.py', 'volatility.exe'],
            'Linux': ['volatility3', 'vol.py', 'volatility'],
            'Darwin': ['volatility3', 'vol.py', 'volatility']
        },
        'required': False
    },
    'sleuthkit': {
        'commands': {
            'Windows': ['fls.exe'],
            'Linux': ['fls'],
            'Darwin': ['fls']
        },
        'required': False
    },
    'bulk_extractor': {
        'commands': {
            'Windows': ['bulk_extractor.exe'],
            'Linux': ['bulk_extractor'],
            'Darwin': ['bulk_extractor']
        },
        'required': False
    },
    'exiftool': {
        'commands': {
            'Windows': ['exiftool.exe'],
            'Linux': ['exiftool'],
            'Darwin': ['exiftool']
        },
        'required': True
    }
}

class DateTimeEncoder(JSONEncoder):
    """Encodeur personnalisé pour gérer les objets datetime dans le JSON."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class ForensicAnalyzer:
    def __init__(self, target_file: str, api_endpoint: str = "http://127.0.0.1:5000/api/v1/report/upload_json/",
                 output_dir: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.target_file = Path(target_file).resolve()
        self.api_endpoint = api_endpoint
        self.temp_dir = None
        self.output_dir = Path(output_dir) if output_dir else self.target_file.parent
        self.logger = logger or logging.getLogger('forensic_analyzer')
        self.os_type = platform.system()
        
        # Création du répertoire de sortie si nécessaire
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.report = {
            "fichier": {},
            "metadonnees": {},
            "analyse_clamav": {},
            "analyse_yara": {},
            "analyse_volatility": {},
            "analyse_sleuthkit": {},
            "bulk_extractor": {},
            "timestamp_analyse": datetime.now().isoformat(),
            "evaluation_risque": {},
            "systeme": {
                "os": self.os_type,
                "version": platform.version(),
                "architecture": platform.machine()
            }
        }

    def __enter__(self):
        """Context manager pour la gestion du dossier temporaire."""
        self.temp_dir = tempfile.TemporaryDirectory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Nettoyage du dossier temporaire à la sortie."""
        if self.temp_dir:
            self.temp_dir.cleanup()

    def _get_tool_command(self, tool_name: str) -> Optional[str]:
        """Retourne la commande appropriée pour l'outil selon l'OS."""
        if tool_name not in TOOLS:
            return None
        
        commands = TOOLS[tool_name]['commands'].get(self.os_type, [])
        for cmd in commands:
            if shutil.which(cmd):
                return cmd
        return None

    def _safe_subprocess_run(self, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Exécute une commande de manière sécurisée."""
        try:
            # Sur Windows, si le chemin contient des espaces, il faut l'entourer de guillemets
            if IS_WINDOWS:
                cmd = [f'"{c}"' if ' ' in c else c for c in cmd]
            
            self.logger.debug(f"Exécution de la commande: {' '.join(cmd)}")
            
            # Sur Windows, on utilise shell=True pour gérer les chemins avec espaces
            if IS_WINDOWS:
                kwargs['shell'] = True
                cmd = ' '.join(cmd)
            
            return subprocess.run(cmd, **kwargs)
        except subprocess.SubprocessError as e:
            self.logger.error(f"Erreur lors de l'exécution de la commande {' '.join(cmd)}: {str(e)}")
            raise RuntimeError(f"Erreur lors de l'exécution de la commande {' '.join(cmd)}: {str(e)}")

    def _is_memory_dump(self) -> bool:
        """Détermine si le fichier est un dump mémoire."""
        if self.target_file.suffix.lower() in MEMORY_EXTENSIONS:
            return True

        try:
            # Sur Windows, on utilise python-magic-bin
            if IS_WINDOWS:
                mime = magic.Magic(mime=True)
            else:
                mime = magic.Magic(mime=True)
            
            file_type = mime.from_file(str(self.target_file))
            return "memory" in file_type.lower() or "dump" in file_type.lower()
        except Exception:
            return False

    def _is_disk_image(self) -> bool:
        """Détermine si le fichier est une image disque."""
        if self.target_file.suffix.lower() in DISK_EXTENSIONS:
            return True

        try:
            # Sur Windows, on utilise python-magic-bin
            if IS_WINDOWS:
                mime = magic.Magic(mime=True)
            else:
                mime = magic.Magic(mime=True)
            
            file_type = mime.from_file(str(self.target_file))
            return "disk" in file_type.lower() or "image" in file_type.lower()
        except Exception:
            return False

    def calculate_hashes(self) -> None:
        """Calcule les hashs MD5 et SHA256 du fichier."""
        self.logger.info("Calcul des hashs du fichier...")
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(self.target_file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        self.report["fichier"].update({
            "nom": self.target_file.name,
            "taille": self.target_file.stat().st_size,
            "date_modif": datetime.fromtimestamp(self.target_file.stat().st_mtime).isoformat(),
            "hashes": {
                "md5": md5_hash.hexdigest(),
                "sha256": sha256_hash.hexdigest()
            }
        })
        self.logger.info("Hashs calculés avec succès")

    def extract_metadata(self) -> None:
        """Extrait les métadonnées avec ExifTool."""
        self.logger.info("Extraction des métadonnées...")
        try:
            exiftool_cmd = self._get_tool_command('exiftool')
            if not exiftool_cmd:
                raise RuntimeError("ExifTool n'est pas installé ou n'est pas dans le PATH")

            result = self._safe_subprocess_run(
                [exiftool_cmd, "-json", str(self.target_file)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                metadata = json.loads(result.stdout)[0]
                self.report["metadonnees"] = self._convert_to_json_compatible(metadata)
                self.logger.info("Métadonnées extraites avec succès")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'extraction des métadonnées: {str(e)}")
            self.report["metadonnees"]["error"] = str(e)

    def scan_clamav(self) -> None:
        """Analyse le fichier avec ClamAV."""
        self.logger.info("Analyse avec ClamAV...")
        try:
            # Essai d'abord avec clamd
            try:
                if IS_WINDOWS:
                    cd = clamd.ClamdNetworkSocket()
                else:
                    cd = clamd.ClamdUnixSocket()
                
                result = cd.scan(str(self.target_file))
                if result and str(self.target_file) in result:
                    self.report["analyse_clamav"] = {
                        "statut": "FOUND" if result[str(self.target_file)][0] == "FOUND" else "OK",
                        "signature": result[str(self.target_file)][1] if result[str(self.target_file)][0] == "FOUND" else None,
                        "timestamp_scan": datetime.now().isoformat(),
                        "methode": "clamd"
                    }
                    self.logger.info("Analyse ClamAV (clamd) terminée")
                    return
            except Exception as e:
                self.logger.warning(f"Échec de l'utilisation de clamd: {str(e)}")

            # Fallback sur clamdscan
            clamdscan_cmd = self._get_tool_command('clamav')
            if not clamdscan_cmd:
                raise RuntimeError("ClamAV n'est pas installé ou n'est pas dans le PATH")

            result = self._safe_subprocess_run(
                [clamdscan_cmd, str(self.target_file)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.report["analyse_clamav"] = {
                    "statut": "OK",
                    "signature": None,
                    "timestamp_scan": datetime.now().isoformat(),
                    "methode": "clamdscan"
                }
            elif result.returncode == 1:
                self.report["analyse_clamav"] = {
                    "statut": "FOUND",
                    "signature": result.stdout.strip(),
                    "timestamp_scan": datetime.now().isoformat(),
                    "methode": "clamdscan"
                }
            self.logger.info("Analyse ClamAV (clamdscan) terminée")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse ClamAV: {str(e)}")
            self.report["analyse_clamav"]["error"] = str(e)

    def scan_yara(self, rules_path: str) -> None:
        """Analyse le fichier avec YARA."""
        self.logger.info("Analyse avec YARA...")
        try:
            rules = yara.compile(rules_path)
            matches = rules.match(str(self.target_file))
            self.report["analyse_yara"] = {
                "regles_match": [match.rule for match in matches],
                "timestamp_scan": datetime.now().isoformat()
            }
            self.logger.info(f"Analyse YARA terminée: {len(matches)} règles matchées")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse YARA: {str(e)}")
            self.report["analyse_yara"]["error"] = str(e)

    def analyze_volatility(self) -> None:
        """Analyse mémoire avec Volatility si c'est un dump mémoire."""
        if not self._is_memory_dump():
            self.logger.info("Le fichier n'est pas un dump mémoire, analyse Volatility ignorée")
            self.report["analyse_volatility"]["status"] = "Not a memory dump"
            return

        self.logger.info("Analyse avec Volatility...")
        try:
            volatility_results = {}
            
            # Détermine la commande Volatility à utiliser
            volatility_cmd = self._get_tool_command('volatility')
            if not volatility_cmd:
                raise RuntimeError("Volatility n'est pas installé ou n'est pas dans le PATH")
            
            # Analyse des processus
            proc = self._safe_subprocess_run(
                [volatility_cmd, "-f", str(self.target_file), "windows.pslist"],
                capture_output=True,
                text=True
            )
            if proc.returncode == 0:
                volatility_results["processus_liste"] = self._parse_volatility_output(proc.stdout)

            # Analyse des connexions réseau
            net = self._safe_subprocess_run(
                [volatility_cmd, "-f", str(self.target_file), "windows.netscan"],
                capture_output=True,
                text=True
            )
            if net.returncode == 0:
                volatility_results["connexions_reseau"] = self._parse_volatility_output(net.stdout)

            volatility_results["timestamp_analyse"] = datetime.now().isoformat()
            volatility_results["version_volatility"] = volatility_cmd
            self.report["analyse_volatility"] = volatility_results
            self.logger.info("Analyse Volatility terminée")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse Volatility: {str(e)}")
            self.report["analyse_volatility"]["error"] = str(e)

    def _parse_volatility_output(self, output: str) -> List[Dict]:
        """Parse la sortie de Volatility en JSON."""
        lines = output.strip().split('\n')
        if not lines:
            return []
        
        # Extrait les en-têtes
        headers = [h.strip() for h in lines[0].split()]
        
        # Parse les données
        results = []
        for line in lines[1:]:
            values = line.split()
            if len(values) == len(headers):
                results.append(dict(zip(headers, values)))
        
        return results

    def analyze_sleuthkit(self) -> None:
        """Analyse le système de fichiers avec SleuthKit."""
        if not self._is_disk_image():
            self.logger.info("Le fichier n'est pas une image disque, analyse SleuthKit ignorée")
            self.report["analyse_sleuthkit"]["status"] = "Not a disk image"
            return

        self.logger.info("Analyse avec SleuthKit...")
        try:
            sleuthkit_results = {}
            
            # Liste des fichiers
            fls_cmd = self._get_tool_command('sleuthkit')
            if not fls_cmd:
                raise RuntimeError("SleuthKit n'est pas installé ou n'est pas dans le PATH")

            fls = self._safe_subprocess_run(
                [fls_cmd, str(self.target_file)],
                capture_output=True,
                text=True
            )
            if fls.returncode == 0:
                sleuthkit_results["fichiers"] = fls.stdout.splitlines()

            sleuthkit_results["timestamp_analyse"] = datetime.now().isoformat()
            self.report["analyse_sleuthkit"] = sleuthkit_results
            self.logger.info("Analyse SleuthKit terminée")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse SleuthKit: {str(e)}")
            self.report["analyse_sleuthkit"]["error"] = str(e)

    def run_bulk_extractor(self) -> None:
        """Extrait les informations avec Bulk Extractor."""
        if not self.temp_dir:
            raise RuntimeError("Le dossier temporaire n'est pas initialisé")

        self.logger.info("Analyse avec Bulk Extractor...")
        try:
            bulk_results = {}
            output_dir = os.path.join(self.temp_dir.name, "bulk_output")
            os.makedirs(output_dir, exist_ok=True)

            bulk_cmd = self._get_tool_command('bulk_extractor')
            if not bulk_cmd:
                raise RuntimeError("Bulk Extractor n'est pas installé ou n'est pas dans le PATH")

            result = self._safe_subprocess_run(
                [bulk_cmd, "-o", output_dir, str(self.target_file)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self._process_bulk_extractor_output(output_dir, bulk_results)
            
            bulk_results["timestamp_analyse"] = datetime.now().isoformat()
            self.report["bulk_extractor"] = bulk_results
            self.logger.info("Analyse Bulk Extractor terminée")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse Bulk Extractor: {str(e)}")
            self.report["bulk_extractor"]["error"] = str(e)

    def _process_bulk_extractor_output(self, output_dir: str, results: Dict) -> None:
        """Traite les fichiers de sortie de bulk_extractor."""
        try:
            # Lecture des emails
            email_file = os.path.join(output_dir, "email.txt")
            if os.path.exists(email_file):
                with open(email_file, "r", encoding='utf-8') as f:
                    results["emails"] = f.read().splitlines()
            
            # Lecture des URLs
            url_file = os.path.join(output_dir, "url.txt")
            if os.path.exists(url_file):
                with open(url_file, "r", encoding='utf-8') as f:
                    results["urls"] = f.read().splitlines()
        except Exception as e:
            results["error"] = str(e)

    def _convert_to_json_compatible(self, data: Any) -> Any:
        """Convertit les données en format JSON-compatible."""
        if isinstance(data, dict):
            return {k: self._convert_to_json_compatible(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._convert_to_json_compatible(item) for item in data]
        elif isinstance(data, (datetime, bytes)):
            return str(data)
        return data

    def assess_risk(self) -> str:
        """Évalue le niveau de risque basé sur les analyses."""
        risk_level = "LOW"
        risk_factors = []

        # Vérification ClamAV
        if self.report["analyse_clamav"].get("statut") == "FOUND":
            risk_level = "HIGH"
            risk_factors.append(f"Malware détecté par ClamAV: {self.report['analyse_clamav'].get('signature')}")

        # Vérification YARA
        if self.report["analyse_yara"].get("regles_match"):
            if risk_level == "LOW":
                risk_level = "HIGH"
            risk_factors.append(f"Règles YARA matchées: {', '.join(self.report['analyse_yara']['regles_match'])}")

        # Vérification Volatility
        if self.report["analyse_volatility"].get("processus_liste"):
            suspicious_processes = [p for p in self.report["analyse_volatility"]["processus_liste"] 
                                 if any(susp in p.get("Name", "").lower() for susp in ["malware", "trojan", "backdoor"])]
            if suspicious_processes:
                if risk_level == "LOW":
                    risk_level = "MEDIUM"
                risk_factors.append(f"Processus suspects détectés: {', '.join(p.get('Name') for p in suspicious_processes)}")

        # Mise à jour du rapport
        self.report["evaluation_risque"] = {
            "niveau": risk_level,
            "facteurs": risk_factors,
            "timestamp": datetime.now().isoformat()
        }

        return risk_level

    def generate_json_report(self) -> str:
        """Génère le rapport au format JSON avec indentation."""
        return json.dumps(self.report, indent=2, cls=DateTimeEncoder, ensure_ascii=False)

    def create_zip_archive(self) -> Path:
        """Crée une archive ZIP contenant tous les résultats."""
        zip_path = self.output_dir / f"{self.target_file.stem}_analysis.zip"
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Ajout du rapport JSON
            report_path = self.output_dir / f"{self.target_file.stem}_report.json"
            zipf.write(report_path, report_path.name)
            
            # Ajout des fichiers de sortie de Bulk Extractor si présents
            if self.temp_dir:
                bulk_dir = os.path.join(self.temp_dir.name, "bulk_output")
                if os.path.exists(bulk_dir):
                    for root, _, files in os.walk(bulk_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Utilisation de Path pour gérer les chemins de manière compatible avec l'OS
                            arcname = str(Path(file_path).relative_to(self.temp_dir.name))
                            zipf.write(file_path, arcname)
        
        return zip_path

    def send_report(self) -> bool:
        """Envoie le rapport à l'API."""
        try:
            json_report = self.generate_json_report()
            response = requests.post(
                self.api_endpoint,
                json=json.loads(json_report),
                headers={"Content-Type": "application/json"}
            )
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Erreur lors de l'envoi du rapport: {str(e)}")
            return False

    def run_analysis(self, yara_rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Exécute l'analyse complète."""
        self.logger.info(f"Démarrage de l'analyse du fichier: {self.target_file}")
        
        self.calculate_hashes()
        self.extract_metadata()
        self.scan_clamav()
        
        if yara_rules_path:
            self.scan_yara(yara_rules_path)
        
        if self._is_memory_dump():
            self.analyze_volatility()
        
        if self._is_disk_image():
            self.analyze_sleuthkit()
        
        self.run_bulk_extractor()
        
        # Évaluation du risque
        self.assess_risk()
        
        # Génération du rapport JSON
        json_report = self.generate_json_report()
        
        # Sauvegarde du rapport
        report_path = self.output_dir / f"{self.target_file.stem}_report.json"
        with open(report_path, "w", encoding='utf-8') as f:
            f.write(json_report)
        self.logger.info(f"Rapport sauvegardé dans {report_path}")
        
        # Création de l'archive ZIP
        zip_path = self.create_zip_archive()
        self.logger.info(f"Archive créée: {zip_path}")
        
        return self.report

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure le système de logging."""
    # Création du dossier de logs si nécessaire
    LOG_DIR.mkdir(exist_ok=True)
    
    # Configuration du logger
    logger = logging.getLogger('forensic_analyzer')
    logger.setLevel(logging.DEBUG if verbose else LOG_LEVEL)
    
    # Handler pour fichier
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(file_handler)
    
    # Handler pour console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(console_handler)
    
    return logger

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Analyse forensique de fichiers suspects")
    parser.add_argument("file", help="Chemin du fichier à analyser")
    parser.add_argument("--yara-rules", help="Chemin vers les règles YARA")
    parser.add_argument("--api-endpoint", default="http://127.0.0.1:5000/api/v1/report/upload_json/",
                      help="Endpoint de l'API pour l'envoi du rapport")
    parser.add_argument("--output-dir", help="Répertoire de sortie pour les résultats")
    parser.add_argument("--no-upload", action="store_true", help="Ne pas envoyer le rapport à l'API")
    parser.add_argument("--verbose", "-v", action="store_true", help="Mode verbeux")
    
    args = parser.parse_args()
    
    # Configuration du logging
    logger = setup_logging(args.verbose)
    
    try:
        # Création des dossiers nécessaires
        for dir_name in ['input', 'output', 'logs']:
            Path(dir_name).mkdir(exist_ok=True)
        
        # Copie du fichier dans le dossier input si nécessaire
        input_file = Path(args.file)
        if not input_file.is_absolute():
            input_file = Path('input') / input_file.name
            shutil.copy2(args.file, input_file)
        
        # Création de l'analyseur
        analyzer = ForensicAnalyzer(
            str(input_file),
            args.api_endpoint,
            args.output_dir,
            logger
        )
        
        # Exécution de l'analyse
        print("\n🔍 Démarrage de l'analyse...")
        report = analyzer.run_analysis(args.yara_rules)
        
        # Affichage des résultats
        print("\n✅ Analyse terminée!")
        print(f"📁 Rapport JSON: output/{input_file.stem}_report.json")
        print(f"📦 Archive ZIP: output/{input_file.stem}_analysis.zip")
        print(f"📝 Logs: logs/forensic_analyzer.log")
        
        # Niveau de risque
        risk_level = report['evaluation_risque']['niveau']
        print(f"\n⚠️ Niveau de risque: {risk_level}")
        if report['evaluation_risque']['facteurs']:
            print("Facteurs de risque:")
            for factor in report['evaluation_risque']['facteurs']:
                print(f"  - {factor}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 