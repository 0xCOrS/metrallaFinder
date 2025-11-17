#!/usr/bin/env python3
"""
Autor: 0xCOrS (with a little help from my friends (claude and google))
Script de Recolección de subdominios y URLs
Versión: 7
"""

import os
import re
import sys
import time
import json
import socket
import random
import logging
import requests
import argparse
import ipaddress
import subprocess
from pathlib import Path
from bs4 import BeautifulSoup
from typing import Set, List, Dict
from urllib.parse import urlparse



class BBHuntingTool:
    """Herramienta para Recon"""
    CDN_CLOUD_ASNS = {
        'AS13335', 'AS209242', 'AS394536',  # Cloudflare
        'AS16509', 'AS14618', 'AS8987',    # AWS
        'AS15169', 'AS396982',             # Google
        'AS8075', 'AS12076',               # Azure
        'AS16625', 'AS32787', 'AS35994',   # Akamai
        'AS54113',                         # Fastly
        'AS16276',                         # OVH
        'AS14061',                         # DigitalOcean
        'AS63949',                         # Linode
    }
    
    def __init__(self, domain: str, base_dir: str = "/home/kali/Desktop/BBHunting"):
        self.domain = domain
        self.base_dir = Path(base_dir)
        self.asn_info = {}  # Información del ASN disponible globalmente
        self.setup_directories()
        self.setup_logging()
        
    def setup_directories(self):
        """Configura la estructura de directorios"""
        self.domain_dir = self.base_dir / self.domain
        self.dirs = {
            'subs': self.domain_dir / "subs", 
            'urls': self.domain_dir / "urls",
            'urlsCC': self.domain_dir / "urlsCC",
            'urls200': self.domain_dir / "200urls",
            'js_files': self.domain_dir / "js_files",
            'json_files': self.domain_dir / "json_files",
            'pdf_files': self.domain_dir / "pdf_files",
            'php_files': self.domain_dir / "php_files",
            'java_files': self.domain_dir / "java_files",
            'exe_files': self.domain_dir / "exe_files",
            'old_files': self.domain_dir / "old_files",
            'bak_files': self.domain_dir / "bak_files",
            'zip_files': self.domain_dir / "zip_files",
            'docx_files': self.domain_dir / "docx_files",
            'xlsx_files': self.domain_dir / "xlsx_files",
            'xls_files': self.domain_dir / "xls_files",
            'txt_files': self.domain_dir / "txt_files",
            'accdb_files': self.domain_dir / "accdb_files",
            'sql_files': self.domain_dir / "sql_files",
            'mdb_files': self.domain_dir / "mdb_files",
            'mdw_files': self.domain_dir / "mdw_files"
        }
        
        # Crear solo directorios base (no los de archivos específicos)
        base_dirs = ['subs', 'urls', 'urls200', 'urlsCC']
        for dir_name in base_dirs:
            self.dirs[dir_name].mkdir(parents=True, exist_ok=True)
            
        os.chdir(self.domain_dir)
        
    def setup_logging(self):
        """Configura el sistema de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.domain_dir / 'bbhunting.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def print_step_banner(self, step_number: int, title: str, description: str = ""):
        """Imprime un banner visual para cada paso del proceso"""
        print()
        print("=" * 80)
        print(f"🔹 PASO {step_number}: {title.upper()}")
        if description:
            print(f"   {description}")
        print("=" * 80)
        
    def print_substep(self, text: str):
        """Imprime un sub-paso con formato visual"""
        print(f"   ▶ {text}")
        
    def print_result(self, text: str, success: bool = True):
        """Imprime un resultado con formato visual"""
        icon = "✅" if success else "❌"
        print(f"   {icon} {text}")
        
    def print_info(self, text: str):
        """Imprime información adicional"""
        print(f"   ℹ️  {text}")
        
    def print_warning(self, text: str):
        """Imprime una advertencia"""
        print(f"   ⚠️  {text}")
        
    def make_request_with_retries(self, url: str, max_retries: int = 5, timeout: int = 60) -> requests.Response:
        """
        Petición HTTP con reintentos ANTI-RATE-LIMIT
        → Pausas largas en 429
        → Rotación de User-Agent
        → SIN fallback local (como pediste)
        """
        user_agents = [
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        ]
    
        for attempt in range(1, max_retries + 1):
            try:
                headers = {
                    'User-Agent': random.choice(user_agents),
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache'
                }
            
                response = requests.get(url, headers=headers, timeout=timeout)
            
                # === 429: RATE LIMIT DETECTADO ===
                if response.status_code == 429:
                    wait_time = min(120 * attempt, 600)  # 2min → 4min → 6min → 8min → 10min
                    self.print_warning(f"429 Too Many Requests (intento {attempt}/{max_retries})")
                    self.print_info(f"Esperando {wait_time} segundos antes de reintentar...")
                    time.sleep(wait_time)
                    continue  # Reintenta con nuevo User-Agent
            
                response.raise_for_status()
                return response

            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    wait_time = 30 * attempt
                    self.print_warning(f"Timeout (intento {attempt}/{max_retries}). Esperando {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise
        
            except requests.exceptions.RequestException as e:
                if attempt < max_retries:
                    wait_time = 15 * attempt
                    self.print_warning(f"Error {e} (intento {attempt}/{max_retries}). Esperando {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    self.logger.error(f"Error final tras {max_retries} intentos: {e}")
                    raise

    def make_request(self, url: str, timeout: int = 30) -> requests.Response:
        """Método de compatibilidad - usa make_request_with_retries"""
        return self.make_request_with_retries(url, max_retries=3, timeout=timeout)
            
    def save_subdomains(self, subdomains: Set[str], filename: str) -> None:
        """Guarda subdominios en un archivo"""
        filepath = self.dirs['subs'] / filename
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for subdomain in sorted(subdomains):
                    f.write(f"{subdomain}\n")
            self.logger.info(f"Guardados {len(subdomains)} subdominios en {filename}")
        except IOError as e:
            self.logger.error(f"Error guardando {filename}: {e}")
            
    def save_urls_by_subdomain(self, subdomain_urls: Dict[str, List[str]], 
                             output_dir: Path) -> None:
        """Guarda URLs organizadas por subdominio"""
        try:
            for subdomain, urls in subdomain_urls.items():
                filepath = output_dir / f"{subdomain}.txt"
                with open(filepath, 'w', encoding='utf-8') as f:
                    for url in urls:
                        f.write(f"{url}\n")
                self.logger.info(f"Guardadas {len(urls)} URLs para {subdomain}")
        except IOError as e:
            self.logger.error(f"Error guardando URLs: {e}")
            
    def extract_subdomain_from_url(self, url: str) -> str:
        """Extrae el subdominio de una URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.split(':')[0]
        except Exception:
            # Fallback al método original si urlparse falla
            parts = url.split('/')
            if len(parts) > 2:
                return parts[2].split(':')[0]
            return ""
            
    def get_asn_info(self) -> Dict[str, str]:
        """Obtiene información del ASN del dominio principal"""
        self.logger.info("Obteniendo información del ASN...")
        
        try:
            ip = socket.gethostbyname(self.domain)
            self.print_substep(f"IP del dominio: {ip}")
            
            # Obtener información del ASN
            response = self.make_request_with_retries(f"https://ipinfo.io/{ip}/json", max_retries=3, timeout=30)
            data = response.json()
            
            asn_info = {
                'ip': ip,
                'asn': data.get('org', 'N/A'),
                'country': data.get('country', 'N/A'),
                'region': data.get('region', 'N/A'),
                'city': data.get('city', 'N/A'),
                'hostname': data.get('hostname', 'N/A')
            }
            
            # Guardar información del ASN
            asn_file = self.dirs['subs'] / 'asn_info.txt'
            with open(asn_file, 'w') as f:
                f.write(f"Dominio: {self.domain}\n")
                f.write(f"IP: {asn_info['ip']}\n")
                f.write(f"ASN: {asn_info['asn']}\n")
                f.write(f"País: {asn_info['country']}\n")
                f.write(f"Región: {asn_info['region']}\n")
                f.write(f"Ciudad: {asn_info['city']}\n")
                f.write(f"Hostname: {asn_info['hostname']}\n")
            
            self.print_result(f"ASN: {asn_info['asn']}")
            self.print_info(f"Ubicación: {asn_info['city']}, {asn_info['region']}, {asn_info['country']}")
            
            return asn_info
            
        except socket.gaierror as e:
            self.logger.error(f"Error resolviendo dominio {self.domain}: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Error obteniendo información ASN: {e}")
            return {}
            
    def wa_subs(self) -> Set[str]:
        """Obtiene subdominios desde Wayback Machine con reintentos"""
        self.print_substep("Consultando Wayback Machine...")
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey&from="
        
        try:
            # Usar método con reintentos para Wayback Machine
            response = self.make_request_with_retries(url, max_retries=5, timeout=90)
            subdomain_urls = {}
            subdomains = set()
            
            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                subdomain = self.extract_subdomain_from_url(line)
                if subdomain:
                    subdomains.add(subdomain)
                    
                    if subdomain not in subdomain_urls:
                        subdomain_urls[subdomain] = []
                    subdomain_urls[subdomain].append(line)
            
            self.save_urls_by_subdomain(subdomain_urls, self.dirs['urls'])
            self.save_subdomains(subdomains, 'wa-subs.txt')
            
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Error obteniendo subdominios de WA después de todos los reintentos: {e}")
            self.print_result(f"Error en Wayback Machine: {e}", success=False)
            return set()
            
    def wa_urls_200(self) -> Set[str]:
        """Obtiene URLs con status 200 desde Wayback Machine con reintentos"""
        self.print_substep("Consultando Wayback Machine (200s)...")
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200"
        
        try:
            # Usar método con reintentos para Wayback Machine
            response = self.make_request_with_retries(url, max_retries=5, timeout=90)
            subdomain_urls = {}
            subdomains = set()
            
            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                subdomain = self.extract_subdomain_from_url(line)
                if subdomain:
                    subdomains.add(subdomain)
                    
                    if subdomain not in subdomain_urls:
                        subdomain_urls[subdomain] = []
                    subdomain_urls[subdomain].append(line)
            
            self.save_urls_by_subdomain(subdomain_urls, self.dirs['urls200'])
            self.save_subdomains(subdomains, 'wa-200-subs.txt')
            
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Error obteniendo URLs 200 de WA después de todos los reintentos: {e}")
            self.print_result(f"Error en Wayback Machine (200s): {e}", success=False)
            return set()
    def commoncrawl_subs(self) -> Set[str]:
        """Obtiene resultados de commoncrawl"""
        self.print_substep("Consultando Common Crawl...")
        url = f"https://index.commoncrawl.org/CC-MAIN-2025-43-index?url=*.{self.domain}/*&output=json"
        try:
            subdomain_urls = {}
            subdomains = set()
            response = self.make_request_with_retries(url, max_retries=5, timeout=90)
            json_data = []
            lines = response.text.splitlines()
            for line in lines:
                try:
                  json_data.append(json.loads(line))
                except json.JSONDecodeError:
                  print("Error JSONDecoding")
					
            t = 0;
            while  (t < len(lines)):
                url_line = json_data[t]['url']
                subdomain = self.extract_subdomain_from_url(url_line)
                if subdomain:
                    subdomains.add(subdomain)
                    if subdomain not in subdomain_urls:
                        subdomain_urls[subdomain] = []
                    subdomain_urls[subdomain].append(url_line)
                t+=1
            self.save_urls_by_subdomain(subdomain_urls, self.dirs['urlsCC'])
            self.save_subdomains(subdomains, 'cc-subs.txt')
            return subdomains
        except Exception as e:
            self.logger.error(f"Error obteniendo URLs de Common Crawl después de todos los reintentos: {e}")
            self.print_result(f"Error en Common Crawl: {e}", success=False)
            return set()
		
    def sh_subs(self) -> Set[str]:
        """Obtiene subdominios desde Shodan"""
        self.print_substep("Consultando Shodan...")
        url = f"https://www.shodan.io/domain/{self.domain}"
        
        try:
            response = self.make_request(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            subdomains = set()
            
            li_tags = soup.select('#subdomains > li')
            for li in li_tags:
                subdomain = li.get_text(strip=True)
                if subdomain and subdomain != 'link':
                    subdomains.add(f"{subdomain}.{self.domain}")
            
            self.save_subdomains(subdomains, 'sh-subs.txt')
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Error obteniendo subdominios de Shodan: {e}")
            return set()
            
    def crt_subs(self) -> Set[str]:
        """Obtiene subdominios desde crt.sh"""
        self.print_substep("Consultando crt.sh...")
        url = f"https://crt.sh/?q={self.domain}"
        
        try:
            response = self.make_request(url)
            subdomains = set()
            
            for line in response.text.splitlines():
                if (self.domain in line and 
                    'crt.sh' not in line and 
                    'Type:' not in line):
                    
                    match = re.search(r'>(.*?)<', line)
                    if match:
                        subdomain = match.group(1).strip()
                        if subdomain:
                            subdomains.add(subdomain)
            
            self.save_subdomains(subdomains, 'crt-subs.txt')
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Error obteniendo subdominios de crt.sh: {e}")
            return set()

    def find_file_urls(self, extension: str, exclude_extensions: List[str]) -> None:
        """Busca URLs que apuntan a archivos de una extensión específica
        
        Args:
            extension: Extensión de archivo a buscar (ej: 'js', 'json', 'pdf')
            exclude_extensions: Lista de extensiones a excluir (ej: ['json', 'jsp'])
        """
        self.logger.info(f"Buscando URLs con archivos .{extension}...")
        if exclude_extensions:
            self.logger.info(f"Excluyendo: {', '.join([f'.{ext}' for ext in exclude_extensions])}")
        
        output_dir = self.dirs[f'{extension}_files']
        output_file = output_dir / f'{extension}_files_urls.txt'
        
        try:
            # Construir patrón de búsqueda más preciso
            # Busca .extension seguido de fin de línea, /, ?, # o espacio
            search_pattern = f"\\.{extension}\\b"
            
            # Construir comando base - cambio de directorio y grep inicial
            base_cmd = f"cd {self.dirs['urls']} && grep -ir '{search_pattern}'"
            
            # Añadir exclusiones específicas
            exclude_cmds = []
            for exclude_ext in exclude_extensions:
                exclude_pattern = f"\\.{exclude_ext}\\b"
                exclude_cmds.append(f"grep -v '{exclude_pattern}'")
            
            # Construir comando completo
            if exclude_cmds:
                cmd = f"{base_cmd} | {' | '.join(exclude_cmds)}"
            else:
                cmd = base_cmd
            
            self.logger.debug(f"Ejecutando comando: {cmd}")
            
            # Ejecutar comando
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                # Crear directorio solo si se encontraron archivos
                output_dir.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                    
                # Contar líneas de resultado
                count = len(result.stdout.strip().split('\n'))
                self.logger.info(f"✅ Encontradas {count} URLs con archivos .{extension}")
                print(f"Se encontraron {count} URLs con ficheros .{extension}")
            else:
                # NO crear directorio ni archivo si no se encontraron resultados
                count = 0
                self.logger.info(f"❌ Se encontraron {count} URLs con archivos .{extension}")
                print(f"Se encontraron {count} URLs con ficheros .{extension}")
                
        except Exception as e:
            self.logger.error(f"Error buscando URLs de archivos .{extension}: {e}")
            print(f"Error buscando ficheros .{extension}: {e}")

    def _query_httpstatus_io_web(self, urls: List[str]) -> Dict[str, Dict]:
        """Consulta httpstatus.io con rotación de User-Agent y pausas anti-rate-limit"""
        # Lista de User-Agents reales (Chrome, Firefox, Safari, etc.)
        user_agents = [
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
        ]
        try:
            selected_ua = random.choice(user_agents)
            # Headers exactos del cURL
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.8',
                'content-type': 'application/json;charset=UTF-8',
                'origin': 'https://httpstatus.io',
                'priority': 'u=1, i',
                'referer': 'https://httpstatus.io/',
                'sec-ch-ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Linux"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'sec-gpc': '1',
                'user-agent': selected_ua
            }
            
            # Payload exacto del cURL
            payload = {
                "urls": urls,
                "userAgent": "browser",
                "userName": "",
                "passWord": "",
                "headerName": "",
                "headerValue": "",
                "strictSSL": True,
                "canonicalDomain": False,
                "additionalSubdomains": ["www"],
                "followRedirect": True,
                "throttleRequests": 100,
                "escapeCharacters": False
            }
            
            self.logger.debug(f"Enviando {len(urls)} URLs a httpstatus.io backend...")
            
            # Request exacta del cURL
            time.sleep(4)
            response = requests.post(
                'https://backend-v2.httpstatus.io/api',
                headers=headers,
                json=payload,
                timeout=60
            )
            # === 429: REINTENTAR CON NUEVO UA ===
            if response.status_code == 429:
                self.print_warning("429 en httpstatus.io → reintentando con nuevo User-Agent...")
                time.sleep(120)  # 2 minutos
                return self._query_httpstatus_io_web(urls)  # ← RECURSIVO CON NUEVO UA
            
            response.raise_for_status()
            data = response.json()
            
            # Procesar respuesta JSON
            results = {}
            
            # La respuesta debería ser una lista de objetos con los resultados
            if isinstance(data, list):
                for i, result in enumerate(data):
                    if i < len(urls):
                        url = urls[i]
                        results[url] = {
                            'status_code': result.get('statusCode'),
                            'response_time': result.get('responseTime'),
                            'content_length': result.get('contentLength'),
                            'final_url': result.get('finalUrl', url),
                            'error': result.get('error')
                        }
            elif isinstance(data, dict):
                # Si es un dict, puede tener diferentes estructuras
                if 'results' in data:
                    for i, result in enumerate(data['results']):
                        if i < len(urls):
                            url = urls[i]
                            results[url] = {
                                'status_code': result.get('statusCode') or result.get('status_code'),
                                'response_time': result.get('responseTime') or result.get('response_time'),
                                'content_length': result.get('contentLength') or result.get('content_length'),
                                'final_url': result.get('finalUrl') or result.get('final_url') or url,
                                'error': result.get('error')
                            }
                else:
                    # Estructura directa
                    for i, url in enumerate(urls):
                        if str(i) in data or url in data:
                            result = data.get(str(i)) or data.get(url)
                            results[url] = {
                                'status_code': result.get('statusCode') or result.get('status_code'),
                                'response_time': result.get('responseTime') or result.get('response_time'),
                                'content_length': result.get('contentLength') or result.get('content_length'),
                                'final_url': result.get('finalUrl') or result.get('final_url') or url,
                                'error': result.get('error')
                            }
            
            self.logger.debug(f"Recibidos resultados para {len(results)} URLs")
            return results
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error de conexión con httpstatus.io backend: {e}")
            # Fallback a verificación directa
            raise
        except requests.exceptions.JSONDecodeError as e:
            self.logger.error(f"Error parseando JSON de httpstatus.io: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error procesando respuesta httpstatus.io: {e}")
            raise
            

    def check_subdomain_status(self, protocol: str = "http") -> Dict[str, Dict]:
        """Verifica el estado de subdominios usando httpstatus.io → SOLO 2 ARCHIVOS"""
        self.logger.info(f"Verificando subdominios activos via {protocol.upper()}...")

        all_subs_file = self.dirs['subs'] / 'all-subs.txt'
        if not all_subs_file.exists():
            self.logger.error("Archivo all-subs.txt no encontrado")
            return {}

        with open(all_subs_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]

        if not subdomains:
            self.logger.warning("No hay subdominios para verificar")
            return {}

        self.logger.info(f"Verificando {len(subdomains)} subdominios via {protocol.upper()}")

        status_dir = self.domain_dir / "status_check"
        status_dir.mkdir(parents=True, exist_ok=True)

        active_subdomains = {}
        batch_size = 99
        total_batches = (len(subdomains) + batch_size - 1) // batch_size

        self.print_substep(f"Procesando en {total_batches} lotes de {batch_size} subdominios...")

        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            batch_num = (i // batch_size) + 1

            self.print_substep(f"Lote {batch_num}/{total_batches}: {len(batch)} subdominios")

            urls = [f"{protocol}://{subdomain}" for subdomain in batch]

            try:
                batch_results = self._query_httpstatus_io_web(urls)

                for subdomain, url in zip(batch, urls):
                    if url in batch_results:
                        result = batch_results[url]
                        status_code = result.get('status_code')
                        if status_code is not None and status_code != 'error':
                            try:
                                status_code = int(status_code)
                                if 200 <= status_code < 600:
                                    active_subdomains[subdomain] = result
                            except (ValueError, TypeError):
                                continue

                if batch_num < total_batches:
                    time.sleep(2)

            except Exception as e:
                self.logger.error(f"Error procesando lote {batch_num}: {e}")
                continue

        # === GUARDAR SOLO 2 ARCHIVOS ===
        active_file = status_dir / f'active_{protocol}_subdomains.txt'
        with open(active_file, 'w') as f:
            f.write(f"# Subdominios activos via {protocol.upper()}\n")
            f.write(f"# Total encontrados: {len(active_subdomains)}\n\n")
            for subdomain in sorted(active_subdomains.keys()):
                f.write(f"{subdomain}\n")

        self.print_result(f"Subdominios activos {protocol.upper()}: {len(active_subdomains)}/{len(subdomains)}")
        return active_subdomains

    def check_all_protocols(self):
        """Verifica subdominios en HTTP y HTTPS → SOLO 2 ARCHIVOS"""
        self.print_substep("Verificando subdominios HTTP...")
        http_results = self.check_subdomain_status("http")

        time.sleep(5)

        self.print_substep("Verificando subdominios HTTPS...")
        https_results = self.check_subdomain_status("https")

        # Resumen simple
        both = len(set(http_results.keys()) & set(https_results.keys()))
        self.print_result(f"HTTP: {len(http_results)} | HTTPS: {len(https_results)} | Ambos: {both}")


    def gowitness_screenshots(self):
        """Ejecuta gowitness para tomar capturas de pantalla de todos los subdominios activos"""
        self.logger.info("Iniciando capturas de pantalla con gowitness...")
        
        status_dir = self.domain_dir / "status_check"
        if not status_dir.exists():
            self.logger.error("Directorio status_check no encontrado. Ejecuta primero check_all_protocols()")
            return
        
        # Archivos de subdominios activos
        http_file = status_dir / 'active_http_subdomains.txt'
        https_file = status_dir / 'active_https_subdomains.txt'
        
        # Crear directorio para capturas
        screenshots_dir = self.domain_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        
        # Combinar subdominios HTTP y HTTPS en una sola lista
        combined_subdomains = []
        all_subdomains_set = set()  # Para evitar duplicados exactos
        
        # Leer subdominios HTTP
        if http_file.exists():
            with open(http_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        subdo = line
                        if subdo not in all_subdomains_set:  # Evitar duplicados exactos
                            combined_subdomains.append(subdo)
                            all_subdomains_set.add(subdo)
                        else:
                            self.logger.debug(f"Duplicado detectado y omitido: {subdo}")
        
        # Leer subdominios HTTPS
        if https_file.exists():
            with open(https_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        subdo = line
                        if subdo not in all_subdomains_set:  # Evitar duplicados exactos
                            combined_subdomains.append(subdo)
                            all_subdomains_set.add(subdo)
                        else:
                            self.logger.debug(f"Duplicado detectado y omitido: {subdo}")
        
        if not combined_subdomains:
            self.logger.warning("No se encontraron subdominios activos para capturas")
            return
        
        # Crear archivo temporal con todas las URLs combinadas SIN DUPLICADOS
        combined_file = screenshots_dir / 'all_active_subdomains.txt'
        with open(combined_file, 'w') as f:
            for subdo in combined_subdomains:
                f.write(f"{subdo}\n")
        
        # Verificar que no hay duplicados en el archivo
        unique_subdos = list(set(combined_subdomains))
        if len(unique_subdos) != len(combined_subdomains):
            duplicates_found = len(combined_subdomains) - len(unique_subdos)
            self.print_warning(f"Encontrados {duplicates_found} duplicados exactos - eliminando...")
            
            # Reescribir archivo sin duplicados
            with open(combined_file, 'w') as f:
                for subdo in unique_subdos:
                    f.write(f"{subdo}\n")
            combined_subdomains = unique_subdos
        
        
        # Ejecutar gowitness una sola vez con todas las URLs
        self._run_gowitness_single_execution(combined_file, screenshots_dir)
        
        self.print_result("Capturas de pantalla completadas")
        self.print_info(f"Capturas guardadas en: {screenshots_dir}")
        self.print_info(f"Índice HTML: {screenshots_dir}/index.html")

    def _run_gowitness_single_execution(self, input_file: Path, output_dir: Path):
        """Ejecuta GoWitness una sola vez con todas las URLs"""
        
        # Verificar que el archivo existe y no está vacío
        if not input_file.exists() or input_file.stat().st_size == 0:
            self.logger.warning(f"Archivo {input_file} no existe o está vacío")
            return
        
        # Contar Subdominios
        with open(input_file, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            
        if not lines:
            self.logger.warning(f"No hay Subdominios válidos en {input_file}")
            return
            
        subdos_count = len(lines)
        self.logger.info(f"Procesando {subdos_count} Subdominios...")
        
        # Cambiar al directorio de screenshots
        original_dir = os.getcwd()
        os.chdir(output_dir)
        
        try:
            # Construir comando GoWitness unificado
            cmd = [
                "gowitness",
                "scan",
                "file",
                "-f", str(input_file),
                "--write-csv"
            ]
            
            self.logger.info(f"Ejecutando: {' '.join(cmd)}")
            self.print_substep(f"Ejecutando GoWitness en {subdos_count} URLs...")
            
            # Ejecutar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 60 s timeout (más tiempo para más URLs)
            )
            
            if result.returncode == 0:
                self.logger.info(f"✅ GoWitness completado exitosamente")
                self.print_result("GoWitness completado exitosamente")
                
                # Mostrar estadísticas si hay output
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    self.logger.info(f"Output GoWitness: {result.stdout}")
                    self.print_info(f"Subdominios procesados: {len(lines)}")
                    
            else:
                self.logger.error(f"Error en GoWitness: {result.stderr}")
                self.print_result(f"Error en GoWitness: {result.stderr}", success=False)
                
            # Contar archivos generados (buscar en subdirectorios también)
            screenshot_files = []
            
            # Buscar en directorio base
            screenshot_files.extend(list(output_dir.glob("*.jpeg")))
            
            # Buscar en subdirectorios (estructura de gowitness)
            screenshot_files.extend(list(output_dir.glob("**/*.jpeg")))
            
            # Eliminar duplicados (en caso de que haya)
            screenshot_files = list(set([str(f) for f in screenshot_files]))
                
            self.logger.info(f"Capturas generadas: {len(screenshot_files)}")
            self.print_result(f"Capturas generadas: {len(screenshot_files)}")

            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout en GoWitness después de 60 minutos")
            self.print_result("Timeout en capturas", success=False)
            
        except FileNotFoundError:
            self.logger.error("GoWitness no encontrado. Instala con: go install github.com/sensepost/gowitness@latest")
            self.print_result("GoWitness no encontrado. Instálalo primero.", success=False)
            
        except Exception as e:
            self.logger.error(f"Error ejecutando GoWitness: {e}")
            self.print_result(f"Error en capturas: {e}", success=False)
            
        finally:
            os.chdir(original_dir)


    def run_full_scan(self) -> None:
        """Ejecuta el escaneo completo"""
        print_banner()
        print()
        print("🚀 INICIANDO ESCANEO COMPLETO DE RECONOCIMIENTO")
        print("=" * 80)
        print(f"🎯 Dominio objetivo: {self.domain}")
        print("=" * 80)
        
        # PASO 1: ASN Info
        self.print_step_banner(1, "INFORMACIÓN DEL ASN", "Obteniendo información de infraestructura")
        self.asn_info = self.get_asn_info()
        
        all_subdomains = set()
        
        # PASO 2: Recolección de subdominios
        self.print_step_banner(2, "RECOLECCIÓN DE SUBDOMINIOS", "Buscando desde múltiples fuentes públicas")
        
        # Recolectar subdominios de todas las fuentes (excepto DNS reverso)
        sources = [
            ("Wayback Machine", self.wa_subs),
            #("Wayback Machine (200s)", self.wa_urls_200),
            ("Common Crawl", self.commoncrawl_subs),
            ("Shodan", self.sh_subs),
            ("crt.sh", self.crt_subs)
        ]
        
        for source_name, func in sources:
            try:
                self.print_substep(f"Consultando {source_name}...")
                subdomains = func()
                all_subdomains.update(subdomains)
                self.print_result(f"{source_name}: {len(subdomains)} subdominios encontrados")
            except Exception as e:
                self.logger.error(f"Error en {source_name}: {e}")
                self.print_result(f"{source_name}: Error - {e}", success=False)
                
        # Guardar subdominios
        self.save_subdomains(all_subdomains, 'all-subs.txt')
        self.print_result(f"Subdominios base recolectados: {len(all_subdomains)}")
        

        # PASO 3: Búsqueda de archivos
        self.print_step_banner(3, "BÚSQUEDA DE ARCHIVOS", "Analizando URLs por extensiones")
        
        file_search_config = {
            'js': ['json', 'jsp'],
            'json': [],
            'pdf': [],
            'php': [],
            'java': [],
            'exe': [],
            'old': [],
            'bak': [],
            'zip': [],
            'docx': [],
            'xlsx': ['xls'],
            'xls': [],
            'txt': [],
            'accdb': [],
            'sql': [],
            'mdb': ['mdw'],
            'mdw': []
        }
        for file_type, exclusions in file_search_config.items():
            self.find_file_urls(file_type, exclusions)
        
        # PASO 4: Verificación de estado
        self.print_step_banner(4, "VERIFICACIÓN DE ESTADO", "Comprobando subdominios activos")
        self.check_all_protocols()
        
        
        # PASO 5: Capturas de pantalla
        self.print_step_banner(5, "CAPTURAS DE PANTALLA", "Tomando screenshots de subdominios activos")
        self.gowitness_screenshots()
        
        # RESUMEN FINAL
        print()
        print("🎉 ESCANEO COMPLETADO")
        print("=" * 80)
        self.print_result(f"Subdominios únicos encontrados: {len(all_subdomains)}")
        self.print_info(f"Archivos de resultados guardados en: {self.domain_dir}")
        print("=" * 80)
        print()


def print_banner():
    """Muestra información de uso y funcionalidad del script"""
    print("""
░███     ░███               ░██                        ░██ ░██            
░████   ░████               ░██                        ░██ ░██            
░██░██ ░██░██  ░███████  ░████████ ░██░████  ░██████   ░██ ░██  ░██████   
░██ ░████ ░██ ░██    ░██    ░██    ░███           ░██  ░██ ░██       ░██  
░██  ░██  ░██ ░█████████    ░██    ░██       ░███████  ░██ ░██  ░███████  
░██       ░██ ░██           ░██    ░██      ░██   ░██  ░██ ░██ ░██   ░██  
░██       ░██  ░███████      ░████ ░██       ░█████░██ ░██ ░██  ░█████░██ 
                                                                          
                                                                          
                                                                          
       ░████ ░██                  ░██                                     
      ░██                         ░██                                     
   ░████████ ░██░████████   ░████████  ░███████  ░██░████                 
      ░██    ░██░██    ░██ ░██    ░██ ░██    ░██ ░███                     
      ░██    ░██░██    ░██ ░██    ░██ ░█████████ ░██                      
      ░██    ░██░██    ░██ ░██   ░███ ░██        ░██                      
      ░██    ░██░██    ░██  ░█████░██  ░███████  ░██                      
                                                                          
                                                                                                        
🔍 0xCOr$ - Recon
═══════════════════════════════════════════════════════════════════════════

📋 USO:
    python metrallaFinder.py <dominio>
    
    Ejemplo: python metrallaFinder.py example.com
""")
def print_usage_and_info():
    """"Muestra información de uso y funcionalidad del script"""
    print_banner()
    print("""

🔄 ORDEN DE EJECUCIÓN:
""")

    # Información detallada del proceso
    steps = [
        {
            "step": "1",
            "name": "Información del ASN",
            "description": "Obtiene IP del dominio y consulta información del ASN",
            "sources": ["ipinfo.io", "api.bgpview.io"],
            "interaction": "✅ NO interactúa con el dominio objetivo",
            "output": "asn_info.txt con IP, ASN, país, región"
        },
        {
            "step": "2",
            "name": "Recolección de Subdominios",
            "description": "Busca subdominios desde múltiples fuentes públicas",
            "sources": ["Wayback Machine", "Shodan", "crt.sh"],
            "interaction": "✅ NO interactúa con el dominio objetivo",
            "output": "wa-subs.txt, sh-subs.txt, crt-subs.txt"
        },        
        {
            "step": "3",
            "name": "Búsqueda de Archivos",
            "description": "Busca archivos por extensión en URLs encontradas",
            "sources": ["Análisis de URLs recolectadas"],
            "interaction": "✅ NO interactúa con el dominio objetivo",
            "output": "js_files/, pdf_files/, etc."
        },
        {
            "step": "4",
            "name": "Verificación de Estado",
            "description": "Verifica qué subdominios están activos (HTTP/HTTPS)",
            "sources": ["httpstatus.io API"],
            "interaction": "✅ NO interactúa con el dominio objetivo",
            "output": "active_http_subdomains.txt, active_https_subdomains.txt"
        },
        {
            "step": "5",
            "name": "Capturas de Pantalla",
            "description": "Toma capturas de subdominios activos",
            "sources": ["Gowitness"],
            "interaction": "❌ SÍ interactúa con el dominio objetivo",
            "output": "screenshots/ con capturas"
        }
    ]

    for step in steps:
        print(f"""
🔸 PASO {step['step']}: {step['name']}
   📝 Descripción: {step['description']}
   🔍 Fuentes: {', '.join(step['sources'])}
   🎯 Interacción: {step['interaction']}
   📄 Output: {step['output']}""")

    print(f"""
══════════════════════════════════════════════════════════════════════════


🗂️ ESTRUCTURA DE ARCHIVOS GENERADA (Versión 7 - 2025):
   dominio.com/
   ├── subs/                          # Todos los subdominios encontrados
   │   ├── all-subs.txt               # ← Archivo maestro (unión de todas las fuentes)
   │   ├── wa-subs.txt                # Wayback Machine
   │   ├── cc-200-subs.txt            # Common Crawl
   │   ├── sh-subs.txt                # Shodan
   │   ├── crt-subs.txt               # crt.sh
   │   └── asn_info.txt               # IP + ASN + ubicación
   │
   ├── urls/                          # URLs históricas completas (Wayback)
   │   └── <subdominio>.txt           # Una por subdominio
   │
   ├── urlsCC/                        # URLs de Common Crawl
   │   └── <subdominio>.txt
   │
   ├── urls200/                       # (vacío si no usas wa_urls_200)
   │
   ├── status_check/                  # Subdominios vivos (HTTP + HTTPS)
   │   ├── active_http_subdomains.txt
   │   └── active_https_subdomains.txt
   │
   ├── screenshots/                   # Capturas con GoWitness
   │   ├── all_active_subdomains.txt  # Lista usada como input
   │   └── *.jpeg                     # Capturas de pantalla
   │
   ├── js_files/                      # Las carpetas por extension se crean solo si se encuentran ficheros URL's con esa extensión.
   ├── json_files/
   ├── pdf_files/
   ├── php_files/
   ├── java_files/
   ├── exe_files/
   ├── old_files/                     
   ├── bak_files/
   ├── zip_files/
   ├── docx_files/
   ├── xlsx_files/
   ├── xls_files/
   ├── txt_files/
   ├── accdb_files/
   ├── sql_files/
   ├── mdb_files/
   ├── mdw_files/
   │
   └── bbhunting.log                  # Log completo de la ejecución

🚀 EXTENSIONES:
   js, json, pdf, php, java, exe, old, bak, zip, docx, xlsx, xls, txt, accdb, sql, mdb, mdw

══════════════════════════════════════════════════════════════════════════
""")


def main():
    """Función principal"""
    if len(sys.argv) < 2:
        print_usage_and_info()
        sys.exit(1)
        
    domain = sys.argv[1]
    #parser = argparse.ArgumentParser(add_help=False)
    #parser.add_argument('-type', action='store_true')
    
    # Validar dominio básico
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', domain):
        print("Error: Dominio inválido")
        sys.exit(1)
        
    try:
        tool = BBHuntingTool(domain)
        tool.run_full_scan()
        
    except KeyboardInterrupt:
        print("\nEscaneo interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"Error crítico: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
