#!/usr/bin/env python3
"""
SAP CVE Automation Tool - Versión Optimizada
Mejoras en el uso de SploitScan y CVE_Prioritizer
"""

import pandas as pd
import numpy as np
import re
import json
import subprocess
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import requests
from bs4 import BeautifulSoup
import logging
import glob
import shutil
import tempfile

# Configurar Rich Console
console = Console()

# Configurar logging básico
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Crear la app Typer
app = typer.Typer(help="🔒 SAP CVE Automation Tool")

# Configuración de procesamiento
BATCH_SIZE = 10  # CVEs por lote
MAX_WORKERS = 3  # Workers concurrentes para SploitScan
DELAY_BETWEEN_REQUESTS = 2  # Segundos entre requests
DELAY_BETWEEN_BATCHES = 3  # Segundos entre lotes
CHECKPOINT_INTERVAL = 20  # Guardar checkpoint cada N CVEs

# Locks para thread-safety
write_lock = Lock()
progress_lock = Lock()


class SAPCVEAutomation:
    def __init__(self):
        self.months = {
            1: 'january', 2: 'february', 3: 'march', 4: 'april',
            5: 'may', 6: 'june', 7: 'july', 8: 'august',
            9: 'september', 10: 'october', 11: 'november', 12: 'december'
        }
        self.output_dir = Path(f"sap_cve_analysis_{datetime.now().strftime('%Y%m%d')}")
        self.output_dir.mkdir(exist_ok=True)
        
        # Estado para checkpoint
        self.checkpoint_file = self.output_dir / "checkpoint.json"
        self.processed_cves = set()
        self.failed_cves = []
        self.sploitscan_results = []

    def _load_checkpoint(self):
        """Carga checkpoint si existe"""
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, 'r') as f:
                    data = json.load(f)
                    self.processed_cves = set(data.get('processed', []))
                    self.failed_cves = data.get('failed', [])
                    console.print(f"📋 Checkpoint cargado: {len(self.processed_cves)} CVEs ya procesados")
            except Exception as e:
                console.print(f"⚠️ Error cargando checkpoint: {e}")

    def _save_checkpoint(self):
        """Guarda checkpoint del progreso"""
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump({
                    'processed': list(self.processed_cves),
                    'failed': self.failed_cves,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            console.print(f"⚠️ Error guardando checkpoint: {e}")

    def extract_sap_data(self, year: int, month: int) -> pd.DataFrame:
        """Extrae y parsea todas las tablas SAP con BeautifulSoup"""
        month_name = self.months.get(month, '')
        url = f"https://support.sap.com/en/my-support/knowledge-base/security-notes-news/{month_name}-{year}.html"

        console.print(f"🔡 Extrayendo datos de SAP: {month_name.title()} {year}")
        console.print(f"🌐 URL: {url}")

        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        tables = soup.find_all("table")
        console.print(f"📊 Encontradas {len(tables)} tablas en la página")

        all_rows = []
        for idx, tbl in enumerate(tables, start=1):
            for tr in tbl.find_all("tr"):
                cells = [td.get_text(" ", strip=True) for td in tr.find_all(["td", "th"])]
                if cells:
                    all_rows.append(cells)

        note_pattern = re.compile(r'[23]\d{6,7}')
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')

        valid_rows = [
            row for row in all_rows
            if any(note_pattern.search(cell) or cve_pattern.search(cell) for cell in row)
        ]

        df = pd.DataFrame(valid_rows)
        console.print(f"✅ Filtradas {len(df)} filas válidas con Notas o CVEs")
        return df
    
    def process_sap_data(self, df: pd.DataFrame) -> tuple:
        """Procesa filas extraídas y normaliza CVEs"""
        if df.empty:
            return pd.DataFrame(), []

        # Renombrar columnas genéricas
        col_count = df.shape[1]
        col_names = [f"Col{i}" for i in range(col_count)]
        df.columns = col_names

        # Buscar CVEs en cualquier columna
        df["cve_id"] = df.apply(
            lambda row: next(
                (m.group(0) for cell in row.astype(str) if (m := re.search(r'CVE-\d{4}-\d{4,7}', cell))),
                None
            ),
            axis=1
        )

        cves = df["cve_id"].dropna().unique().tolist()
        console.print(f"✅ Procesados {len(df)} registros, encontrados {len(cves)} CVEs")

        return df, cves
    
    def _run_sploitscan_single(self, cve_id: str, config_file: str = ".streamlit/config.json") -> Optional[Dict]:
        """Ejecuta SploitScan para un CVE individual"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                tmp_path = tmp.name
            
            cmd = [
                "sploitscan",
                cve_id,
                "-c", config_file,
                "-m", "cisa,epss,prio,references",
                "-e", "json",
                "-o", tmp_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90  # Timeout individual de 90 segundos
            )
            
            if result.returncode == 0 and os.path.exists(tmp_path):
                time.sleep(1)  # Dar tiempo para que se escriba el archivo
                with open(tmp_path, 'r') as f:
                    data = json.load(f)
                os.unlink(tmp_path)
                
                # Extraer el primer resultado si es una lista
                if isinstance(data, list) and len(data) > 0:
                    return data[0]
                return data if isinstance(data, dict) else None
            
            # Limpiar archivo temporal si existe
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            
            return None
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout procesando {cve_id}")
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            return None
        except Exception as e:
            logger.error(f"Error procesando {cve_id}: {e}")
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            return None

    def _process_cve_batch(self, cve_id: str, config_file: str) -> Dict[str, Any]:
        """Procesa un CVE y retorna resultado con metadata"""
        try:
            result = self._run_sploitscan_single(cve_id, config_file)
            
            if result:
                with progress_lock:
                    self.processed_cves.add(cve_id)
                return {'success': True, 'cve_id': cve_id, 'data': result}
            else:
                with progress_lock:
                    self.failed_cves.append(cve_id)
                return {'success': False, 'cve_id': cve_id, 'data': None}
                
        except Exception as e:
            logger.error(f"Error en batch para {cve_id}: {e}")
            with progress_lock:
                self.failed_cves.append(cve_id)
            return {'success': False, 'cve_id': cve_id, 'data': None}

    def run_sploitscan(self, cve_list: List[str], tool_path: str = ".", 
                      batch_size: int = BATCH_SIZE, max_workers: int = MAX_WORKERS) -> str:
        """
        Ejecuta SploitScan de forma optimizada con:
        - Procesamiento paralelo controlado
        - Sistema de checkpoint
        - Rate limiting automático
        - Manejo robusto de errores
        """
        console.print(f"🔍 Ejecutando SploitScan optimizado")
        console.print(f"📊 CVEs a procesar: {len(cve_list)}")
        console.print(f"⚙️  Configuración: {batch_size} CVEs/lote, {max_workers} workers")
        
        original_dir = os.getcwd()
        self.sploitscan_results = []
        
        # Cargar checkpoint
        self._load_checkpoint()
        
        # Filtrar CVEs ya procesados
        pending_cves = [cve for cve in cve_list if cve not in self.processed_cves]
        
        if not pending_cves:
            console.print("✅ Todos los CVEs ya fueron procesados")
            return self._consolidate_sploitscan_results()
        
        console.print(f"📋 CVEs pendientes: {len(pending_cves)} de {len(cve_list)}")

        try:
            if tool_path != "." and os.path.exists(tool_path):
                os.chdir(tool_path)
                console.print(f"📂 Cambiado a directorio: {tool_path}")
            
            config_file = ".streamlit/config.json"
            total_batches = (len(pending_cves) + batch_size - 1) // batch_size
            
            # Procesar con barra de progreso
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task(
                    f"[cyan]Procesando CVEs...", 
                    total=len(pending_cves)
                )
                
                for i in range(0, len(pending_cves), batch_size):
                    batch = pending_cves[i:i + batch_size]
                    batch_num = (i // batch_size) + 1
                    
                    progress.update(
                        task, 
                        description=f"[cyan]Lote {batch_num}/{total_batches} ({len(batch)} CVEs)"
                    )
                    
                    # Procesar lote en paralelo
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = {
                            executor.submit(self._process_cve_batch, cve, config_file): cve 
                            for cve in batch
                        }
                        
                        for future in as_completed(futures):
                            result = future.result()
                            if result['success'] and result['data']:
                                self.sploitscan_results.append(result['data'])
                            
                            progress.advance(task)
                            time.sleep(DELAY_BETWEEN_REQUESTS / max_workers)
                    
                    # Guardar checkpoint periódicamente
                    if len(self.processed_cves) % CHECKPOINT_INTERVAL == 0:
                        self._save_checkpoint()
                    
                    # Delay entre lotes
                    if i + batch_size < len(pending_cves):
                        time.sleep(DELAY_BETWEEN_BATCHES)
            
            # Guardar checkpoint final
            self._save_checkpoint()
            
            # Consolidar resultados
            if not self.sploitscan_results:
                console.print("❌ No se generaron resultados de SploitScan")
                return ""
            
            # Guardar resultados consolidados
            consolidated_file = self._consolidate_sploitscan_results()
            
            # Reporte final
            console.print(f"\n📊 Resumen SploitScan:")
            console.print(f"   ✅ Exitosos: {len(self.sploitscan_results)}")
            console.print(f"   ❌ Fallidos: {len(self.failed_cves)}")
            console.print(f"   📁 Archivo: {consolidated_file}")
            
            if self.failed_cves:
                console.print(f"\n⚠️  CVEs fallidos: {', '.join(self.failed_cves[:5])}")
                if len(self.failed_cves) > 5:
                    console.print(f"   ... y {len(self.failed_cves) - 5} más")
            
            return consolidated_file

        except FileNotFoundError:
            console.print("❌ Comando 'sploitscan' no encontrado")
            return ""
        except Exception as e:
            console.print(f"❌ Error general en SploitScan: {e}")
            return ""
        finally:
            os.chdir(original_dir)

    def _consolidate_sploitscan_results(self) -> str:
        """Consolida todos los resultados de SploitScan en un archivo"""
        if not self.sploitscan_results:
            return ""
        
        consolidated_file = f"sploitscan_consolidated_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        
        try:
            with open(consolidated_file, 'w') as f:
                json.dump(self.sploitscan_results, f, indent=4)
            return consolidated_file
        except Exception as e:
            console.print(f"❌ Error consolidando resultados: {e}")
            return ""

    def _run_cve_prioritizer_batch(self, cve_batch: List[str], output_file: str, 
                                   tool_path: str = ".") -> bool:
        """Ejecuta CVE_Prioritizer para un lote de CVEs"""
        try:
            cve_string = ",".join(cve_batch)
            
            cmd = [
                "cve_prioritizer",
                "-l", cve_string,
                "-vck", "-vc", "-v",
                "-o", output_file
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos por lote
            )
            
            if result.returncode == 0 and os.path.exists(output_file):
                return True
            
            return False
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout en CVE_Prioritizer para lote")
            return False
        except Exception as e:
            logger.error(f"Error en CVE_Prioritizer: {e}")
            return False

    def run_cve_prioritizer(self, cve_list: List[str], output_file: str, 
                           tool_path: str = ".", batch_size: int = 50) -> bool:
        """
        Ejecuta CVE_Prioritizer de forma optimizada:
        - Procesa en lotes para evitar timeouts
        - Combina resultados automáticamente
        - Manejo robusto de errores
        """
        console.print(f"📊 Ejecutando CVE_Prioritizer optimizado")
        console.print(f"📋 CVEs a procesar: {len(cve_list)}")
        
        original_dir = os.getcwd()
        all_results = []
        
        try:
            if tool_path != "." and os.path.exists(tool_path):
                os.chdir(tool_path)
                console.print(f"📂 Cambiado a directorio: {tool_path}")
            
            total_batches = (len(cve_list) + batch_size - 1) // batch_size
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task(
                    f"[cyan]Priorizando CVEs...", 
                    total=total_batches
                )
                
                for i in range(0, len(cve_list), batch_size):
                    batch = cve_list[i:i + batch_size]
                    batch_num = (i // batch_size) + 1
                    
                    progress.update(
                        task,
                        description=f"[cyan]Lote {batch_num}/{total_batches}"
                    )
                    
                    # Archivo temporal para este lote
                    temp_output = f"temp_prioritizer_{batch_num}.csv"
                    
                    if self._run_cve_prioritizer_batch(batch, temp_output, tool_path):
                        # Leer y agregar resultados
                        try:
                            df = pd.read_csv(temp_output)
                            all_results.append(df)
                            os.remove(temp_output)
                        except Exception as e:
                            logger.error(f"Error leyendo lote {batch_num}: {e}")
                    
                    progress.advance(task)
                    time.sleep(DELAY_BETWEEN_BATCHES)
            
            # Combinar todos los resultados
            if all_results:
                combined_df = pd.concat(all_results, ignore_index=True)
                combined_df.drop_duplicates(subset=['cve_id'], inplace=True)
                combined_df.to_csv(output_file, index=False)
                
                console.print(f"✅ CVE_Prioritizer completado: {output_file}")
                console.print(f"   📊 Total CVEs procesados: {len(combined_df)}")
                return True
            else:
                console.print("❌ CVE_Prioritizer no generó resultados")
                return False
                
        except FileNotFoundError:
            console.print("❌ Comando 'cve_prioritizer' no encontrado")
            console.print("💡 Verificar que CVE_Prioritizer esté instalado globalmente")
            return False
        except Exception as e:
            console.print(f"❌ Error ejecutando CVE_Prioritizer: {str(e)}")
            return False
        finally:
            os.chdir(original_dir)
    
    def dataframeSplotscan(self, file_json: str) -> pd.DataFrame:
        """Procesa SploitScan - EXACTAMENTE igual que el original"""
        try:
            if not os.path.exists(file_json):
                console.print(f"❌ Archivo no encontrado: {file_json}")
                return pd.DataFrame()
            
            console.print("📄 Procesando resultados de SploitScan...")
            
            data = pd.DataFrame(columns=['cve_id', 'dateUpdated', 'descriptions', 'product_l', 'epss_l', 'percentile', 'priority_l', 'cweId'])
            dict_list = []
            sap_sp = pd.read_json(file_json, typ='series')
            
            for i in sap_sp:
                if 'problemTypes' in i['CVE Data']['containers']['cna'].keys():            
                    if 'cweId' in i['CVE Data']['containers']['cna']['problemTypes'][0]['descriptions'][0].keys():
                        cweId = i['CVE Data']['containers']['cna']['problemTypes'][0]['descriptions'][0]['cweId']
                    else:
                        cweId = i['CVE Data']['containers']['cna']['problemTypes'][0]['descriptions'][0]['description']
                else:
                    cweId = None
                    
                if len(i['EPSS Data']['data']) == 1:
                    epss_l = i['EPSS Data']['data'][0]['epss']
                    percentile = i['EPSS Data']['data'][0]['percentile']
                else:
                    epss_l = None
                    percentile = None
                    
                if 'datePublished' in i['CVE Data']['cveMetadata']:
                    datePublished = i['CVE Data']['cveMetadata']['datePublished']
                else:
                    datePublished = None
                    
                if 'references' in i['CVE Data']['containers']['cna'].keys():            
                    note_id = re.findall('[2,3]{1}[0-9]{6}', str(i['CVE Data']['containers']['cna']['references'][0]['url']))
                else:
                    note_id = None
                    
                row_list = {
                    'cve_id': i['CVE Data']['cveMetadata']['cveId'],
                    'datePublished': datePublished,
                    'dateUpdated': i['CVE Data']['cveMetadata']['dateUpdated'],
                    'descriptions': i['CVE Data']['containers']['cna']['descriptions'][0]['value'],
                    'product_l': i['CVE Data']['containers']['cna']['affected'][0]['product'],
                    'epss_l': epss_l,
                    'percentile': percentile,
                    'priority_l': i['Priority']['Priority'],
                    'cweId': cweId,
                    'note_id': str(note_id)
                }
                dict_list.append(row_list)

            data = pd.DataFrame.from_dict(dict_list)
            data.drop_duplicates(subset=['cve_id'], inplace=True)
            
            console.print(f"✅ Procesados {len(data)} registros de SploitScan")
            return data
            
        except Exception as e:
            console.print(f"❌ Error procesando SploitScan: {str(e)}")
            return pd.DataFrame()
    
    def merge_results(self, sap_df: pd.DataFrame, sploitscan_df: pd.DataFrame, 
                     prioritizer_file: str, year: int) -> pd.DataFrame:
        """Combina todos los resultados - igual que el original"""
        console.print("🔗 Combinando resultados...")
        
        try:
            # Empezar con los datos SAP procesados (que ya tienen cve_id)
            result_df = sap_df.copy()
            
            # Merge con SploitScan
            if not sploitscan_df.empty:
                result_df = result_df.merge(sploitscan_df, on=['cve_id'], how='left')
                console.print(f"✅ Datos de SploitScan combinados")
            
            # Merge con CVE_Prioritizer
            if os.path.exists(prioritizer_file):
                cp_df = pd.read_csv(prioritizer_file)
                cp_df.drop_duplicates(subset=['cve_id'], inplace=True)
                result_df = result_df.merge(cp_df, on=['cve_id'], how='left')
                console.print(f"✅ Datos de CVE_Prioritizer combinados")
            
            # Añadir año igual que en el original
            result_df['sap_note_year'] = str(year)

            # Renombrar columnas
            result_df.rename(columns={'Col0': 'Note#', 'Col1': 'Title', 'Col2': 'Priority', 'Col3': 'CVSS'}, inplace=True)
            
            # Orden final de columnas
            final_cols = ['cve_id', 'datePublished', 'dateUpdated',
                          'descriptions', 'product_l', 'epss_l', 'percentile', 'priority_l', 'cweId', 
                          'note_id', 'Note#', 'Title', 'Priority', 'CVSS', 'priority', 'epss', 'cvss', 'cvss_version',
                          'cvss_severity', 'kev', 'ransomware', 'kev_source', 'cpe', 'vendor',
                          'product', 'vector', 'sap_note_year']
            
            # Filtrar columnas existentes en el dataframe para evitar errores
            existing_cols = [col for col in final_cols if col in result_df.columns]
            result_df = result_df[existing_cols]
            
            console.print(f"✅ Combinación completada. Total registros: {len(result_df)}")
            return result_df
            
        except Exception as e:
            console.print(f"❌ Error combinando resultados: {str(e)}")
            return sap_df
    
    def save_results(self, df: pd.DataFrame, filename: str) -> str:
        """Guarda los resultados finales"""
        output_file = self.output_dir / f"{filename}.csv"
        
        try:
            df.to_csv(output_file, index=False)
            console.print(f"💾 Resultados guardados en: {output_file}")
            return str(output_file)
        except Exception as e:
            console.print(f"❌ Error guardando resultados: {str(e)}")
            return ""
    
    def print_summary(self, df: pd.DataFrame) -> None:
        """Imprime un resumen de los resultados"""
        if df.empty:
            return
        
        console.print("\n" + "="*60)
        console.print("📊 RESUMEN DEL ANÁLISIS")
        console.print("="*60)
        
        total_records = len(df)
        total_cves = len(df[df['cve_id'].notna()])
        
        console.print(f"📋 Total de registros: {total_records}")
        console.print(f"🔍 CVE-IDs encontrados: {total_cves}")
        
        # Distribución por prioridad
        if 'Priority' in df.columns:
            console.print(f"\n📊 Distribución por prioridad:")
            priority_counts = df['Priority'].value_counts()
            for priority, count in priority_counts.items():
                percentage = (count/total_records)*100
                console.print(f"   • {priority}: {count} ({percentage:.1f}%)")


@app.command()
def analyze(
    year: int = typer.Option(default=None, help="Año para análisis"),
    month: int = typer.Option(default=None, help="Mes para análisis (1-12)"),
    skip_sploitscan: bool = typer.Option(False, "--skip-sploitscan", help="Saltar SploitScan"),
    skip_prioritizer: bool = typer.Option(False, "--skip-prioritizer", help="Saltar CVE_Prioritizer"),
    sploitscan_path: str = typer.Option(".", help="Ruta donde ejecutar SploitScan"),
    prioritizer_path: str = typer.Option(".", help="Ruta donde ejecutar CVE_Prioritizer"),
    output_name: str = typer.Option(None, help="Nombre para archivo de salida"),
    batch_size: int = typer.Option(BATCH_SIZE, help="Tamaño de lote para procesamiento"),
    max_workers: int = typer.Option(MAX_WORKERS, help="Workers concurrentes para SploitScan")
):
    """🚀 Ejecuta el análisis completo de vulnerabilidades SAP (OPTIMIZADO)"""
    
    # Valores por defecto
    if year is None:
        year = datetime.now().year
    if month is None:
        month = datetime.now().month
    
    # Validaciones
    if not (1 <= month <= 12):
        console.print("❌ El mes debe estar entre 1 y 12")
        raise typer.Exit(1)
    
    console.print("="*60)
    console.print("🔒 SAP CVE AUTOMATION TOOL - OPTIMIZADO")
    console.print("="*60)
    console.print(f"📅 Analizando: {month:02d}/{year}")
    console.print(f"🔍 SploitScan: {'❌ Saltado' if skip_sploitscan else '✅ Habilitado'}")
    console.print(f"📊 CVE_Prioritizer: {'❌ Saltado' if skip_prioritizer else '✅ Habilitado'}")
    console.print(f"⚙️  Batch size: {batch_size} | Workers: {max_workers}")
    console.print("="*60)
    
    automation = SAPCVEAutomation()
    
    # Paso 1: Extraer datos de SAP
    console.print("\n1️⃣ EXTRAYENDO DATOS DE SAP")
    console.print("-" * 40)
    sap_data = automation.extract_sap_data(year, month)
    
    # Paso 2: Procesar datos
    console.print("\n2️⃣ PROCESANDO DATOS SAP")
    console.print("-" * 40)
    sap_df, cve_list = automation.process_sap_data(sap_data)
    
    if not cve_list:
        console.print("⚠️ No se encontraron CVE-IDs. Solo se guardarán datos SAP.")
        skip_sploitscan = skip_prioritizer = True
    else:
        console.print(f"🔍 {len(cve_list)} CVEs listos para procesar")
    
    # Paso 3: Ejecutar SploitScan (OPTIMIZADO)
    sploitscan_df = pd.DataFrame()
    if not skip_sploitscan and cve_list:
        console.print("\n3️⃣ EJECUTANDO SPLOITSCAN (OPTIMIZADO)")
        console.print("-" * 40)
        
        sploitscan_file = automation.run_sploitscan(
            cve_list, 
            sploitscan_path,
            batch_size=batch_size,
            max_workers=max_workers
        )
        
        if sploitscan_file:
            # Copiar archivo al directorio de salida
            sploitscan_source = os.path.join(sploitscan_path, sploitscan_file) if sploitscan_path != "." else sploitscan_file
            sploitscan_dest = automation.output_dir / f"sploitscan_{year}{month:02d}.json"
            
            try:
                shutil.copy(sploitscan_source, sploitscan_dest)
                sploitscan_df = automation.dataframeSplotscan(str(sploitscan_dest))
            except Exception as e:
                console.print(f"❌ Error copiando archivo SploitScan: {e}")
                if os.path.exists(sploitscan_source):
                    sploitscan_df = automation.dataframeSplotscan(sploitscan_source)
    
    # Paso 4: Ejecutar CVE_Prioritizer (OPTIMIZADO)
    prioritizer_file = ""
    if not skip_prioritizer and cve_list:
        console.print("\n4️⃣ EJECUTANDO CVE_PRIORITIZER (OPTIMIZADO)")
        console.print("-" * 40)
        
        csv_file = f"prioritizer_{year}{month:02d}.csv"
        
        if automation.run_cve_prioritizer(cve_list, csv_file, prioritizer_path, batch_size=50):
            # Copiar archivo al directorio de salida
            prioritizer_source = os.path.join(prioritizer_path, csv_file) if prioritizer_path != "." else csv_file
            prioritizer_dest = automation.output_dir / csv_file
            
            try:
                shutil.copy(prioritizer_source, prioritizer_dest)
                prioritizer_file = str(prioritizer_dest)
            except Exception as e:
                console.print(f"❌ Error copiando archivo CVE_Prioritizer: {e}")
                if os.path.exists(prioritizer_source):
                    prioritizer_file = prioritizer_source
    
    # Paso 5: Combinar resultados
    console.print("\n5️⃣ COMBINANDO RESULTADOS")
    console.print("-" * 40)
    final_df = automation.merge_results(sap_df, sploitscan_df, prioritizer_file, year)
    
    # Paso 6: Guardar resultados
    console.print("\n6️⃣ GUARDANDO RESULTADOS")
    console.print("-" * 40)
    if output_name is None:
        output_name = f"sap_cve_{year}{month:02d}"
    
    output_file = automation.save_results(final_df, output_name)
    
    # Mostrar resumen
    automation.print_summary(final_df)
    
    if output_file:
        console.print(f"\n✅ ANÁLISIS COMPLETADO EXITOSAMENTE!")
        console.print(f"📁 Archivo de salida: {output_file}")
    else:
        console.print(f"\n⚠️ Análisis completado con advertencias")


@app.command()
def test():
    """🧪 Prueba simple de comandos"""
    
    console.print("🧪 PROBANDO COMANDOS")
    console.print("="*40)
    
    # Probar SploitScan
    console.print("\n🔍 Probando SploitScan:")
    try:
        result = subprocess.run(["sploitscan", "--help"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            console.print("✅ sploitscan - FUNCIONA")
        else:
            console.print("❌ sploitscan - Error")
    except:
        console.print("❌ sploitscan - No encontrado")
    
    # Probar CVE_Prioritizer
    console.print("\n📊 Probando CVE_Prioritizer:")
    try:
        result = subprocess.run(["cve_prioritizer", "--help"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            console.print("✅ cve_prioritizer - FUNCIONA")
        else:
            console.print("❌ cve_prioritizer - Error")
    except:
        console.print("❌ cve_prioritizer - No encontrado")


if __name__ == "__main__":
    app()