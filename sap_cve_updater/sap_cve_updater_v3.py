#!/usr/bin/env python3
"""
SAP CVE Data Updater
Actualiza datos de CVEs usando SploitScan y CVE_Prioritizer
Mantiene EXACTAMENTE la misma estructura del CSV original
"""

import os
import sys
import csv
import json
import time
import logging
import subprocess
import tempfile
import re
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import argparse

# Configuración
BATCH_SIZE = 10  # CVEs por lote
MAX_WORKERS = 3  # Threads concurrentes
DELAY_BETWEEN_BATCHES = 5  # Segundos entre lotes
DELAY_BETWEEN_REQUESTS = 2  # Segundos entre requests individuales
CHECKPOINT_INTERVAL = 20  # Guardar progreso cada N CVEs

# Lock para escritura thread-safe
write_lock = Lock()
progress_lock = Lock()


class CVEDataUpdater:
    def __init__(self, input_csv, output_csv, log_file, checkpoint_file, force=False):
        self.input_csv = input_csv
        self.output_csv = output_csv
        self.log_file = log_file
        self.checkpoint_file = checkpoint_file
        self.force = force
        self.processed_cves = set()
        self.all_rows = []  # Almacenar TODAS las filas
        self.updated_indices = {}  # Mapeo de índice -> datos actualizados
        self.failed_cves = []
        self.cve_column = None
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Cargar checkpoint si existe (solo si no es force)
        if not force:
            self.load_checkpoint()
        else:
            self.logger.info("Modo FORCE activado - reprocesando todos los CVEs")
    
    def detect_cve_column(self, row):
        """Detecta automáticamente la columna que contiene CVE-IDs"""
        # Patrones comunes de nombres de columna
        possible_names = ['cve_id', 'CVE_ID', 'CVE ID', 'CVE-ID', 'cve', 'CVE', 'id', 'ID']
        
        # Buscar por nombre exacto (case insensitive)
        for name in possible_names:
            for key in row.keys():
                if key.lower() == name.lower():
                    value = row[key].strip() if row[key] else ''
                    if value and re.match(r'CVE-\d{4}-\d+', value, re.IGNORECASE):
                        return key
        
        # Buscar por patrón en cualquier columna
        for key, value in row.items():
            if value and re.match(r'CVE-\d{4}-\d+', str(value).strip(), re.IGNORECASE):
                self.logger.info(f"Columna CVE detectada: '{key}'")
                return key
        
        return None
    
    def load_checkpoint(self):
        """Carga el estado previo si existe"""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    data = json.load(f)
                    self.processed_cves = set(data.get('processed', []))
                    self.logger.info(f"Checkpoint cargado: {len(self.processed_cves)} CVEs ya procesados")
            except Exception as e:
                self.logger.warning(f"No se pudo cargar checkpoint: {e}")
    
    def save_checkpoint(self):
        """Guarda el estado actual"""
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump({
                    'processed': list(self.processed_cves),
                    'timestamp': datetime.now().isoformat()
                }, f)
        except Exception as e:
            self.logger.error(f"Error guardando checkpoint: {e}")
    
    def read_input_csv(self):
        """Lee el CSV completo y extrae CVEs a procesar"""
        cves_to_process = []
        
        try:
            with open(self.input_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.fieldnames = reader.fieldnames  # IMPORTANTE: Mantener orden original
                
                # Debug: mostrar columnas disponibles
                self.logger.info(f"Columnas en CSV ({len(self.fieldnames)}): {', '.join(self.fieldnames)}")
                
                for idx, row in enumerate(reader):
                    # Detectar columna CVE en la primera fila
                    if self.cve_column is None:
                        self.cve_column = self.detect_cve_column(row)
                        if self.cve_column:
                            self.logger.info(f"Usando columna: '{self.cve_column}' para CVE-IDs")
                        else:
                            self.logger.error("No se pudo detectar columna con CVE-IDs")
                            self.logger.error(f"Primera fila: {row}")
                            sys.exit(1)
                    
                    # Guardar TODAS las filas (para mantener estructura completa)
                    self.all_rows.append(row)
                    
                    cve_id = row.get(self.cve_column, '').strip()
                    
                    # Validar formato CVE y determinar si procesar
                    if cve_id and re.match(r'CVE-\d{4}-\d+', cve_id, re.IGNORECASE):
                        cve_id = cve_id.upper()
                        row[self.cve_column] = cve_id
                        
                        # Solo agregar a lista de procesamiento si es necesario
                        if self.force or cve_id not in self.processed_cves:
                            cves_to_process.append({'index': idx, 'row': row, 'cve_id': cve_id})
                
            total_rows = len(self.all_rows)
            valid_cves = sum(1 for row in self.all_rows if row.get(self.cve_column, '').strip())
            
            self.logger.info(f"Total de filas en CSV: {total_rows}")
            self.logger.info(f"CVEs válidos encontrados: {valid_cves}")
            self.logger.info(f"CVEs ya procesados: {len(self.processed_cves)}")
            self.logger.info(f"CVEs a procesar ahora: {len(cves_to_process)}")
            
            return cves_to_process
            
        except Exception as e:
            self.logger.error(f"Error leyendo CSV: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            sys.exit(1)
    
    def run_sploitscan(self, cve_id):
        """Ejecuta SploitScan para un CVE"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                tmp_path = tmp.name
            
            cmd = [
                'sploitscan',
                '-c', cve_id,
                '--json-output', tmp_path,
                '--fast-mode'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, 'r') as f:
                        data = json.load(f)
                    os.unlink(tmp_path)
                    return data
                except:
                    os.unlink(tmp_path)
                    return None
            
            return None
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout en SploitScan para {cve_id}")
            return None
        except FileNotFoundError:
            self.logger.error("SploitScan no encontrado. Instalar con: pip install sploitscan")
            return None
        except Exception as e:
            self.logger.error(f"Error en SploitScan para {cve_id}: {e}")
            return None
    
    def run_cve_prioritizer(self, cve_id):
        """Ejecuta CVE_Prioritizer para un CVE"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                tmp_path = tmp.name
            
            cmd = [
                'cve_prioritizer',
                '-c', cve_id,
                '-j', tmp_path,
                '--no-color'
            ]
            
            if os.getenv('VULNCHECK_API'):
                cmd.extend(['-vc'])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, 'r') as f:
                        data = json.load(f)
                    os.unlink(tmp_path)
                    return data
                except:
                    os.unlink(tmp_path)
                    return None
            
            return None
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout en CVE_Prioritizer para {cve_id}")
            return None
        except FileNotFoundError:
            self.logger.error("CVE_Prioritizer no encontrado. Instalar con: pip install cve-prioritizer")
            return None
        except Exception as e:
            self.logger.error(f"Error en CVE_Prioritizer para {cve_id}: {e}")
            return None
    
    def map_field_name(self, standard_name):
        """Mapea nombres estándar a nombres de columna del CSV"""
        # Mapeo de nombres estándar a posibles nombres en el CSV
        mappings = {
            'cvss_score': ['cvss', 'CVSS', 'cvss_score', 'CVSS_Score'],
            'cvss_vector': ['vector', 'CVSS_Vector', 'cvss_vector'],
            'cvss_severity': ['cvss_severity', 'severity', 'Severity'],
            'cvss_version': ['cvss_version', 'version'],
            'description': ['descriptions', 'Description', 'description'],
            'epss_score': ['epss', 'epss_l', 'EPSS_Score', 'epss_score'],
            'epss_percentile': ['percentile', 'EPSS_Percentile', 'epss_percentile'],
            'priority': ['priority', 'Priority', 'priority_l'],
            'kev': ['kev', 'KEV', 'CISA_KEV', 'kev_source'],
            'cwe': ['cweId', 'CWE', 'cwe'],
            'published': ['datePublished', 'published', 'Published'],
            'updated': ['dateUpdated', 'updated', 'Updated']
        }
        
        if standard_name in mappings:
            for possible_name in mappings[standard_name]:
                if possible_name in self.fieldnames:
                    return possible_name
        
        return None
    
    def merge_data(self, original_row, sploitscan_data, prioritizer_data):
        """Actualiza solo los campos existentes en el CSV original"""
        updated_row = original_row.copy()
        
        # Actualizar con datos de SploitScan
        if sploitscan_data:
            cve_info = sploitscan_data.get('cve_info', {})
            
            # CVSS Score
            cvss_field = self.map_field_name('cvss_score')
            if cvss_field and cve_info.get('cvss_score'):
                updated_row[cvss_field] = str(cve_info['cvss_score'])
            
            # CVSS Vector
            vector_field = self.map_field_name('cvss_vector')
            if vector_field and cve_info.get('cvss_vector'):
                updated_row[vector_field] = cve_info['cvss_vector']
            
            # CVSS Severity
            severity_field = self.map_field_name('cvss_severity')
            if severity_field and cve_info.get('cvss_severity'):
                updated_row[severity_field] = cve_info['cvss_severity']
            
            # CVSS Version
            version_field = self.map_field_name('cvss_version')
            if version_field and cve_info.get('cvss_version'):
                updated_row[version_field] = cve_info['cvss_version']
            
            # Descripción
            desc_field = self.map_field_name('description')
            if desc_field and cve_info.get('description'):
                updated_row[desc_field] = cve_info['description']
            
            # EPSS
            epss = sploitscan_data.get('epss', {})
            if epss:
                epss_score_field = self.map_field_name('epss_score')
                if epss_score_field and epss.get('epss_score'):
                    updated_row[epss_score_field] = str(epss['epss_score'])
                
                epss_percentile_field = self.map_field_name('epss_percentile')
                if epss_percentile_field and epss.get('epss_percentile'):
                    updated_row[epss_percentile_field] = str(epss['epss_percentile'])
            
            # CISA KEV
            kev_field = self.map_field_name('kev')
            if kev_field:
                cisa_kev = sploitscan_data.get('cisa_kev')
                if cisa_kev:
                    updated_row[kev_field] = 'Yes'
                elif updated_row.get(kev_field) == '':
                    updated_row[kev_field] = 'No'
        
        # Actualizar con datos de CVE_Prioritizer
        if prioritizer_data:
            results = prioritizer_data.get('results', [])
            if results:
                result = results[0]
                
                # Prioridad
                priority_field = self.map_field_name('priority')
                if priority_field and result.get('priority'):
                    updated_row[priority_field] = result['priority']
                
                # CVSS (si no se actualizó antes)
                cvss_field = self.map_field_name('cvss_score')
                if cvss_field and not updated_row.get(cvss_field) and result.get('cvss'):
                    updated_row[cvss_field] = str(result['cvss'])
                
                # EPSS (si no se actualizó antes)
                epss_field = self.map_field_name('epss_score')
                if epss_field and not updated_row.get(epss_field) and result.get('epss'):
                    updated_row[epss_field] = str(result['epss'])
                
                epss_percentile_field = self.map_field_name('epss_percentile')
                if epss_percentile_field and not updated_row.get(epss_percentile_field) and result.get('percentile'):
                    updated_row[epss_percentile_field] = str(result['percentile'])
                
                # KEV
                kev_field = self.map_field_name('kev')
                if kev_field and result.get('kev'):
                    updated_row[kev_field] = 'Yes' if result['kev'] == 'Yes' else 'No'
        
        # Actualizar fecha de modificación si existe esa columna
        updated_field = self.map_field_name('updated')
        if updated_field:
            updated_row[updated_field] = datetime.now().strftime('%Y-%m-%d')
        
        return updated_row
    
    def process_cve(self, item):
        """Procesa un CVE individual"""
        idx = item['index']
        row = item['row']
        cve_id = item['cve_id']
        
        try:
            self.logger.info(f"Procesando {cve_id}...")
            
            # Ejecutar SploitScan
            sploitscan_data = self.run_sploitscan(cve_id)
            time.sleep(DELAY_BETWEEN_REQUESTS)
            
            # Ejecutar CVE_Prioritizer
            prioritizer_data = self.run_cve_prioritizer(cve_id)
            time.sleep(DELAY_BETWEEN_REQUESTS)
            
            # Combinar datos
            updated_row = self.merge_data(row, sploitscan_data, prioritizer_data)
            
            # Guardar actualización por índice
            with write_lock:
                self.updated_indices[idx] = updated_row
            
            # Marcar como procesado
            with progress_lock:
                self.processed_cves.add(cve_id)
            
            self.logger.info(f"✓ {cve_id} procesado exitosamente")
            return {'success': True, 'cve_id': cve_id, 'index': idx}
            
        except Exception as e:
            self.logger.error(f"✗ Error procesando {cve_id}: {e}")
            with progress_lock:
                self.failed_cves.append(cve_id)
            return {'success': False, 'cve_id': cve_id, 'index': idx}
    
    def process_batch(self, batch):
        """Procesa un lote de CVEs en paralelo"""
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self.process_cve, item): item for item in batch}
            
            for future in as_completed(futures):
                result = future.result()
    
    def run(self):
        """Ejecuta el proceso completo"""
        start_time = time.time()
        self.logger.info("="*80)
        self.logger.info("Iniciando actualización de datos SAP CVE")
        self.logger.info("="*80)
        
        # Leer CSV completo
        cves_to_process = self.read_input_csv()
        
        if not cves_to_process:
            self.logger.info("No hay CVEs nuevos para procesar")
            if not self.force and self.processed_cves:
                self.logger.info("SUGERENCIA: Usa --force para reprocesar todos los CVEs")
                self.logger.info(f"O elimina el checkpoint: rm {self.checkpoint_file}")
            
            # Aunque no haya nada que procesar, escribir el CSV de salida
            self.write_output_csv()
            return
        
        total_cves = len(cves_to_process)
        
        # Procesar en lotes
        for i in range(0, total_cves, BATCH_SIZE):
            batch = cves_to_process[i:i + BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            total_batches = (total_cves + BATCH_SIZE - 1) // BATCH_SIZE
            
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Procesando lote {batch_num}/{total_batches} ({len(batch)} CVEs)")
            self.logger.info(f"{'='*60}")
            
            self.process_batch(batch)
            
            # Guardar checkpoint periódicamente
            if len(self.processed_cves) % CHECKPOINT_INTERVAL == 0:
                self.save_checkpoint()
                self.logger.info(f"Checkpoint guardado: {len(self.processed_cves)} CVEs procesados")
            
            # Delay entre lotes (excepto último)
            if i + BATCH_SIZE < total_cves:
                self.logger.info(f"Esperando {DELAY_BETWEEN_BATCHES}s antes del siguiente lote...")
                time.sleep(DELAY_BETWEEN_BATCHES)
        
        # Guardar checkpoint final
        self.save_checkpoint()
        
        # Escribir CSV actualizado
        self.write_output_csv()
        
        # Reporte final
        elapsed_time = time.time() - start_time
        self.logger.info("\n" + "="*80)
        self.logger.info("REPORTE FINAL")
        self.logger.info("="*80)
        self.logger.info(f"Total de filas en CSV: {len(self.all_rows)}")
        self.logger.info(f"CVEs procesados en esta ejecución: {len(self.updated_indices)}")
        self.logger.info(f"CVEs exitosos: {len(self.processed_cves)}")
        self.logger.info(f"CVEs fallidos: {len(self.failed_cves)}")
        self.logger.info(f"Tiempo total: {elapsed_time:.2f}s")
        self.logger.info(f"CSV actualizado: {self.output_csv}")
        self.logger.info(f"Log completo: {self.log_file}")
        
        if self.failed_cves:
            self.logger.warning(f"\nCVEs fallidos: {', '.join(self.failed_cves)}")
    
    def write_output_csv(self):
        """Escribe el CSV actualizado manteniendo TODA la estructura original"""
        try:
            with open(self.output_csv, 'w', encoding='utf-8', newline='') as f:
                # IMPORTANTE: Usar fieldnames originales en el orden original
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()
                
                # Escribir TODAS las filas
                for idx, row in enumerate(self.all_rows):
                    # Si esta fila fue actualizada, usar datos nuevos
                    if idx in self.updated_indices:
                        output_row = self.updated_indices[idx]
                    else:
                        output_row = row
                    
                    # Asegurar que solo se escriben las columnas originales
                    filtered_row = {k: output_row.get(k, '') for k in self.fieldnames}
                    writer.writerow(filtered_row)
            
            self.logger.info(f"✓ CSV actualizado guardado: {self.output_csv}")
            self.logger.info(f"  - Filas totales: {len(self.all_rows)}")
            self.logger.info(f"  - Filas actualizadas: {len(self.updated_indices)}")
            self.logger.info(f"  - Columnas: {len(self.fieldnames)}")
            
        except Exception as e:
            self.logger.error(f"Error escribiendo CSV: {e}")
            import traceback
            self.logger.error(traceback.format_exc())


def check_dependencies():
    """Verifica que las herramientas estén instaladas"""
    tools = ['sploitscan', 'cve_prioritizer']
    missing = []
    
    for tool in tools:
        try:
            subprocess.run([tool, '--help'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            missing.append(tool)
    
    if missing:
        print(f"ERROR: Herramientas no encontradas: {', '.join(missing)}")
        print("\nInstalar con:")
        print("  pip install sploitscan cve-prioritizer")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Actualiza datos de CVEs SAP usando SploitScan y CVE_Prioritizer'
    )
    parser.add_argument(
        '-i', '--input',
        default='sap_cve_last_01.csv',
        help='Archivo CSV de entrada (default: sap_cve_last_01.csv)'
    )
    parser.add_argument(
        '-o', '--output',
        default='sap_cve_updated.csv',
        help='Archivo CSV de salida (default: sap_cve_updated.csv)'
    )
    parser.add_argument(
        '-l', '--log',
        default='update_log.txt',
        help='Archivo de log (default: update_log.txt)'
    )
    parser.add_argument(
        '-c', '--checkpoint',
        default='checkpoint.json',
        help='Archivo de checkpoint (default: checkpoint.json)'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Forzar reprocesamiento de todos los CVEs (ignorar checkpoint)'
    )
    parser.add_argument(
        '--skip-check',
        action='store_true',
        help='Omitir verificación de dependencias'
    )
    
    args = parser.parse_args()
    
    # Verificar dependencias
    if not args.skip_check:
        check_dependencies()
    
    # Verificar que el archivo de entrada existe
    if not os.path.exists(args.input):
        print(f"ERROR: Archivo de entrada no encontrado: {args.input}")
        sys.exit(1)
    
    # Crear updater y ejecutar
    updater = CVEDataUpdater(
        input_csv=args.input,
        output_csv=args.output,
        log_file=args.log,
        checkpoint_file=args.checkpoint,
        force=args.force
    )
    
    updater.run()


if __name__ == '__main__':
    main()
