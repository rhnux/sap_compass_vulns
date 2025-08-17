#!/usr/bin/env python3
"""
SAP CVE Automation Tool - Versión Simplificada
Enfoque en hacer funcionar SploitScan correctamente
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
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import logging
import glob
import shutil

# Configurar Rich Console
console = Console():
sploitscan_df = pd.DataFrame()
    if not skip_sploitscan and cve_list:
        console.print("\n3️⃣ EJECUTANDO SPLOITSCAN")
        console.print("-" * 40)
        
        sploitscan_file = automation.run_sploitscan(cve_list, sploitscan_path)
        
        if sploitscan_file:
            # Copiar archivo al directorio de salida
            sploitscan_source = os.path.join(sploitscan_path, sploitscan_file) if sploitscan_path != "." else sploitscan_file
            sploitscan_dest = automation.output_dir / f"sploitscan_{year}{month:02d}.json"
            
            try:
                shutil.copy(sploitscan_source, sploitscan_dest)
                sploitscan_df = automation.dataframeSplotscan(str(sploitscan_dest))
            except Exception as e:
                console.print(f"❌ Error copiando archivo SploitScan: {e}")
                sploitscan_df = automation.dataframeSplotscan(sploitscan_source)
    
    # Paso 4: Ejecutar CVE_Prioritizer
    prioritizer_file = ""
    if not skip_prioritizer and cve_list:
        console.print("\n4️⃣ EJECUTANDO CVE_PRIORITIZER")
        console.print("-" * 40)
        
        csv_file = f"prioritizer_{year}{month:02d}.csv"
        
        if automation.run_cve_prioritizer(prioritizer_string, csv_file, prioritizer_path):
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

# Configurar logging básico
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear la app Typer
app = typer.Typer(help="🔒 SAP CVE Automation Tool")

class SAPCVEAutomation:
    """Clase principal para automatizar el análisis de CVEs de SAP"""
    
    def __init__(self):
        self.months = {
            1: 'january', 2: 'february', 3: 'march', 4: 'april',
            5: 'may', 6: 'june', 7: 'july', 8: 'august',
            9: 'september', 10: 'october', 11: 'november', 12: 'december'
        }
        self.output_dir = Path(f"sap_cve_analysis_{datetime.now().strftime('%Y%m%d')}")
        self.output_dir.mkdir(exist_ok=True)
        
    def extract_sap_data(self, year: int, month: int) -> List:
        """Extrae datos de vulnerabilidades SAP del mes especificado"""
        month_name = self.months.get(month, '')
        url = f'https://support.sap.com/en/my-support/knowledge-base/security-notes-news/{month_name}-{year}.html'
        
        console.print(f"📡 Extrayendo datos de SAP: {month_name.title()} {year}")
        console.print(f"🌐 URL: {url}")
        
        try:
            console.print("⏳ Descargando datos de SAP...")
            sap_data = pd.read_html(url, flavor='html5lib', header=0)
            
            if not sap_data:
                console.print("❌ No se encontraron datos en la página de SAP")
                return []
                
            console.print(f"✅ Datos extraídos exitosamente ({len(sap_data)} tablas encontradas)")
            return sap_data
            
        except Exception as e:
            console.print(f"❌ Error extrayendo datos de SAP: {str(e)}")
            logger.error(f"Error detallado: {str(e)}")
            return []
    
    def process_sap_data(self, sap_data: List) -> tuple:
        """Procesa los datos de SAP y extrae CVE-IDs - Replica exactamente tu notebook"""
        if not sap_data:
            return pd.DataFrame(), []
        
        console.print("🔄 Procesando datos de SAP...")
        
        try:
            # Usar exactamente la misma función de tu notebook
            def etData1(x):
                _df = pd.DataFrame(x[0], columns=['Note#', 'Title', 'Priority', 'CVSS'])
                _df["cve_id"] = _df["Title"].str.extract(r'(CVE-....-\d+)')
                return _df
            
            # Procesar igual que en tu notebook
            sap_df = etData1(sap_data)
            
            # Obtener lista de CVEs igual que en tu notebook
            l_sap_cve = sap_df.cve_id.to_list()
            clean_sap_cve = [x for x in l_sap_cve if str(x) != 'nan']
            
            console.print(f"✅ Procesados {len(sap_df)} registros, encontrados {len(clean_sap_cve)} CVE-IDs")
            
            return sap_df, clean_sap_cve
            
        except Exception as e:
            console.print(f"❌ Error procesando datos: {str(e)}")
            return pd.DataFrame(), []
    
    def create_cve_strings(self, cve_list: List[str]) -> tuple:
        """Crea strings de CVEs para las herramientas - igual que tu notebook"""
        if not cve_list:
            return "", ""
        
        # Para SploitScan (separado por espacios)
        string_list = [str(element) for element in cve_list]
        delimiter = " "
        result_string_cve = delimiter.join(string_list)
        
        # Para CVE_Prioritizer (separado por comas)
        prioritizer_string = ",".join(string_list)
        
        console.print(f"📝 Creados strings para herramientas:")
        console.print(f"   • SploitScan: {len(cve_list)} CVEs separados por espacios")
        console.print(f"   • CVE_Prioritizer: {len(cve_list)} CVEs separados por comas")
        
        return result_string_cve, prioritizer_string
    
    def run_sploitscan(self, cve_list: List[str], tool_path: str = ".") -> str:
        """Ejecuta SploitScan - ARREGLADO para pasar CVEs individualmente"""
        console.print("🔍 Ejecutando SploitScan...")
        console.print(f"CVEs a procesar: {len(cve_list)} CVEs")
        console.print(f"Primeros CVEs: {cve_list[:5]}")
        
        original_dir = os.getcwd()
        
        try:
            if tool_path != "." and os.path.exists(tool_path):
                os.chdir(tool_path)
                console.print(f"📁 Cambiado a directorio: {tool_path}")
            
            # Construir comando: sploitscan CVE1 CVE2 CVE3 ... -m ... -d -e json
            cmd = ["sploitscan"] + cve_list + ["-m", "cisa,epss,prio,references", "-d", "-e", "json"]
            
            console.print(f"🔄 Ejecutando comando con {len(cve_list)} CVEs")
            console.print(f"Comando: sploitscan {' '.join(cve_list[:3])}{'...' if len(cve_list) > 3 else ''} -m cisa,epss,prio,references -d -e json")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            console.print(f"📊 Return code: {result.returncode}")
            
            if result.stdout:
                console.print(f"📄 STDOUT:\n{result.stdout}")
            
            if result.stderr:
                console.print(f"⚠️ STDERR:\n{result.stderr}")
            
            if result.returncode == 0:
                console.print("✅ SploitScan ejecutado exitosamente")
                
                # Buscar archivo JSON generado
                time.sleep(2)  # Esperar que se escriba el archivo
                
                patterns = [
                    "*_and_*more_export.json",
                    "*_export.json", 
                    "sploitscan_*.json",
                    "*.json"
                ]
                
                for pattern in patterns:
                    matching_files = glob.glob(pattern)
                    if matching_files:
                        # Tomar el archivo más reciente
                        generated_file = max(matching_files, key=os.path.getmtime)
                        console.print(f"✅ Archivo encontrado: {generated_file}")
                        return generated_file
                
                console.print("⚠️ SploitScan completado pero no se encontró archivo JSON")
                # Listar archivos para debug
                all_files = os.listdir(".")
                json_files = [f for f in all_files if f.endswith('.json')]
                console.print(f"📋 Archivos JSON en directorio: {json_files}")
                return ""
                
            else:
                console.print(f"❌ SploitScan falló con código: {result.returncode}")
                return ""
                
        except subprocess.TimeoutExpired:
            console.print("⏰ Timeout en SploitScan (600 segundos)")
            return ""
        except FileNotFoundError:
            console.print("❌ Comando 'sploitscan' no encontrado")
            console.print("💡 Verificar que SploitScan esté instalado globalmente")
            return ""
        except Exception as e:
            console.print(f"❌ Error ejecutando SploitScan: {str(e)}")
            return ""
            
        finally:
            os.chdir(original_dir)
    
    def run_cve_prioritizer(self, cve_string: str, output_file: str, tool_path: str = ".") -> bool:
        """Ejecuta CVE_Prioritizer - SIMPLIFICADO, solo primera opción"""
        console.print("📊 Ejecutando CVE_Prioritizer...")
        console.print(f"CVEs a procesar: {cve_string[:100]}...")
        
        original_dir = os.getcwd()
        
        try:
            if tool_path != "." and os.path.exists(tool_path):
                os.chdir(tool_path)
                console.print(f"📁 Cambiado a directorio: {tool_path}")
            
            # SOLO ejecutar la primera opción: comando cve_prioritizer global
            cmd = ["cve_prioritizer", "-l", cve_string, "-vck", "-vc", "-v", "-o", output_file]
            
            console.print(f"🔄 Ejecutando: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            console.print(f"📊 Return code: {result.returncode}")
            
            if result.stdout:
                console.print(f"📄 STDOUT:\n{result.stdout}")
            
            if result.stderr:
                console.print(f"⚠️ STDERR:\n{result.stderr}")
            
            if result.returncode == 0 and os.path.exists(output_file):
                console.print(f"✅ CVE_Prioritizer completado: {output_file}")
                return True
            else:
                console.print("❌ CVE_Prioritizer falló")
                return False
            
        except subprocess.TimeoutExpired:
            console.print("⏰ Timeout en CVE_Prioritizer (600 segundos)")
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
        """Procesa SploitScan - EXACTAMENTE igual que tu notebook"""
        try:
            if not os.path.exists(file_json):
                console.print(f"❌ Archivo no encontrado: {file_json}")
                return pd.DataFrame()
            
            console.print("🔄 Procesando resultados de SploitScan...")
            
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
        """Combina todos los resultados - igual que tu notebook"""
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
            
            # Añadir año igual que en tu notebook
            result_df['sap_note_year'] = str(year)
            
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
    output_name: str = typer.Option(None, help="Nombre para archivo de salida")
):
    """🚀 Ejecuta el análisis completo de vulnerabilidades SAP"""
    
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
    console.print("🔒 SAP CVE AUTOMATION TOOL - SIMPLIFICADO")
    console.print("="*60)
    console.print(f"📅 Analizando: {month:02d}/{year}")
    console.print(f"🔍 SploitScan: {'❌ Saltado' if skip_sploitscan else '✅ Habilitado'}")
    console.print(f"📊 CVE_Prioritizer: {'❌ Saltado' if skip_prioritizer else '✅ Habilitado'}")
    console.print("="*60)
    
    automation = SAPCVEAutomation()
    
    # Paso 1: Extraer datos de SAP
    console.print("\n1️⃣ EXTRAYENDO DATOS DE SAP")
    console.print("-" * 40)
    sap_data = automation.extract_sap_data(year, month)
    
    if not sap_data:
        console.print("❌ No se pudieron obtener datos de SAP. Abortando.")
        raise typer.Exit(1)
    
    # Paso 2: Procesar datos
    console.print("\n2️⃣ PROCESANDO DATOS SAP")
    console.print("-" * 40)
    sap_df, cve_list = automation.process_sap_data(sap_data)
    
    if not cve_list:
        console.print("⚠️ No se encontraron CVE-IDs. Solo se guardarán datos SAP.")
        skip_sploitscan = skip_prioritizer = True
    else:
        # No crear strings, usar directamente la lista
        console.print(f"📝 {len(cve_list)} CVEs listos para procesar")
        prioritizer_string = ",".join(cve_list)
    
    # Paso 3: Ejecutar SploitScan
    sploitscan_df = pd.DataFrame()
    if not skip_sploitscan and cve_list:
        console.print("\n3️⃣ EJECUTANDO SPLOITSCAN")
        console.print("-" * 40)
        
        sploitscan_file = automation.run_sploitscan(cve_list, sploitscan_path)
        
        if sploitscan_file:
            # Copiar archivo al directorio de salida
            sploitscan_source = os.path.join(sploitscan_path, sploitscan_file) if sploitscan_path != "." else sploitscan_file
            sploitscan_dest = automation.output_dir / f"sploitscan_{year}{month:02d}.json"
            
            try:
                shutil.copy(sploitscan_source, sploitscan_dest)
                sploitscan_df = automation.dataframeSplotscan(str(sploitscan_dest))
            except Exception as e:
                console.print(f"❌ Error copiando archivo SploitScan: {e}")
                sploitscan_df = automation.dataframeSplotscan(sploitscan_source)
    
    # Paso 4: Ejecutar CVE_Prioritizer
    prioritizer_file = ""
    if not skip_prioritizer and cve_list:
        console.print("\n4️⃣ EJECUTANDO CVE_PRIORITIZER")
        console.print("-" * 40)
        
        csv_file = f"prioritizer_{year}{month:02d}.csv"
        
        if automation.run_cve_prioritizer(prioritizer_string, csv_file, prioritizer_path):
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
        result = subprocess.run(["sploitscan", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            console.print("✅ sploitscan - FUNCIONA")
        else:
            console.print("❌ sploitscan - Error")
    except:
        console.print("❌ sploitscan - No encontrado")
    
    # Probar CVE_Prioritizer
    console.print("\n📊 Probando CVE_Prioritizer:")
    try:
        result = subprocess.run(["cve_prioritizer", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            console.print("✅ cve_prioritizer - FUNCIONA")
        else:
            console.print("❌ cve_prioritizer - Error")
    except:
        console.print("❌ cve_prioritizer - No encontrado")

if __name__ == "__main__":
    app()