#!/usr/bin/env python3
"""
SAP Security Utils
Utilidades para el proyecto SAP Compass Vulns
"""

import csv
import json
import sys
import argparse
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import re


class CSVAnalyzer:
    """Analiza archivos CSV de CVEs SAP"""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.rows = []
        self.fieldnames = []
        self.cve_column = None
    
    def load(self):
        """Carga el archivo CSV"""
        with open(self.filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            self.fieldnames = list(reader.fieldnames)
            self.rows = list(reader)
        
        # Detectar columna CVE
        for col in self.fieldnames:
            if 'cve' in col.lower():
                self.cve_column = col
                break
        
        return self
    
    def stats(self):
        """Genera estadísticas del CSV"""
        print("\n" + "="*70)
        print("ESTADÍSTICAS DEL CSV")
        print("="*70)
        print(f"Archivo: {self.filepath}")
        print(f"Total de filas: {len(self.rows)}")
        print(f"Total de columnas: {len(self.fieldnames)}")
        print(f"\nColumnas:")
        for i, col in enumerate(self.fieldnames, 1):
            print(f"  {i:2d}. {col}")
        
        if self.cve_column:
            print(f"\n📊 Análisis de CVEs (columna: {self.cve_column}):")
            cves = [row[self.cve_column] for row in self.rows if row.get(self.cve_column)]
            print(f"  Total de CVEs: {len(cves)}")
            
            # CVEs por año
            years = Counter()
            for cve in cves:
                match = re.search(r'CVE-(\d{4})', cve)
                if match:
                    years[match.group(1)] += 1
            
            print(f"\n  CVEs por año:")
            for year in sorted(years.keys()):
                print(f"    {year}: {years[year]}")
        
        # Análisis de campos con datos
        print(f"\n📈 Completitud de datos:")
        for col in self.fieldnames:
            filled = sum(1 for row in self.rows if row.get(col) and row[col].strip())
            pct = (filled / len(self.rows) * 100) if self.rows else 0
            status = "✓" if pct > 80 else "⚠" if pct > 50 else "✗"
            print(f"  {status} {col:25s}: {filled:4d}/{len(self.rows)} ({pct:5.1f}%)")
        
        return self
    
    def compare(self, other_filepath):
        """Compara con otro CSV"""
        print("\n" + "="*70)
        print("COMPARACIÓN DE ARCHIVOS")
        print("="*70)
        
        other = CSVAnalyzer(other_filepath).load()
        
        # Comparar estructura
        print(f"\n📋 Estructura:")
        print(f"  Archivo 1: {len(self.fieldnames)} columnas, {len(self.rows)} filas")
        print(f"  Archivo 2: {len(other.fieldnames)} columnas, {len(other.rows)} filas")
        
        # Columnas diferentes
        cols1 = set(self.fieldnames)
        cols2 = set(other.fieldnames)
        
        only_in_1 = cols1 - cols2
        only_in_2 = cols2 - cols1
        common = cols1 & cols2
        
        print(f"\n  Columnas comunes: {len(common)}")
        if only_in_1:
            print(f"  Solo en archivo 1: {', '.join(only_in_1)}")
        if only_in_2:
            print(f"  Solo en archivo 2: {', '.join(only_in_2)}")
        
        # Comparar CVEs si ambos tienen columna CVE
        if self.cve_column and other.cve_column:
            cves1 = set(row[self.cve_column] for row in self.rows if row.get(self.cve_column))
            cves2 = set(row[other.cve_column] for row in other.rows if row.get(other.cve_column))
            
            print(f"\n📊 CVEs:")
            print(f"  Solo en archivo 1: {len(cves1 - cves2)}")
            print(f"  Solo en archivo 2: {len(cves2 - cves1)}")
            print(f"  En ambos: {len(cves1 & cves2)}")
    
    def validate(self):
        """Valida el formato y contenido del CSV"""
        print("\n" + "="*70)
        print("VALIDACIÓN DEL CSV")
        print("="*70)
        
        issues = []
        warnings = []
        
        # Validar formato CVE
        if self.cve_column:
            invalid_cves = []
            for i, row in enumerate(self.rows):
                cve = row.get(self.cve_column, '')
                if cve and not re.match(r'^CVE-\d{4}-\d+$', cve):
                    invalid_cves.append((i+2, cve))  # +2 por header y 0-index
            
            if invalid_cves:
                issues.append(f"CVEs con formato inválido: {len(invalid_cves)}")
                for line, cve in invalid_cves[:5]:
                    print(f"  Línea {line}: {cve}")
                if len(invalid_cves) > 5:
                    print(f"  ... y {len(invalid_cves)-5} más")
        
        # Verificar filas duplicadas
        if self.cve_column:
            cve_counts = Counter(row[self.cve_column] for row in self.rows if row.get(self.cve_column))
            duplicates = {cve: count for cve, count in cve_counts.items() if count > 1}
            
            if duplicates:
                warnings.append(f"CVEs duplicados: {len(duplicates)}")
                for cve, count in list(duplicates.items())[:5]:
                    print(f"  {cve}: aparece {count} veces")
        
        # Verificar campos vacíos importantes
        important_fields = ['cvss', 'epss', 'priority', 'descriptions']
        for field in important_fields:
            matching_cols = [col for col in self.fieldnames if field.lower() in col.lower()]
            if matching_cols:
                col = matching_cols[0]
                empty = sum(1 for row in self.rows if not row.get(col) or not row[col].strip())
                if empty > len(self.rows) * 0.2:  # >20% vacío
                    warnings.append(f"Campo '{col}' vacío en {empty} filas ({empty/len(self.rows)*100:.1f}%)")
        
        # Resumen
        print(f"\n{'='*70}")
        if issues:
            print(f"❌ Problemas encontrados: {len(issues)}")
            for issue in issues:
                print(f"  • {issue}")
        else:
            print(f"✓ No se encontraron problemas críticos")
        
        if warnings:
            print(f"\n⚠ Advertencias: {len(warnings)}")
            for warning in warnings:
                print(f"  • {warning}")
        
        return len(issues) == 0
    
    def export_summary(self, output_file):
        """Exporta un resumen en JSON"""
        summary = {
            'file': str(self.filepath),
            'timestamp': datetime.now().isoformat(),
            'total_rows': len(self.rows),
            'total_columns': len(self.fieldnames),
            'columns': self.fieldnames,
        }
        
        if self.cve_column:
            cves = [row[self.cve_column] for row in self.rows if row.get(self.cve_column)]
            years = Counter()
            for cve in cves:
                match = re.search(r'CVE-(\d{4})', cve)
                if match:
                    years[match.group(1)] += 1
            
            summary['cves'] = {
                'total': len(cves),
                'by_year': dict(years)
            }
        
        # Completitud de datos
        completeness = {}
        for col in self.fieldnames:
            filled = sum(1 for row in self.rows if row.get(col) and row[col].strip())
            completeness[col] = {
                'filled': filled,
                'total': len(self.rows),
                'percentage': round(filled / len(self.rows) * 100, 2) if self.rows else 0
            }
        
        summary['completeness'] = completeness
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        print(f"\n✓ Resumen exportado a: {output_file}")
        
        return summary


class CSVMerger:
    """Combina múltiples archivos CSV de CVEs"""
    
    def __init__(self, output_file):
        self.output_file = output_file
        self.files = []
        self.merged_rows = {}
        self.all_fieldnames = set()
    
    def add_file(self, filepath, priority=1):
        """Agrega un archivo para mergear"""
        self.files.append({'path': filepath, 'priority': priority})
        return self
    
    def merge(self):
        """Realiza el merge de los archivos"""
        print("\n" + "="*70)
        print("MERGEANDO ARCHIVOS CSV")
        print("="*70)
        
        # Ordenar por prioridad (mayor prioridad = más reciente/confiable)
        self.files.sort(key=lambda x: x['priority'], reverse=True)
        
        for file_info in self.files:
            filepath = file_info['path']
            priority = file_info['priority']
            
            print(f"\nProcesando: {filepath} (prioridad: {priority})")
            
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = list(reader.fieldnames)
                self.all_fieldnames.update(fieldnames)
                
                # Detectar columna CVE
                cve_col = None
                for col in fieldnames:
                    if 'cve' in col.lower():
                        cve_col = col
                        break
                
                if not cve_col:
                    print(f"  ⚠ No se encontró columna CVE, saltando archivo")
                    continue
                
                # Procesar filas
                count = 0
                for row in reader:
                    cve_id = row.get(cve_col, '').strip()
                    if not cve_id:
                        continue
                    
                    # Solo agregar/actualizar si no existe o tiene menor prioridad
                    if cve_id not in self.merged_rows:
                        self.merged_rows[cve_id] = {'priority': priority, 'data': row, 'source': filepath}
                        count += 1
                    elif self.merged_rows[cve_id]['priority'] < priority:
                        # Actualizar con datos de mayor prioridad
                        old_data = self.merged_rows[cve_id]['data']
                        for key, value in row.items():
                            if value and value.strip():  # Solo sobrescribir si hay valor
                                old_data[key] = value
                        self.merged_rows[cve_id]['priority'] = priority
                        count += 1
                
                print(f"  ✓ {count} CVEs procesados")
        
        print(f"\n{'='*70}")
        print(f"Total de CVEs únicos: {len(self.merged_rows)}")
        print(f"Total de columnas: {len(self.all_fieldnames)}")
        
        return self
    
    def save(self):
        """Guarda el resultado mergeado"""
        if not self.merged_rows:
            print("ERROR: No hay datos para guardar")
            return
        
        # Ordenar fieldnames
        fieldnames = sorted(self.all_fieldnames)
        
        with open(self.output_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for cve_id in sorted(self.merged_rows.keys()):
                row = self.merged_rows[cve_id]['data']
                # Asegurar que todas las columnas existen
                output_row = {col: row.get(col, '') for col in fieldnames}
                writer.writerow(output_row)
        
        print(f"\n✓ Archivo mergeado guardado: {self.output_file}")
        print(f"  - CVEs: {len(self.merged_rows)}")
        print(f"  - Columnas: {len(fieldnames)}")


def main():
    parser = argparse.ArgumentParser(
        description='Utilidades para archivos CSV de SAP CVEs',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Comando: stats
    stats_parser = subparsers.add_parser('stats', help='Mostrar estadísticas del CSV')
    stats_parser.add_argument('file', help='Archivo CSV a analizar')
    stats_parser.add_argument('-o', '--output', help='Exportar resumen a JSON')
    
    # Comando: compare
    compare_parser = subparsers.add_parser('compare', help='Comparar dos archivos CSV')
    compare_parser.add_argument('file1', help='Primer archivo CSV')
    compare_parser.add_argument('file2', help='Segundo archivo CSV')
    
    # Comando: validate
    validate_parser = subparsers.add_parser('validate', help='Validar formato del CSV')
    validate_parser.add_argument('file', help='Archivo CSV a validar')
    
    # Comando: merge
    merge_parser = subparsers.add_parser('merge', help='Combinar múltiples archivos CSV')
    merge_parser.add_argument('files', nargs='+', help='Archivos CSV a combinar')
    merge_parser.add_argument('-o', '--output', required=True, help='Archivo de salida')
    merge_parser.add_argument('-p', '--priorities', help='Prioridades (ej: 1,2,3)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Ejecutar comando
    if args.command == 'stats':
        analyzer = CSVAnalyzer(args.file).load()
        analyzer.stats()
        if args.output:
            analyzer.export_summary(args.output)
    
    elif args.command == 'compare':
        analyzer = CSVAnalyzer(args.file1).load()
        analyzer.compare(args.file2)
    
    elif args.command == 'validate':
        analyzer = CSVAnalyzer(args.file).load()
        is_valid = analyzer.validate()
        sys.exit(0 if is_valid else 1)
    
    elif args.command == 'merge':
        merger = CSVMerger(args.output)
        
        priorities = None
        if args.priorities:
            priorities = [int(x) for x in args.priorities.split(',')]
        
        for i, filepath in enumerate(args.files):
            priority = priorities[i] if priorities and i < len(priorities) else len(args.files) - i
            merger.add_file(filepath, priority)
        
        merger.merge().save()


if __name__ == '__main__':
    main()
