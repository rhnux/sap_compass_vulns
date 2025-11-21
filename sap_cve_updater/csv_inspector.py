#!/usr/bin/env python3
"""
CSV Inspector - Diagnóstico rápido de CSV
Muestra información detallada sobre el archivo CSV
"""

import csv
import sys
import re
from collections import Counter


def inspect_csv(filename):
    """Inspecciona el archivo CSV y muestra información detallada"""
    
    print("="*70)
    print(f"INSPECCIONANDO: {filename}")
    print("="*70)
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            
            # Información de columnas
            print(f"\n📋 COLUMNAS ({len(fieldnames)}):")
            print("-" * 70)
            for i, col in enumerate(fieldnames, 1):
                print(f"  {i:2d}. '{col}'")
            
            # Buscar columna con CVE-IDs
            print(f"\n🔍 BUSCANDO COLUMNA CON CVE-IDs:")
            print("-" * 70)
            
            cve_columns = []
            for col in fieldnames:
                if any(x in col.upper() for x in ['CVE', 'ID']):
                    cve_columns.append(col)
                    print(f"  ✓ Candidato: '{col}'")
            
            if not cve_columns:
                print("  ⚠ No se encontraron columnas con 'CVE' o 'ID' en el nombre")
            
            # Analizar primeras filas
            print(f"\n📊 ANÁLISIS DE DATOS:")
            print("-" * 70)
            
            rows = []
            cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
            cve_stats = Counter()
            
            for i, row in enumerate(reader):
                rows.append(row)
                if i < 5:  # Primeras 5 filas
                    print(f"\n  Fila {i+1}:")
                    for key, value in row.items():
                        # Resaltar CVEs
                        if cve_pattern.match(str(value).strip()):
                            print(f"    '{key}': '{value}' ⭐ CVE ENCONTRADO")
                            cve_stats[key] += 1
                        else:
                            # Mostrar solo primeros 50 caracteres
                            short_value = str(value)[:50]
                            if len(str(value)) > 50:
                                short_value += "..."
                            print(f"    '{key}': '{short_value}'")
                
                if i >= 100:  # Limitar a 100 filas para estadísticas
                    break
            
            total_rows = len(rows)
            
            print(f"\n📈 ESTADÍSTICAS:")
            print("-" * 70)
            print(f"  Total de filas analizadas: {total_rows}")
            
            if cve_stats:
                print(f"\n  Columnas con CVE-IDs encontrados:")
                for col, count in cve_stats.most_common():
                    print(f"    '{col}': {count} CVEs en {total_rows} filas")
                    
                # Sugerir columna
                best_column = cve_stats.most_common(1)[0][0]
                print(f"\n  ✅ COLUMNA SUGERIDA: '{best_column}'")
            else:
                print(f"\n  ⚠ NO se encontraron CVE-IDs en formato 'CVE-YYYY-NNNNN'")
                print(f"  Verifica que el CSV contenga CVEs válidos")
            
            # Verificar checkpoint
            print(f"\n🔖 CHECKPOINT:")
            print("-" * 70)
            import os
            checkpoint_file = 'checkpoint.json'
            if os.path.exists(checkpoint_file):
                print(f"  ⚠ Archivo {checkpoint_file} existe")
                print(f"  Esto puede impedir que se procesen CVEs ya procesados")
                print(f"\n  Soluciones:")
                print(f"    1. Usar --force para reprocesar todo")
                print(f"    2. Eliminar checkpoint: rm {checkpoint_file}")
            else:
                print(f"  ✓ No existe checkpoint previo")
            
            print("\n" + "="*70)
            print("DIAGNÓSTICO COMPLETADO")
            print("="*70)
            
    except FileNotFoundError:
        print(f"\n❌ ERROR: Archivo no encontrado: {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: python csv_inspector.py <archivo.csv>")
        sys.exit(1)
    
    inspect_csv(sys.argv[1])
