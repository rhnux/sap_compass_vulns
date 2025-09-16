#!/usr/bin/env python3
"""
SAP CVE Automation Tool - BS4 Version
Parsea tablas de SAP Security Notes de forma robusta con BeautifulSoup.
"""

import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
from pathlib import Path
from datetime import datetime
import typer
from rich.console import Console

console = Console()
app = typer.Typer(help="🔐 SAP CVE Automation Tool - BS4")

class SAPCVEAutomation:
    def __init__(self):
        self.months = {
            1: 'january', 2: 'february', 3: 'march', 4: 'april',
            5: 'may', 6: 'june', 7: 'july', 8: 'august',
            9: 'september', 10: 'october', 11: 'november', 12: 'december'
        }
        self.output_dir = Path(f"sap_cve_analysis_{datetime.now().strftime('%Y%m%d')}")
        self.output_dir.mkdir(exist_ok=True)

    def extract_sap_data(self, year: int, month: int) -> pd.DataFrame:
        """Extrae y parsea todas las tablas SAP con BeautifulSoup"""
        month_name = self.months.get(month, '')
        url = f"https://support.sap.com/en/my-support/knowledge-base/security-notes-news/{month_name}-{year}.html"

        console.print(f"📡 Extrayendo datos de SAP: {month_name.title()} {year}")
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

    def process_sap_data(self, df: pd.DataFrame):
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

@app.command()
def analyze(year: int = None, month: int = None):
    """Ejecuta análisis básico con BS4"""
    if year is None:
        year = datetime.now().year
    if month is None:
        month = datetime.now().month

    console.print("="*60)
    console.print("🔐 SAP CVE AUTOMATION TOOL - BS4")
    console.print("="*60)
    console.print(f"📅 Analizando: {month:02d}/{year}")
    console.print("="*60)

    automation = SAPCVEAutomation()
    sap_df = automation.extract_sap_data(year, month)
    sap_df, cves = automation.process_sap_data(sap_df)

    console.print("\n📊 RESUMEN")
    console.print(f"Notas encontradas: {len(sap_df)}")
    console.print(f"CVEs encontrados: {len(cves)}")

    if not sap_df.empty:
        output = automation.output_dir / f"sap_notes_bs4_{year}{month:02d}.csv"
        sap_df.to_csv(output, index=False)
        console.print(f"💾 Guardado en {output}")

if __name__ == "__main__":
    app()
