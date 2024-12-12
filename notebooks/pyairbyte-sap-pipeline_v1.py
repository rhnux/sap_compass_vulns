import io
import pandas as pd
import numpy as np
import airbyte as ab
import tabula
import requests
from typing import List, Dict, Any

def extract_pdf_data(pdf_path: str) -> List[pd.DataFrame]:
    """
    Extract data from PDF using Tabula
    
    Args:
        pdf_path (str): Path to the PDF file
    
    Returns:
        List[pd.DataFrame]: List of DataFrames extracted from PDF
    """
    return tabula.read_pdf(pdf_path, pages='all', stream=True, pandas_options={'header': None})

def process_pdf_headers(dataframes: List[pd.DataFrame]) -> List[pd.DataFrame]:
    """
    Process headers and extract CVE IDs for PDF data
    
    Args:
        dataframes (List[pd.DataFrame]): List of input DataFrames
    
    Returns:
        List[pd.DataFrame]: Processed DataFrames with proper headers
    """
    data_list = []
    header = dataframes[0].iloc[0]
    dataframes[0].columns = header
    dataframes[0] = dataframes[0].drop([0])
    dataframes[0]["cve_id"] = dataframes[0]["Title"].str.extract(r'(CVE-....-\d+)')
    
    for df in dataframes:
        if df.shape[1] == header.shape[0]:
            df.columns = header
            df["cve_id"] = df["Title"].str.extract(r'(CVE-....-\d+)')
            data_list.append(df)
    
    return data_list

def merge_pdf_titles(df: pd.DataFrame) -> pd.DataFrame:
    """
    Merge titles and clean up the DataFrame for PDF data
    
    Args:
        df (pd.DataFrame): Input DataFrame
    
    Returns:
        pd.DataFrame: Processed DataFrame
    """
    df['Title'] = df['Title'].astype(str)
    blocks = df['CVSS'].notna().cumsum()
    
    agg_dict = {col:' '.join if col=='Title' else 'first' for col in df}
    df_t = df.groupby(blocks).agg(agg_dict).reset_index(drop=True)
    
    df_t.dropna(inplace=True)
    df_t = df_t[(df_t['Note#'] != 'Note#')]
    df_t['Note#'] = df_t['Note#'].astype(int)
    df_t.reset_index(drop=True, inplace=True)
    
    return df_t

def extract_web_data(url: str) -> pd.DataFrame:
    """
    Extract SAP security notes from web page
    
    Args:
        url (str): URL of the SAP security notes page
    
    Returns:
        pd.DataFrame: Extracted security notes
    """
    try:
        tables = pd.read_html(url, flavor='html5lib')
        return tables
    except Exception as e:
        print(f"Error extracting data from {url}: {e}")
        return None

def process_web_data(data: List[pd.DataFrame], is_first_format: bool = True) -> pd.DataFrame:
    """
    Process web scraped data into a consistent DataFrame
    
    Args:
        data (List[pd.DataFrame]): List of DataFrames from web scraping
        is_first_format (bool): Whether to use first or second data format
    
    Returns:
        pd.DataFrame: Processed DataFrame
    """
    if not data:
        return pd.DataFrame()
    
    if is_first_format:
        df = pd.DataFrame(data[0], columns=['Note#', 'Title', 'Severity', 'CVSS'])
        df.rename(columns={'Severity': 'Priority'}, inplace=True)
    else:
        df = pd.DataFrame(data[0], columns=['Note#', 'Title', 'Priority', 'CVSS'])
    
    df["cve_id"] = df["Title"].str.extract(r'(CVE-....-\d+)')
    return df

def create_sap_notes_pipeline():
    """
    Create a comprehensive SAP security notes pipeline
    """
    # PDF Processing for previous years
    pdf_years = [
        ('2021 Blog.pdf', '2021_patch_notes.csv'),
        ('2022 12 Patch Day Blog V9.0.pdf', '2022_patch_notes.csv'),
        ('2023 12 Patch Day Blog V2.0 (1).pdf', '2023_patch_notes.csv')
    ]
    
    pdf_dataframes = []
    for pdf_path, csv_path in pdf_years:
        raw_dataframes = extract_pdf_data(pdf_path)
        processed_dataframes = process_pdf_headers(raw_dataframes)
        merged_df = pd.concat(processed_dataframes)
        final_df = merge_pdf_titles(merged_df)
        final_df.to_csv(csv_path, index=False)
        pdf_dataframes.append(final_df)
    
    # Web Scraping for 2024
    web_months = [
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2024.html', True),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/february-2024.html', True),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/march-2024.html', True),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/april-2024.html', True),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/may-2024.html', True),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/june-2024.html', True),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/july-2024.html', False),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/august-2024.html', False),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/september-2024.html', False),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/october-2024.html', False),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/november-2024.html', False),
        ('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/december-2024.html', False)
    ]
    
    web_dataframes = []
    for url, is_first_format in web_months:
        web_data = extract_web_data(url)
        if web_data:
            processed_df = process_web_data(web_data, is_first_format)
            web_dataframes.append(processed_df)
    
    # Combine all years of data
    sap_2024_notes = pd.concat(web_dataframes).dropna()
    sap_2024_notes.to_csv('sap_2024_notes.csv', index=False)
    
    # Combine all years
    all_notes_dataframes = pdf_dataframes + [sap_2024_notes]
    sap_all_notes = pd.concat(all_notes_dataframes)
    sap_all_notes.to_csv('sap_all_security_notes.csv', index=False)
    
    # Optional: Create Airbyte Pipeline for CSV files
    csv_files = [
        '2021_patch_notes.csv', 
        '2022_patch_notes.csv', 
        '2023_patch_notes.csv', 
        'sap_2024_notes.csv',
        'sap_all_security_notes.csv'
    ]
    
    # Create sources from CSV files
    sources = [
        ab.get_source(
            "source-csv",
            install_if_missing=True,
            config={
                "dataset_name": f"sap_notes_{file.split('.')[0]}",
                "file_path": file
            }
        ) for file in csv_files
    ]
    
    # Create local destination
    destination = ab.get_destination(
        "destination-local-csv",
        config={
            "destination_path": "./airbyte_output"
        }
    )
    
    # Create and sync connections
    for source in sources:
        connection = source.to_connection(destination)
        connection.sync()

def main():
    create_sap_notes_pipeline()

if __name__ == "__main__":
    main()

# Requirements:
# pip install airbyte pandas tabula-py numpy requests html5lib
