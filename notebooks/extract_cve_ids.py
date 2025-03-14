#!/usr/bin/env python3
"""
Script to extract CVE-IDs from SAP security notes for a specified year and save them to a .txt file.
"""

import argparse
import pandas as pd
import tabula
import re
from typing import List

# Configure logging
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_cve_ids_from_pdf(pdf_path: str) -> List[str]:
    """
    Extract CVE-IDs from a PDF file containing SAP security notes.
    """
    try:
        # Read the PDF using tabula
        df_list = tabula.read_pdf(pdf_path, pages='all', stream=True, pandas_options={'header': None})
        
        # Process the extracted data
        cve_ids = []
        for df in df_list:
            if not df.empty:
                # Debugging: Print the DataFrame to inspect its structure
                logger.debug(f"Extracted DataFrame:\n{df}")
                
                # Iterate through each row in the DataFrame
                for index, row in df.iterrows():
                    # Convert the row to a string and search for CVE-IDs
                    row_text = ' '.join(row.astype(str).tolist())
                    matches = re.findall(r'CVE-\d{4}-\d+', row_text)
                    if matches:
                        cve_ids.extend(matches)
        
        return cve_ids
    except Exception as e:
        logger.error(f"Error extracting CVE-IDs from {pdf_path}: {str(e)}")
        raise

def extract_cve_ids_from_html(url: str) -> List[str]:
    """
    Extract CVE-IDs from an HTML page containing SAP security notes.
    """
    try:
        # Read the HTML table using pandas
        df_list = pd.read_html(url, flavor='html5lib')
        
        # Process the extracted data
        cve_ids = []
        for df in df_list:
            if not df.empty:
                # Ensure the 'Title' column is treated as a string
                df['Title'] = df['Title'].astype(str)
                # Extract CVE-IDs from the 'Title' column
                extracted_cves = df['Title'].str.extract(r'(CVE-\d{4}-\d+)')[0].dropna().tolist()
                cve_ids.extend(extracted_cves)
        
        return cve_ids
    except Exception as e:
        logger.error(f"Error extracting CVE-IDs from {url}: {str(e)}")
        raise

def save_cve_ids_to_file(cve_ids: List[str], output_file: str) -> None:
    """
    Save the extracted CVE-IDs to a .txt file.
    """
    try:
        with open(output_file, 'w') as f:
            f.write('\n'.join(cve_ids))
        logger.info(f"CVE-IDs saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving CVE-IDs to {output_file}: {str(e)}")
        raise

def main(year: int) -> None:
    """
    Main function to extract CVE-IDs for the specified year and save them to a .txt file.
    """
    try:
        # Define the data source based on the year
        if year == 2021:
            pdf_path = '2021 Blog.pdf'
            cve_ids = extract_cve_ids_from_pdf(pdf_path)
        elif year == 2022:
            pdf_path = '2022 12 Patch Day Blog V9.0.pdf'
            cve_ids = extract_cve_ids_from_pdf(pdf_path)
        elif year == 2023:
            pdf_path = '2023 12 Patch Day Blog V2.0 (1).pdf'
            cve_ids = extract_cve_ids_from_pdf(pdf_path)
        elif year == 2024:
            url = 'https://support.sap.com/en/my-support/knowledge-base/security-notes-news/bulletin-2024.html'
            cve_ids = extract_cve_ids_from_html(url)
        elif year == 2025:
            url = 'https://support.sap.com/en/my-support/knowledge-base/security-notes-news/march-2025.html'
            cve_ids = extract_cve_ids_from_html(url)
        else:
            raise ValueError(f"Unsupported year: {year}. Supported years are 2021, 2022, 2023, 2024, and 2025.")
        
        # Save the CVE-IDs to a .txt file
        output_file = f"{year}_cve_ids.txt"
        save_cve_ids_to_file(cve_ids, output_file)
    
    except Exception as e:
        logger.error(f"Error processing year {year}: {str(e)}")
        raise

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Extract CVE-IDs from SAP security notes for a specified year.")
    parser.add_argument(
        '--year',
        type=int,
        required=True,
        choices=[2021, 2022, 2023, 2024, 2025],
        help="The year to extract CVE-IDs for. Supported years: 2021, 2022, 2023, 2024, 2025."
    )
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Run the main function
    main(args.year)