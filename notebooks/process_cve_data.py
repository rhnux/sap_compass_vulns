#!/usr/bin/env python3
"""
Script to process CVE data from SploitScan and CVE_Prioritizer outputs.
"""

import pandas as pd
import re
from typing import List, Dict
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def dataframe_sploitscan(file_json: str) -> pd.DataFrame:
    """
    Create a DataFrame from SploitScan JSON output.
    """
    try:
        data = pd.DataFrame(columns=[
            'cve_id', 'dateUpdated', 'descriptions', 'product_l', 'epss_l', 
            'percentile', 'priority_l', 'cweId', 'note_id'
        ])
        dict_list = []
        sap_sp = pd.read_json(file_json, typ='series')

        for i in sap_sp:
            # Extract CWE ID
            if 'problemTypes' in i['CVE Data']['containers']['cna'].keys():
                if 'cweId' in i['CVE Data']['containers']['cna']['problemTypes'][0]['descriptions'][0].keys():
                    cweId = i['CVE Data']['containers']['cna']['problemTypes'][0]['descriptions'][0]['cweId']
                else:
                    cweId = i['CVE Data']['containers']['cna']['problemTypes'][0]['descriptions'][0]['description']
            else:
                cweId = None

            # Extract EPSS data
            if len(i['EPSS Data']['data']) == 1:
                epss_l = i['EPSS Data']['data'][0]['epss']
                percentile = i['EPSS Data']['data'][0]['percentile']
            else:
                epss_l = None
                percentile = None

            # Extract datePublished
            datePublished = i['CVE Data']['cveMetadata'].get('datePublished', None)

            # Extract note_id from references
            if 'references' in i['CVE Data']['containers']['cna'].keys():
                note_id = re.findall('[2,3]{1}[0-9]{6}', str(i['CVE Data']['containers']['cna']['references'][0]['url']))
            else:
                note_id = None

            # Create a row dictionary
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

        # Convert the list of dictionaries to a DataFrame
        data = pd.DataFrame.from_dict(dict_list)
        return data

    except Exception as e:
        logger.error(f"Error processing SploitScan JSON file {file_json}: {str(e)}")
        raise

def process_year(year: int, sploitscan_json: str, cve_prioritizer_csv: str, sap_notes_csv: str) -> pd.DataFrame:
    """
    Process data for a specific year by merging SploitScan, CVE_Prioritizer, and SAP notes data.
    """
    try:
        # Load SploitScan data
        sp_sap_cve = dataframe_sploitscan(sploitscan_json)
        sp_sap_cve.drop_duplicates(subset=['cve_id'], inplace=True)

        # Load CVE_Prioritizer data
        cp_sap_cve = pd.read_csv(cve_prioritizer_csv)
        cp_sap_cve.drop_duplicates(subset=['cve_id'], inplace=True)

        # Load SAP notes data
        sap_notes = pd.read_csv(sap_notes_csv)

        # Merge the data
        sap_cve = sp_sap_cve.merge(sap_notes, on=['cve_id'])
        sap_cve = sap_cve.merge(cp_sap_cve, on=['cve_id'])
        sap_cve['sap_note_year'] = str(year)

        return sap_cve

    except Exception as e:
        logger.error(f"Error processing year {year}: {str(e)}")
        raise

def standardize_data(sap_cve_df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardize the data (e.g., Priority and cweId values).
    """
    try:
        # Standardize Priority values
        sap_cve_df.loc[
            (sap_cve_df['Priority'] == 'Hot') | 
            (sap_cve_df['Priority'] == 'HotNews') | 
            (sap_cve_df['Priority'] == 'Very High'), 'Priority'
        ] = 'Hot News'

        # Standardize cweId values
        sap_cve_df.loc[
            (sap_cve_df['cweId'] == 'Cross-Site Scripting') | 
            (sap_cve_df['cweId'] == 'Cross Site Scripting') | 
            (sap_cve_df['cweId'] == "Cross-Site Scripting (XSS)"), 'cweId'
        ] = "CWE-79"

        sap_cve_df.loc[
            (sap_cve_df['cweId'] == 'Missing Authorization check') | 
            (sap_cve_df['cweId'] == 'Missing Authorization') | 
            (sap_cve_df['cweId'] == 'Missing Authorization Check'), 'cweId'
        ] = "CWE-862"

        # Add more standardization rules as needed...

        return sap_cve_df

    except Exception as e:
        logger.error(f"Error standardizing data: {str(e)}")
        raise

def main(years: List[int], output_file: str) -> None:
    """
    Main function to process CVE data for multiple years and save the final DataFrame to a CSV file.
    """
    try:
        # Process data for each year
        dfs = []
        for year in years:
            sploitscan_json = f'sap_history_data_curate/aws_{year}.json'
            cve_prioritizer_csv = f'sap_history_data_curate/aws_{year}.csv'
            sap_notes_csv = f'sap_notes_{year}.csv'

            logger.info(f"Processing data for year {year}...")
            df = process_year(year, sploitscan_json, cve_prioritizer_csv, sap_notes_csv)
            dfs.append(df)

        # Combine all DataFrames
        sap_cve_df = pd.concat(dfs, ignore_index=True)

        # Standardize the data
        sap_cve_df = standardize_data(sap_cve_df)

        # Save the final DataFrame to a CSV file
        sap_cve_df.to_csv(output_file, index=False)
        logger.info(f"Final DataFrame saved to {output_file}")

    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
        raise

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Process CVE data from SploitScan and CVE_Prioritizer outputs.")
    parser.add_argument(
        '--years',
        nargs='+',
        type=int,
        required=True,
        help="List of years to process (e.g., 2021 2022 2023)."
    )
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help="Output CSV file to save the final DataFrame."
    )

    # Parse the arguments
    args = parser.parse_args()

    # Run the main function
    main(args.years, args.output)