import pandas as pd
import numpy as np
import tabula
import re
import argparse
from pathlib import Path

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Process CVE data and generate a CSV file.')
    parser.add_argument('-o', '--output', required=True, help='Output CSV file name')
    return parser.parse_args()

def new_header(xdf):
    """Create a new header for the DataFrame."""
    data_list = []
    header = xdf[0].iloc[0]
    xdf[0].columns = header
    xdf[0] = xdf[0].drop([0])
    xdf[0]["cve_id"] = xdf[0]["Title"].str.extract(r'(CVE-....-\d+)')
    for i in range(0, len(xdf)):
        if i == 0:
            data = xdf[i].iloc[1:]
        else:
            data = xdf[i]
        if data.shape[1] == header.shape[0]:
            data.columns = header
            xdf[i]["cve_id"] = xdf[i]["Title"].str.extract(r'(CVE-....-\d+)')
            data_list.append(data)
    return data_list

def merge_title(ydf):
    """Merge rows in the 'Title' column."""
    ydf['Title'] = ydf['Title'].astype(str)
    blocks = ydf['CVSS'].notna().cumsum()
    agg_dict = {col: ' '.join if col == 'Title' else 'first' for col in ydf}
    df_t = ydf.groupby(blocks).agg(agg_dict).reset_index(drop=True)
    df_t.dropna(inplace=True)
    df_t = df_t[(df_t['Note#'] != 'Note#')]
    df_t['Note#'] = df_t['Note#'].astype(int)
    df_t.reset_index(drop=True, inplace=True)
    return df_t

def ds_sap_24(x):
    """Process SAP 2024 data."""
    sap_2024_ls = []
    for mes in x:
        mes.rename(columns={'Severity': 'Priority'}, inplace=True)
        sap_2024_ls.append(mes)
    sap_2024 = pd.concat(sap_2024_ls, ignore_index=True)
    sap_2024["cve_id"] = sap_2024["Title"].str.extract(r'(CVE-....-\d+)')
    return sap_2024

def et_data(x):
    """Extract and transform data."""
    _df = pd.DataFrame(x[0], columns=['Note#', 'Title', 'Severity', 'CVSS'])
    _df.rename(columns={'Severity': 'Priority'}, inplace=True)
    _df["cve_id"] = _df["Title"].str.extract(r'(CVE-....-\d+)')
    return _df

def dataframe_splotscan(file_json):
    """Create a DataFrame from SploitScan JSON data."""
    data = pd.DataFrame(columns=['cve_id', 'dateUpdated', 'descriptions', 'product_l', 'epss_l', 'percentile', 'priority_l', 'cweId'])
    dict_list = []
    sap_sp = pd.read_json(f'{file_json}', typ='series')
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
    return data

def standardize_cwe_ids(df):
    """Standardize CWE IDs in the DataFrame."""
    cwe_mappings = {
        'Cross-Site Scripting': 'CWE-79',
        'Cross Site Scripting': 'CWE-79',
        'Cross-Site Scripting (XSS)': 'CWE-79',
        'Missing Authorization check': 'CWE-862',
        'Missing Authorization': 'CWE-862',
        'Missing Authorization Check': 'CWE-862',
        'CVE-2021-21484': 'CWE-863',
        'CVE-2023-30533': 'CWE-1321',
        'CVE-2022-35737': 'CWE-129',
        'CVE-2023-44487': 'CWE-400',
        'CVE-2020-6308': 'CWE-918',
        'CVE-2020-6207': 'CWE-306',
        'CVE-2021-33690': 'CWE-918',
        'CVE-2021-38163': 'CWE-78',
        'CVE-2021-44235': 'CWE-78',
        'CVE-2021-37531': 'CWE-78',
        'CVE-2021-33663': 'CWE-74',
        'CVE-2024-33007': 'CWE-79',
        'CVE-2021-27608': 'CWE-428',
        'CVE-2021-27635': 'CWE-112',
        'CVE-2021-27617': 'CWE-112',
        'CVE-2021-40499': 'CWE-94',
        'CVE-2021-27611': 'CWE-94',
        'CVE-2021-21466': 'CWE-94',
        'CVE-2021-27602': 'CWE-94',
        'CVE-2021-44231': 'CWE-94',
        'CVE-2021-21480': 'CWE-94',
        'CVE-2020-10683': 'CWE-611',
        'CVE-2021-21444': 'CWE-1021',
        'CVE-2019-17495': 'CWE-352',
        'CVE-2021-44151': 'CWE-330',
        'CVE-2013-3587': 'CWE-200',
        'CVE-2019-0388': 'CWE-290',
        'CVE-2020-26816': 'CWE-312',
        'CVE-2020-6215': 'CWE-601',
        'CVE-2020-6224': 'CWE-532',
        'CVE-2021-21445': 'CWE-444',
        'CVE-2021-21449': 'CWE-119',
        'CVE-2021-21465': 'CWE-89',
        'CVE-2021-21469': 'CWE-200',
        'CVE-2021-21470': 'CWE-611',
        'CVE-2021-21472': 'CWE-306',
        'CVE-2021-21474': 'CWE-326',
        'CVE-2021-21475': 'CWE-22',
        'CVE-2021-21476': 'CWE-601',
        'CVE-2021-21477': 'CWE-94',
        'CVE-2021-21478': 'CWE-601',
        'CVE-2021-21488': 'CWE-502',
        'CVE-2021-21491': 'CWE-601',
        'CVE-2021-27610': 'CWE-287',
        'CVE-2021-27612': 'CWE-601',
        'CVE-2021-27638': 'CWE-20',
        'CVE-2021-33672': 'CWE-116',
        'CVE-2021-33676': 'CWE-862',
        'CVE-2021-33685': 'CWE-22',
        'CVE-2021-33687': 'CWE-200',
        'CVE-2021-33688': 'CWE-89',
        'CVE-2021-38150': 'CWE-312',
        'CVE-2021-38176': 'CWE-89',
        'CVE-2021-38177': 'CWE-476',
        'CVE-2021-40497': 'CWE-668',
        'CVE-2021-42064': 'CWE-89',
        'CVE-2021-42068': 'CWE-20',
        'CVE-2021-44232': 'CWE-22',
        'CVE-2023-0215': 'CWE-416',
        'CVE-2020-6369': 'CWE-798',
        'CVE-2020-13936': 'CWE-94',
        'CVE-2021-21446': 'CWE-400',
        'CVE-2021-21482': 'CWE-200',
        'CVE-2021-21483': 'CWE-200',
        'CVE-2021-21485': 'CWE-200',
        'CVE-2024-47593': 'CWE-524',
        'CVE-2022-26104': 'CWE-862',
    }
    df['cweId'] = df['cweId'].replace(cwe_mappings)
    return df

def main():
    args = parse_arguments()
    output_file = Path(args.output)

    # Load and process PDF data
    dft_2021 = tabula.read_pdf('2021 Blog.pdf', pages='all', stream=True, pandas_options={'header': None})
    dft_2022 = tabula.read_pdf('2022 12 Patch Day Blog V9.0.pdf', pages='all', stream=True, pandas_options={'header': None})
    dft_2023 = tabula.read_pdf('2023 12 Patch Day Blog V2.0 (1).pdf', pages='all', stream=True, pandas_options={'header': None})

    dftt_2021 = new_header(dft_2021)
    dftt_2022 = new_header(dft_2022)
    dftt_2023 = new_header(dft_2023)

    sap_2021 = pd.concat(dftt_2021)
    sap_2022 = pd.concat(dftt_2022)
    sap_2023 = pd.concat(dftt_2023)

    sap_2021_notes = merge_title(sap_2021)
    sap_2022_notes = merge_title(sap_2022)
    sap_2023_notes = merge_title(sap_2023)

    # Load and process HTML data
    sap_2024_all = pd.read_html('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/bulletin-2024.html', flavor='html5lib')
    sap_2024_df = ds_sap_24(sap_2024_all)

    sap_202501 = pd.read_html('https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2025.html', flavor='html5lib')
    sap_202501_df = et_data(sap_202501)
    sap_2025_notes = sap_202501_df.dropna()
    sap_2025_notes.replace({'Priority': 'Critical'}, {'Priority': 'Hot News'}, inplace=True)

    # Load and process JSON data
    sp_sap_cve_2021 = dataframe_splotscan('../2021_aws.json')
    sp_sap_cve_2021.drop_duplicates(subset=['cve_id'], inplace=True)
    sp_sap_cve_2022 = dataframe_splotscan('../2022_aws.json')
    sp_sap_cve_2022.drop_duplicates(subset=['cve_id'], inplace=True)
    sp_sap_cve_2023 = dataframe_splotscan('../2023_aws.json')
    sp_sap_cve_2023.drop_duplicates(subset=['cve_id'], inplace=True)
    sp_sap_cve_2024 = dataframe_splotscan('../2024_aws.json')
    sp_sap_cve_2024.drop_duplicates(subset=['cve_id'], inplace=True)
    sp_sap_cve_2025 = dataframe_splotscan('../2025_aws.json')
    sp_sap_cve_2025.drop_duplicates(subset=['cve_id'], inplace=True)

    # Load CSV data
    cp_sap_cve_2021 = pd.read_csv('../2021_aws.csv')
    cp_sap_cve_2022 = pd.read_csv('../2022_aws.csv')
    cp_sap_cve_2023 = pd.read_csv('../2023_aws.csv')
    cp_sap_cve_2024 = pd.read_csv('../2024_aws.csv')
    cp_sap_cve_2025 = pd.read_csv('../2025_aws.csv')

    cp_sap_cve_2021.drop_duplicates(subset=['cve_id'], inplace=True)
    cp_sap_cve_2022.drop_duplicates(subset=['cve_id'], inplace=True)
    cp_sap_cve_2023.drop_duplicates(subset=['cve_id'], inplace=True)
    cp_sap_cve_2024.drop_duplicates(subset=['cve_id'], inplace=True)
    cp_sap_cve_2025.drop_duplicates(subset=['cve_id'], inplace=True)

    # Merge dataframes
    sap_cve_2023 = sap_2023_notes.merge(sp_sap_cve_2023, on=['cve_id'])
    sap_cve_2023 = sap_cve_2023.merge(cp_sap_cve_2023, on=['cve_id'])
    sap_cve_2023['sap_note_year'] = '2023'

    sap_cve_2022 = sp_sap_cve_2022.merge(sap_2022_notes, on=['cve_id'])
    sap_cve_2022 = sap_cve_2022.merge(cp_sap_cve_2022, on=['cve_id'])
    sap_cve_2022['sap_note_year'] = '2022'

    sap_cve_2021 = sp_sap_cve_2021.merge(sap_2021_notes, on=['cve_id'])
    sap_cve_2021 = sap_cve_2021.merge(cp_sap_cve_2021, on=['cve_id'])
    sap_cve_2021['sap_note_year'] = '2021'

    sap_cve_2024 = sp_sap_cve_2024.merge(sap_2024_df, on=['cve_id'])
    sap_cve_2024 = sap_cve_2024.merge(cp_sap_cve_2024, on=['cve_id'])
    sap_cve_2024['sap_note_year'] = '2024'

    sap_cve_2025 = sp_sap_cve_2025.merge(sap_2025_notes, on=['cve_id'])
    sap_cve_2025 = sap_cve_2025.merge(cp_sap_cve_2025, on=['cve_id'])
    sap_cve_2025['sap_note_year'] = '2025'

    # Concatenate all dataframes
    sap_cve_df = pd.concat([sap_cve_2021, sap_cve_2022, sap_cve_2023, sap_cve_2024, sap_cve_2025], ignore_index=True)

    # Standardize CWE IDs
    sap_cve_df = standardize_cwe_ids(sap_cve_df)

    # Save the final DataFrame to CSV
    sap_cve_df.to_csv(output_file, index=False)
    print(f"Data successfully saved to {output_file}")

if __name__ == "__main__":
    main()
