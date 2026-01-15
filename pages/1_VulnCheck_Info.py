import streamlit as st
import streamlit_antd_components as sac
import vulncheck_sdk
import pandas as pd
import plotly.express as px
import logfire
#import calplot

# VulnCheck config
DEFAULT_HOST = "https://api.vulncheck.com"
DEFAULT_API = DEFAULT_HOST + "/v3"
TOKEN = st.secrets["VULNCHECK_API"]
YEAR = 2025

# Configure the VulnCheck API client
configuration = vulncheck_sdk.Configuration(host=DEFAULT_API)
configuration.api_key["Bearer"] = TOKEN

# Config Logfire
LOGFIRE = st.secrets["LOGFIRE"]
logfire.configure(token=LOGFIRE)
logfire.info('Vulncheck, {place}!', place='SAP COMPASS Vulns')

@st.cache_data
def get_df():
    with vulncheck_sdk.ApiClient(configuration) as api_client:
        indices_client = vulncheck_sdk.IndicesApi(api_client)

        limit = 2000

        # Initialize lists to store vendor and CVE data
        cve = []
        vendor = []
        product = []
        ransomware = []
        date_added = []
        cisa_date_added = []

        # Make the initial request to start pagination
        api_response = indices_client.index_vulncheck_kev_get(start_cursor="true", limit=limit)

        # Process the first page of results
        for entry in api_response.data:
            # Directly access the first element of the list
            cve.append(entry.cve[0])  # Since there is always one CVE in the list
            vendor.append(entry.vendor_project)
            product.append(entry.product)
            ransomware.append(entry.known_ransomware_campaign_use)
            date_added.append(entry.date_added[:10])

            # Handle cisa_date_added when it's None or has a date
            if entry.cisa_date_added is None:
                cisa_date_added.append("none")
            else:
                cisa_date_added.append(entry.cisa_date_added[:10])

        # Continue fetching data while there's a next cursor
        while api_response.meta.next_cursor is not None:

            # Fetch the next page using the cursor
            api_response = indices_client.index_vulncheck_kev_get(
                cursor=api_response.meta.next_cursor, limit=limit
            )

            # Append the new data from the next pa2025ge
            for entry in api_response.data:
                cve.append(entry.cve[0])
                vendor.append(entry.vendor_project)
                product.append(entry.product)
                ransomware.append(entry.known_ransomware_campaign_use)
                date_added.append(entry.date_added[:10])

                # Handle cisa_date_added when it's None or has a date
                if entry.cisa_date_added is None:
                    cisa_date_added.append("none")
                else:
                    cisa_date_added.append(entry.cisa_date_added[:10])

    # Create a DataFrame from the accumulated data
    df_original = pd.DataFrame({
        'CVE': cve,
        'Vendor': vendor,
        'Product': product,
        'Ransomware': ransomware,
        'Date Added': date_added,
        'CISA Date Added': cisa_date_added
    })

    return df_original

# Streamlit app setup
st.set_page_config(
    page_title="VulnCheck Info",
    page_icon="assets/favicon.ico",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# UI Components
st.logo("static/logo.png", link="https://dub.sh/dso-days", icon_image="static/logo.png", size='large')

sac.divider(label="<img height='96' width='96' src='https://cdn.simpleicons.org/SAP/white' /> Compass Priority Vulnerabilities", color='#ffffff')


st.title("VulnCheck Known Exploited Vulnerabilties", anchor=False)

vuln_data = get_df()

logfire.debug('Vulncheck, {place}!', place=vuln_data)

#filtered_vuln_data = vuln_data[vuln_data['Vendor'].isin(priority_filter) & df['sap_note_year'].isin(year_filter)]
filtered_vuln_data = vuln_data[vuln_data['Vendor'] == "SAP"]
st.dataframe(vuln_data)

df_kev = vuln_data.copy()

df_kev['Date Added'] = pd.to_datetime(df_kev['Date Added'])
df_kev['CISA Date Added'] = df_kev['CISA Date Added'].replace('none', pd.NaT)
df_kev['CISA Date Added'] = pd.to_datetime(df_kev['CISA Date Added'], format='%Y-%m-%d', errors='coerce')

# Get the current date and calculate the number of months passed in the year
current_date = df_kev['Date Added'].max()  # Use the latest date in 'Date Added'
months_passed = current_date.month if current_date.year == YEAR else 12  # Use full 12 months for past years

# VulnCheck KEV data for the specified year
df_kev_vulncheck_year = df_kev[df_kev['Date Added'].dt.year == YEAR]
total_kevs_vulncheck = df_kev_vulncheck_year['CVE'].nunique()
avg_kevs_per_month_vulncheck = total_kevs_vulncheck / months_passed

# CISA KEV data where 'CISA Date Added' is within the specified year
df_kev_cisa_year = df_kev[df_kev['CISA Date Added'].dt.year == YEAR]
total_kevs_cisa = df_kev_cisa_year['CVE'].nunique()
avg_kevs_per_month_cisa = total_kevs_cisa / months_passed

# Unique vendors and products for VulnCheck KEV
unique_vendors_vulncheck = df_kev_vulncheck_year['Vendor'].nunique()
unique_products_vulncheck = df_kev_vulncheck_year['Product'].nunique()

# Unique vendors and products for CISA KEV
unique_vendors_cisa = df_kev_cisa_year['Vendor'].nunique()
unique_products_cisa = df_kev_cisa_year['Product'].nunique()

# Compile statistics into a structured DataFrame with multi-level columns
stats_df_kev = pd.DataFrame({
    ("Total KEVs Added", "VulnCheck KEV"): [total_kevs_vulncheck],
    ("Total KEVs Added", "CISA KEV"): [total_kevs_cisa],
    ("Avg. KEVs per month", "VulnCheck KEV"): [avg_kevs_per_month_vulncheck],
    ("Avg. KEVs per month", "CISA KEV"): [avg_kevs_per_month_cisa],
    ("Unique Vendors", "VulnCheck KEV"): [unique_vendors_vulncheck],
    ("Unique Vendors", "CISA KEV"): [unique_vendors_cisa],
    ("Unique Products", "VulnCheck KEV"): [unique_products_vulncheck],
    ("Unique Products", "CISA KEV"): [unique_products_cisa],
})

# Set the year as the index
stats_df_kev.index = [YEAR]

style = [{'selector': 'th', 'props': [('font-weight', 'bold'), ('text-align', 'center')]}]

# Apply styling for centered text in both headers and cells and format averages to 1 decimal point
styled_stats_df_kev = stats_df_kev.style \
    .format({("Avg. KEVs per month", "VulnCheck KEV"): "{:.1f}", 
                ("Avg. KEVs per month", "CISA KEV"): "{:.1f}"}) \
    .set_table_styles({
        ('Total KEVs Added', 'VulnCheck KEV'): style,
        ('Total KEVs Added', 'CISA KEV'): style,
        ('Avg. KEVs per month', 'VulnCheck KEV'): style,
        ('Avg. KEVs per month', 'CISA KEV'): style,
        ('Unique Vendors', 'VulnCheck KEV'): style,
        ('Unique Vendors', 'CISA KEV'): style,
        ('Unique Products', 'VulnCheck KEV'): style,
        ('Unique Products', 'CISA KEV'): style
    }).set_properties(**{'text-align': 'center'}) \
    .set_caption(f"<b>{YEAR} Year-to-Date KEV Statistics</b>") \
    .set_table_attributes('style="width:100%; border-collapse: collapse;"')



sac.divider(label="2025 Known Exploited Vulnerabilities Statistics", color='#ffffff')

#st.subheader("2025 Known Exploited Vulnerabilities Statistics", anchor=False)
st.dataframe(styled_stats_df_kev)


