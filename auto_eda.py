import streamlit as st
import pandas as pd
import plotly.express as px
import streamlit_antd_components as sac
import httpx

# SAP Notes data loading

df = pd.read_csv('data/sap_cve_last_01.csv', )
df['datePublished'] = pd.to_datetime(df['datePublished'], format='mixed', utc=True)
df['dateUpdated'] = pd.to_datetime(df['dateUpdated'], format='mixed', utc=True)

df.drop_duplicates(subset=['Note#'], inplace=True)

df['sap_note_year'] = df['sap_note_year'].astype('category')
df['Note#'] = df['Note#'].astype('category')
df['priority'] = df['priority'].astype('category')
df['priority_l'] = df['priority_l'].astype('category')
df['Priority'] = df['Priority'].astype('category')
df['cvss_severity'] = df['cvss_severity'].astype('category')
df['epss'] = (df['epss'] * 100).round(2)
df.info()

# Select A+|1+ CVEs & Get EPSS data of TOP Priorities CVEs
@st.cache_data
def sap_cve_top_priority():
    sap_cve_top = df[(df['priority_l'] == 'A+') | (df['priority'] == 'Priority 1+')]
    # cve list
    cves = sap_cve_top.cve_id.unique().tolist()
    string_list = [str(element) for element in cves]
    delimiter = " "
    result_string = delimiter.join(string_list)
    #print(result_string)
    epss_history = []
    for cve in cves:
        r = httpx.get(f'https://api.first.org/data/v1/epss?cve={cve}&scope=time-series')
        cve_ts = r.json()['data'][0]
        epss_history.append(cve_ts)
    r.close()
    return sap_cve_top, result_string, epss_history


st.set_page_config(
    page_title="SAP Compass Vulns",
    page_icon="assets/favicon.ico",
    layout="wide",
    initial_sidebar_state="collapsed",
)

LOGO_URL_LARGE = "https://dso-days-siteblog.vercel.app/assets/logo.png"
LOGO_URL_SMALL = "https://dso-days-siteblog.vercel.app/assets/logo.png"

logo_SAP = 'assets/sap.png'

#st.logo(image=icon_logo, )
st.logo(
     LOGO_URL_LARGE,
     link="https://dub.sh/dso-days",
     icon_image=LOGO_URL_SMALL,
     )

sac.divider(label='SAP Compass Vulns', icon=sac.BsIcon(name='compass', size=25), color='#04adbf')

st.sidebar.header("Filters")
#priority_filter = st.sidebar.multiselect("Select Priority Level", df['priority_l'].unique(), default=df['priority_l'].unique())
priority_filter = st.sidebar.multiselect("Select SAP Priority Level", df['Priority'].unique(), default=df['Priority'].unique())
on = st.sidebar.toggle("Priority Top 20")

if on:
    epps_h = sap_cve_top_priority()
    st.title("Top 20 SAP Priority Vulnerabilities")
    st.json(epps_h[2])

st.title("SAP Compass Priority Vulnerabilities")
# Filter DataFrame based on selection
#filtered_df = df[df['priority_l'].isin(priority_filter)]
filtered_df = df[df['Priority'].isin(priority_filter)]

vulns = filtered_df.shape[0]

st.subheader(f"Filtered Vulnerabilities | 🪲 :violet[{vulns}]")
#st.write(filtered_df[['Note#', 'cve_id', 'description']])
st.write(filtered_df[['Note#', 'cve_id', 'priority', 'priority_l', 'epss', 'cvss', 'kev', 'dateUpdated','product_l']])


col1, col2 = st.columns(2, vertical_alignment="bottom")

with col1:
    # Show CVSS Distribution
    st.subheader("EPSS Score Distribution")
    #fig_cvss = px.histogram(filtered_df, x="cvss", nbins=10, title="Distribution of CVSS Scores")
    #st.plotly_chart(fig_cvss, use_container_width=True )
    chart_data = filtered_df[["cvss","epss","cve_id","Note#"]]
    st.scatter_chart(chart_data,
                    y="epss",
                    x="cvss",
                    color="#ff1493",
                    use_container_width=True)

with col2:
    # Potentially Display another chart (like by date)
    st.subheader("Vulns Date Updated")
    df['dateUpdated'] = pd.to_datetime(df['dateUpdated'])
    count_by_date = df.groupby(df['dateUpdated'].dt.date).size().reset_index(name='count')
    st.bar_chart(count_by_date, y="count", x="dateUpdated",
                 color="#04adbf", use_container_width=True)




st.subheader("Parallel Category Diagram")
dfp = filtered_df[['sap_note_year','priority_l','priority','Priority','cvss_severity']]
fig_parallel = px.parallel_categories(
    dfp, dimensions=['sap_note_year','priority_l','priority','Priority','cvss_severity'],
    labels={'sap_note_year':'Year',
            'priority_l':'SploitScan',
            'priority':'CVE-Prioritizer',
            'Priority':'SAP',
            'cvss_severity':'cvssSeverity'},
            color=dfp['sap_note_year'],   
            color_continuous_scale="magenta")

st.plotly_chart(fig_parallel, theme=None, use_container_width=True)


with st.expander("Dataset Filtered Vulnerabilities"):
    st.subheader("Filtered Vulnerabilities")
    st.write(filtered_df)
