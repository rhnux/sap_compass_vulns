import streamlit as st
import pandas as pd
import plotly.express as px
import streamlit_antd_components as sac
import httpx
import re

# SAP Notes data loading

df = pd.read_csv('data/sap_cve_last_02.csv', )
df['datePublished'] = pd.to_datetime(df['datePublished'], format='mixed', utc=True)
df['dateUpdated'] = pd.to_datetime(df['dateUpdated'], format='mixed', utc=True)

df.drop_duplicates(subset=['Note#'], inplace=True)

df['sap_note_year'] = df['sap_note_year'].astype('category')
df['Note#'] = df['Note#'].astype('category')
df['priority'] = df['priority'].astype('category')
df['priority_l'] = df['priority_l'].astype('category')
df['Priority'] = df['Priority'].astype('category')
df['cvss_severity'] = df['cvss_severity'].astype('category')
df['cveInfo'] = df['cve_id'].apply(lambda x: x.replace(f'{x}', f'https://www.cvedetails.com/cve/{x}'))
df['cveSAP'] = df['cve_id'].apply(lambda x: x.replace(f'{x}', f'https://me.sap.com/notes/{x}'))
df['epss'] = df['epss'].map(lambda x: x * 100).astype('float').round(2)
df.info()

# Select A+|1+ CVEs & Get EPSS data of TOP Priorities CVEs
@st.cache_data
def sap_cve_top_priority(xdf):
    sap_cve_top = xdf[(xdf['priority_l'] == 'A+') | (xdf['priority'] == 'Priority 1+')]
    col_epss_hist = []
    for index, row in sap_cve_top.iterrows():
        cve = row['cve_id']
        r = httpx.get(f'https://api.first.org/data/v1/epss?cve={cve}&scope=time-series')
        epss_ts = r.json()['data'][0]
        epss_hist = []
        for l in epss_ts['time-series']:
            epss_hist.append(float(l['epss'])*100)
            
        epss_hist.reverse()
        col_epss_hist.append(epss_hist)
    return sap_cve_top, col_epss_hist


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
filtered_df = df[df['Priority'].isin(priority_filter)]
on = st.sidebar.toggle("Priority Top")

if on:
    with st.container():
        epss_h = sap_cve_top_priority(filtered_df)
        sap_cve_top25 = epss_h[0].copy()
        sap_cve_top25 = sap_cve_top25.assign(epss_l_30 = epss_h[1])
        top = sap_cve_top25.shape[0]
        st.title(f":violet[Top {top}] SAP Priority Vulnerabilities")
        sap_cve_top252 = sap_cve_top25[['Note#','cve_id','priority_l',
                                        'priority','cvss','epss_l_30','cweId']]
        st.dataframe(sap_cve_top252,
                    column_config = {
                        "Note#": "SAP Note#",
                        "cve_id": "cve_id",
                        "priority_l": "priority_l",
                        "priority": "priority",
                        "cvss": "cvssScore",
                        "epss_l_30": st.column_config.AreaChartColumn("EPSS (Last 30 days)", y_min=0, y_max=100),
                        "cweId": "CWE"
                        },
                    hide_index=True,
                    )
        #st.write(sap_cve_top25)
        #st.json(epss_h[1])
        col1t25, col2t25 = st.columns(2, vertical_alignment="bottom")
        with col1t25:
            # Show CVSS Distribution
            st.subheader("EPSS Score Distribution")
            chart_data = sap_cve_top25[["cvss","epss","cve_id","Note#"]]
            st.scatter_chart(chart_data,
                            y="epss",
                            x="cvss",
                            x_label="CVSS Score",
                            y_label="EPSS %",
                            color="#ff1493",
                            use_container_width=True)

        with col2t25:
            # Potentially Display another chart (like by date)
            st.subheader("Vulns Date Updated")
            sap_cve_top25['dateUpdated'] = pd.to_datetime(sap_cve_top25['dateUpdated'])
            count_by_date = sap_cve_top25.groupby(sap_cve_top25['dateUpdated'].dt.date).size().reset_index(name='count')
            st.bar_chart(count_by_date, y="count", x="dateUpdated",
                        color="#04adbf", use_container_width=True)

st.title("SAP Compass Priority Vulnerabilities")
# Filter DataFrame based on selection
#filtered_df = df[df['priority_l'].isin(priority_filter)]

vulns = filtered_df.shape[0]

st.subheader(f"Filtered Vulnerabilities | 🪲 :violet[{vulns}]")
#st.write(filtered_df[['Note#', 'cve_id', 'description']])
st.dataframe(filtered_df[['Note#', 'cveInfo', 'cveSAP', 'Priority', 'priority', 'priority_l',
                          'epss', 'cvss', 'product_l']],
             column_config={
                 "epss": st.column_config.NumberColumn(
                     "EPSS %",
                     help="Probabilidad para explotar la vulnerabilidad."
             #        min_value=0,
             #        max_value=100,
                     #step=1,
                     #format="%.2f",
                     ),
                 "cveInfo": st.column_config.LinkColumn(
                     "cveInfo",
                     help="CVE Details",
                     #validate=r"^https://www.cvedetails.com/cve/[a-z]$",
                     max_chars=50,
                     display_text=r"(CVE-....-\d+)"
                     ),
                 "cveSAP": st.column_config.LinkColumn(
                     "cveSAP",
                     help="CVE SAP Details",
                     #validate=r"^https://www.cvedetails.com/cve/[a-z]$",
                     max_chars=50,
                     display_text=r"(CVE-....-\d+)"
                     ),
             },
             hide_index=True)


col1, col2 = st.columns(2, vertical_alignment="bottom")

with col1:
    # Show CVSS Distribution
    st.subheader("EPSS Score Distribution")
    chart_data = filtered_df[["cvss","epss","cve_id","Note#"]]
    st.scatter_chart(chart_data,
                    y="epss",
                    x="cvss",
                    x_label="CVSS Score",
                    y_label="EPSS %",
                    color="#ff1493",
                    use_container_width=True)

with col2:
    # Potentially Display another chart (like by date)
    st.subheader("Vulns Date Published")
    df['dateUpdated'] = pd.to_datetime(df['datePublished'])
    count_by_date = df.groupby(df['datePublished'].dt.date).size().reset_index(name='count')
    st.bar_chart(count_by_date, y="count", x="datePublished",
                 color="#04adbf", use_container_width=True)




st.subheader("Parallel Category Diagram")
dfp = filtered_df[['sap_note_year', 'priority_l','priority','Priority','cvss_severity']]
#dfp['team'] = pd.factorize(dfp['sap_note_year'])[0]
fig_parallel = px.parallel_categories(
    dfp, dimensions=['sap_note_year','priority_l','priority','Priority','cvss_severity'],
    labels={'sap_note_year':'Year',
            'priority_l':'SploitScan',
            'priority':'CVE-Prioritizer',
            'Priority':'SAP',
            'cvss_severity':'cvssSeverity'},
            color=dfp['sap_note_year'],
            #range_color=year_c[1])  '#4e79a7' #5f45bf '#3b2e8c'
            color_continuous_scale=['#5f45bf','#04adbf','#ba38f2','#ff1493'])

st.plotly_chart(fig_parallel, theme=None, use_container_width=True)


with st.expander("Dataset Filtered Vulnerabilities"):
    st.subheader("Filtered Vulnerabilities")
    st.write(filtered_df)
