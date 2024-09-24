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
on = st.sidebar.toggle("Priority Top 20")

if on:
    with st.container():
        epss_h = sap_cve_top_priority()
        sap_cve_top25 = epss_h[0].copy()
        sap_cve_top25 = sap_cve_top25.assign(epss_l_30 = epss_h[1])
        st.title("Top 20 SAP Priority Vulnerabilities")
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
                            color="#ff1493",
                            use_container_width=True)

        with col2t25:
            # Potentially Display another chart (like by date)
            st.subheader("Vulns Date Updated")
            sap_cve_top25['dateUpdated'] = pd.to_datetime(sap_cve_top25['dateUpdated'])
            count_by_date = df.groupby(df['dateUpdated'].dt.date).size().reset_index(name='count')
            st.bar_chart(count_by_date, y="count", x="dateUpdated",
                        color="#04adbf", use_container_width=True)

st.title("SAP Compass Priority Vulnerabilities")
# Filter DataFrame based on selection
#filtered_df = df[df['priority_l'].isin(priority_filter)]
filtered_df = df[df['Priority'].isin(priority_filter)]

vulns = filtered_df.shape[0]

st.subheader(f"Filtered Vulnerabilities | 🪲 :violet[{vulns}]")
#st.write(filtered_df[['Note#', 'cve_id', 'description']])
st.dataframe(filtered_df[['Note#', 'cve_id', 'priority', 'priority_l', 'epss', 'cvss', 'kev', 'dateUpdated','product_l']],
             column_config={
                 "epss": st.column_config.NumberColumn(
                     "EPSS",
                     min_value=0,
                     max_value=100,
                     step=1,
                     format="%.2f",
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
