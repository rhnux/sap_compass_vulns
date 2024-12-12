import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit_antd_components as sac
from datetime import date, timedelta
import httpx
import re

# Caching data loading
@st.cache_data
def load_data():
    df = pd.read_csv('data/sap_cve_last_202412_all.csv')
    cwe_top_25 = pd.read_csv('data/cwe_top_25_2024.csv')
    ll_cwe_t25 = list(cwe_top_25['ID'])
    
    df['datePublished'] = pd.to_datetime(df['datePublished'], format='mixed', utc=True)
    df['dateUpdated'] = pd.to_datetime(df['dateUpdated'], format='mixed', utc=True)
    df['cwe_t25'] = df['cweId'].isin(ll_cwe_t25)
    
    df.drop_duplicates(subset=['Note#'], inplace=True)
    
    df['sap_note_year'] = df['sap_note_year'].astype('category')
    df['year'] = pd.to_datetime(df['sap_note_year'], format='%Y', utc=True)
    df['Note#'] = df['Note#'].astype('category')
    df['priority'] = df['priority'].astype('category')
    df['priority_l'] = df['priority_l'].astype('category')
    df['Priority'] = df['Priority'].astype('category')
    df['cvss_severity'] = df['cvss_severity'].astype('category')
    df['kev'].fillna(False, inplace=True)
    df['cveInfo'] = df['cve_id'].apply(lambda x: f'https://www.cvedetails.com/cve/{x}')
    df['cveSAP'] = df['cve_id'].apply(lambda x: f'https://www.cve.org/CVERecord?id={x}')
    df['epss'] = (df['epss'] * 100).astype('float').round(2)
    
    return df

# Caching EPSS data fetching
@st.cache_data
def fetch_epss_data(cve):
    r = httpx.get(f'https://api.first.org/data/v1/epss?cve={cve}&scope=time-series')
    epss_ts = r.json()['data'][0]
    return [float(l['epss'])*100 for l in reversed(epss_ts['time-series'])]

# Select A+|1+ CVEs & Get EPSS data of TOP Priorities CVEs
@st.cache_data
def sap_cve_top_priority(xdf):
    sap_cve_top = xdf[(xdf['priority_l'].isin(['A+', 'B'])) | (xdf['priority'] == 'Priority 1+')]
    col_epss_hist = [fetch_epss_data(row['cve_id']) for _, row in sap_cve_top.iterrows()]
    return sap_cve_top, col_epss_hist

# Function to calculate EPSS trend
def calculate_epss_trend(epss_values, up_threshold=1.01, down_threshold=0.99):
    if len(epss_values) < 2:
        return 'stable'
    first_val, last_val = epss_values[0], epss_values[-1]
    if last_val > first_val * up_threshold:
        return 'up'
    elif last_val < first_val * down_threshold:
        return 'down'
    return 'stable'

# Function to calculate individual scores
def calculate_scores(row, kev_weight=3, cvss_multiplier=2, epss_up_multiplier=3, epss_stable_multiplier=2, cwe_weight=1.5):
    kev_score = kev_weight if row['kev'] else 0
    cvss_score = row['cvss'] * cvss_multiplier
    epss_trend = calculate_epss_trend(row['epss_l_30'])
    epss_avg = np.mean(row['epss_l_30']) if len(row['epss_l_30']) > 0 else 0
    epss_score = epss_avg * (epss_up_multiplier if epss_trend == 'up' else epss_stable_multiplier if epss_trend == 'stable' else 1)
    cwe_score = cwe_weight if row['cwe_t25'] else 0
    priority_score = 1
    
    return {
        'epss_trend': epss_trend,
        'epss_avg': epss_avg,
        'kev_score': kev_score,
        'cvss_score': cvss_score,
        'epss_score': epss_score,
        'cwe_score': cwe_score,
        'priority_score': priority_score,
        'composite_score': kev_score + cvss_score + epss_score + cwe_score + priority_score
    }

# Main function to process the DataFrame and rank vulnerabilities
@st.cache_data
def process_vulnerability_data(ydf, kev_weight=3, cvss_multiplier=2, epss_up_multiplier=3, epss_stable_multiplier=2, cwe_weight=1.5):
    score_columns = ydf.apply(
        lambda row: calculate_scores(row, kev_weight, cvss_multiplier, epss_up_multiplier, epss_stable_multiplier, cwe_weight), 
        axis=1, 
        result_type='expand'
    )
    
    ydf = pd.concat([ydf, score_columns], axis=1)
    return ydf.sort_values(by='composite_score', ascending=False)

# Streamlit app setup
st.set_page_config(
    page_title="SAP Compass Vulns",
    page_icon="assets/favicon.ico",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Load data
df = load_data()
# UI Components
st.logo("assets/logo.png", link="https://dub.sh/dso-days", icon_image="assets/logo.png")

sac.divider(label='SAP Compass Vulns', icon=sac.BsIcon(name='compass', size=25), color='#04adbf')

# Sidebar
st.sidebar.markdown('<div style="text-align: center;">Last updated 10-12-2024</div>', unsafe_allow_html=True)
sentiment_mapping = [":red[:material/thumb_down:]", ":green[:material/thumb_up:]"]
st.sidebar.markdown('<div style="text-align: justify;"></br></br>How do you like this app?</div>', unsafe_allow_html=True)
selected = st.sidebar.feedback("thumbs")
if selected is not None:
    st.sidebar.markdown(f'### You selected: {sentiment_mapping[selected]}')
st.sidebar.caption("Info and Details")
st.sidebar.caption(":blue[:material/neurology:] [SAP Vulnerabilities - CVE-IDs](https://dso-days-siteblog.vercel.app/blog/sap-cve-ids/)")

# Main content
st.title("SAP Compass Priority Vulnerabilities")

st.info('New 2024 CWE Top 25 for Rethink process', icon=":material/emergency_heat:")

with st.expander("Vulnerability Summary 2024", expanded=False, icon=":material/brand_awareness:"):
    st.header(f"From January 2021 to date, :blue[{df.shape[0]} SAP Notes] related to :orange[{len(df['cve_id'].unique())} CVE-IDs] are reported.")

    count_by_month = df.groupby([df['datePublished'].dt.to_period('M'), 'Priority']).size().reset_index(name='v')
    count_by_month['cumulative_v'] = count_by_month.groupby('Priority')['v'].cumsum()
    total_by_priority = count_by_month.groupby('Priority')['v'].sum().reset_index()

    with st.container():
        metrics = st.columns(4, gap='large')
        for priority, color in zip(['Hot News', 'High', 'Medium', 'Low'], ['violet', 'red', 'orange', 'blue']):
            value = total_by_priority.loc[total_by_priority['Priority'] == priority, 'v'].values[0]
            metrics[['Hot News', 'High', 'Medium', 'Low'].index(priority)].metric(f":{color}[{priority}]", value=value)

st.divider()

# Filters
col1s, col2s, col3s = st.columns([2,2,1], vertical_alignment='center')
with col1s:
    priority_filter = st.multiselect("Select SAP Priority Level", df['Priority'].unique(), default=df['Priority'].unique())
with col2s:
    year_filter = st.multiselect("Select SAP Note Year", df['sap_note_year'].unique(), default=df['sap_note_year'].unique())
with col3s:
    on = st.toggle(":blue[:material/neurology:] Rethink Priorities", key="on_rethink", help="Run process Rethink Priority Score")

filtered_df = df[df['Priority'].isin(priority_filter) & df['sap_note_year'].isin(year_filter)]

st.divider()

if on:
    with st.container():
        epss_h = sap_cve_top_priority(filtered_df)
        sap_cve_top25 = epss_h[0].copy()
        sap_cve_top25['epss_l_30'] = epss_h[1]
        sap_cve_top25 = process_vulnerability_data(sap_cve_top25)
        top = sap_cve_top25.shape[0]
        top_vs = sap_cve_top25.drop_duplicates(subset=['cve_id'])
        kev = top_vs[top_vs['kev']]
        cweT25 = top_vs[top_vs['cwe_t25']]
        
        tab1, tab2 = st.tabs(["Vunls Top Priority", "CVE Info"])
        with tab1:
            st.header(f":violet[Top {top}] Priority Vulnerabilities of :blue[{filtered_df.shape[0]}] selected SAP Notes")
            st.header(f':orange[{top_vs.shape[0]}] Unique CVE-IDs & :red[{kev.shape[0]} on KEV]')
            
            st.dataframe(
                sap_cve_top25[['Note#','cve_id','Priority','priority_l','priority','cvss','kev','epss','cweId','cwe_t25','composite_score']],
                column_config = {
                    "composite_score": st.column_config.NumberColumn("Score", help="Rethink Priority Score.", format="%.3f"),
                },
                hide_index=True,
            )
            
            # CVSS Distribution
            chart_data = sap_cve_top25[["cvss","epss","cve_id","Note#"]]
            fig = px.scatter(chart_data, x='cvss', y='epss', color_discrete_sequence=["#ff1493"],
                             labels={"cvss": "CVSS score", "epss": "EPSS %"})
            fig.add_hline(y=25, line_color='grey', line_dash='dash', 
                          annotation_text="Threshold EPSS: 25%", annotation_position="bottom right")
            fig.add_vline(x=6.0, line_color='grey', line_dash='dash', 
                          annotation_text="Threshold CVSS: 6.0", annotation_position="top right")
            fig.update_layout(xaxis_title="CVSS Score", yaxis_title="EPSS %")
            st.subheader("EPSS Score Distribution")
            st.plotly_chart(fig, use_container_width=True)

        with tab2:
            st.subheader('CVE Details by Rethink Priority Score')
            st.header(f':orange[{top_vs.shape[0]} CVE-IDs] | :red[{kev.shape[0]} on KEV] | :blue[{cweT25.shape[0]} on CWE Top 25]')
            st.dataframe(
                top_vs[['cveInfo','Priority','priority_l','priority','cweId','epss','cvss',
                        'cvss_severity','kev','sap_note_year','cwe_t25','epss_l_30','epss_trend',
                        'epss_avg','kev_score','cvss_score','epss_score','cwe_score','priority_score',
                        'composite_score','vendor','product','descriptions']],
                column_config={
                    "cveInfo": st.column_config.LinkColumn("cveInfo", help="CVE Details", max_chars=50, display_text=r"(CVE-....-\d+)"),
                    "epss_l_30": st.column_config.AreaChartColumn("EPSS (Last 30 days)", y_min=0, y_max=100),
                    "composite_score": st.column_config.NumberColumn("Score", help="Rethink Priority Score.", format="%.2f"),
                },
                hide_index=True
            )
            
            st.subheader('Treemap Score Priorities')
            fig_tm = px.treemap(top_vs, path=[px.Constant("CVE Details"), 'Priority', 'sap_note_year', 'priority', 'priority_l'], values='composite_score')
            fig_tm.update_traces(marker_colorscale=['#5eadf2','#3b2e8c','#04adbf','#ba38f2','#ff1493'])                                        
            fig_tm.update_layout(margin = dict(t=50, l=25, r=25, b=25))
            st.plotly_chart(fig_tm, theme=None, use_container_width=True)    
    st.divider()

st.header(f":violet[{filtered_df.shape[0]}] Selected Vulnerabilities")
st.dataframe(
    filtered_df[['Note#', 'cveInfo', 'cveSAP', 'Priority', 'priority_l', 'priority', 'epss', 'cvss', 'product_l']],
    column_config={
        "epss": st.column_config.NumberColumn("EPSS %", help="Probabilidad para explotar la vulnerabilidad."),
        "cveInfo": st.column_config.LinkColumn("cveInfo", help="CVE Details", max_chars=50, display_text=r"(CVE-....-\d+)"),
        "cveSAP": st.column_config.LinkColumn("cveSAP", help="CVE SAP Details", max_chars=50, display_text=r"(CVE-....-\d+)"),
    },
    hide_index=True
)

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
    st.subheader("Vulns Year Published")
    filtered_df['yp'] = filtered_df['datePublished'].values.astype('datetime64[Y]')
    count_by_date = filtered_df.groupby(filtered_df['yp'].dt.date).size().reset_index(name='count')
    print(count_by_date)
    st.bar_chart(count_by_date, y="count", x="yp", x_label="CVE Year Published",
                 color="#ba38f2", use_container_width=True)




st.subheader("Parallel Category Diagram")
dfp = filtered_df[['sap_note_year','year','priority_l','priority','Priority','cvss_severity']]
#dfp['team'] = pd.factorize(dfp['year'])[0].astype('int')
fig_parallel = px.parallel_categories(
    dfp, dimensions=['sap_note_year','Priority','cvss_severity','priority_l','priority'],
    labels={'sap_note_year':'Year',
            'priority_l':'SploitScan',
            'priority':'CVE-Prioritizer',
            'Priority':'SAP',
            'cvss_severity':'cvssSeverity'},
            color=dfp['sap_note_year'],
            #range_color=year_c[1])  '#4e79a7' #5f45bf '#3b2e8c' #5eadf2
            color_continuous_scale=['#5eadf2','#3b2e8c','#ba38f2','#ff1493'],
            color_continuous_midpoint=2022)
st.plotly_chart(fig_parallel, theme=None, use_container_width=True)



    
st.divider() 

with st.expander("Dataset SAP Vulnerabilities"):
    st.subheader("Dataset Raw")
    st.write(df)
