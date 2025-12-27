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
def load_data(use_history_file):
    if use_history_file:
        df = pd.read_csv('data/sap_cve_old_all.csv')
    else:
        df = pd.read_csv('data/sap_cve_2025_aws.csv')
    df.sort_values(by='cve_id', inplace=True)
    cwe_top_25 = pd.read_csv('data/cwe_top_25_2024.csv')
    ll_cwe_t25 = list(cwe_top_25['ID'])
    
    df['datePublished'] = pd.to_datetime(df['datePublished'], format='mixed', utc=True)
    df['dateUpdated'] = pd.to_datetime(df['dateUpdated'], format='mixed', utc=True)
    df['monthName'] = df['datePublished'].dt.month_name()
    df['year'] = df['datePublished'].dt.year.astype(str)    
    #df['year'] = pd.to_datetime(df['sap_note_year'], format='%Y', utc=True)
    df['cwe_t25'] = df['cweId'].isin(ll_cwe_t25)

    
    df.drop_duplicates(subset=['Note#'], inplace=True)
    
    df['sap_note_year'] = df['sap_note_year'].astype('category')
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
    #sap_cve_top = xdf[(xdf['priority_l'].isin(['A+', 'B'])) | (xdf['priority'] == 'Priority 1+')]
    sap_cve_top = xdf[(xdf['priority_l'].isin(['A+'])) |
                       (xdf['priority'] == 'Priority 1+') |
                       (xdf['cvss'] > 7.5)]
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

# UI Components
st.logo("assets/logo.png", link="https://dub.sh/dso-days", icon_image="assets/logo.png", size='large')

sac.divider(label="<img height='96' width='96' src='https://cdn.simpleicons.org/SAP/white' /> Compass Priority Vulnerabilities", color='#ffffff')

# Load data
use_history_file = st.toggle(":blue[:material/history_edu:] History SAP CVE-IDs",
                             key="load_history", help="Load history SAP CVE-IDs")
df = load_data(use_history_file)

if use_history_file:
    ref_data_from = "2001"
else:
    ref_data_from = "2021" 


# Sidebar
st.sidebar.markdown('<div style="text-align: center;">Last updated 09-12-2025</div>', unsafe_allow_html=True)
sentiment_mapping = [":red[:material/thumb_down:]", ":green[:material/thumb_up:]"]
st.sidebar.markdown('<div style="text-align: justify;"></br></br>How do you like this app?</div>', unsafe_allow_html=True)
selected = st.sidebar.feedback("thumbs")
if selected is not None:
    st.sidebar.markdown(f'### You selected: {sentiment_mapping[selected]}')
st.sidebar.caption("Info and Details")
st.sidebar.caption(":blue[:material/neurology:] [SAP Vulnerabilities - CVE-IDs](https://dso-days-siteblog.vercel.app/blog/sap-cve-ids/)")
st.sidebar.caption(":blue[:material/neurology:] [SAP Vulnerabilities Summary 2024](https://dso-days-siteblog.vercel.app/blog/2024-sap-compass-vulns-summary/)")
st.sidebar.caption(":blue[:material/neurology:] [SAP Panorama Security Notes en 2025](https://dso-days-siteblog.vercel.app/blog/202508-sap-compass-data-review/)")   
st.sidebar.caption(":blue[:material/neurology:] [SAP Vulnerabilities Summary 2025](https://dso-days-siteblog.vercel.app/blog/2025-sap-compass-vulns-summary/)")

st.sidebar.caption(":blue[:material/south_america:] :blue-badge[AR]")

# Main content
#st.html("<img height='96' width='96' src='https://cdn.simpleicons.org/SAP/white' />")
#st.title("SAP Compass Priority Vulnerabilities")

#st.toast('New 2024 CWE Top 25 for Rethink process', icon=":material/emergency_heat:")


with st.expander(f"Vulnerability Summary {ref_data_from}-2025", expanded=True, icon=":material/explore:"):
    st.header(f"From January {ref_data_from} to date, :blue[{df.shape[0]} SAP Notes] related to :orange[{len(df['cve_id'].unique())} CVE-IDs] are reported.", anchor=False)

    count_by_month = df.groupby([df['datePublished'].dt.to_period('M'), 'Priority']).size().reset_index(name='v')
    #count_by_month['cumulative_v'] = count_by_month.groupby('Priority')['v'].cumsum()
    total_by_priority = count_by_month.groupby('Priority')['v'].sum().reset_index()

    today_utc = pd.Timestamp.now(tz='UTC')
    twelve_months_ago = today_utc - pd.DateOffset(years=1)
    last_12_months_df = df[df['datePublished'] >= twelve_months_ago]

    with st.container():
        metrics = st.columns(4, gap='large')
        priorities = ['Critical', 'High', 'Medium', 'Low']
        colors = ['violet', 'red', 'orange', 'blue']
        
        # Mapping streamlit colors to hex for plotly
        color_map = {
            'violet': '#ba38f2',
            'red': '#ff4b4b',
            'orange': '#ffa500',
            'blue': '#0080ff'
        }

        # --- Prepare data for all sparklines and deltas ---
        # Use a period range for the last 12 full months for robustness
        today_utc = pd.Timestamp.now(tz='UTC')
        end_period = today_utc.to_period('M')
        start_period = (today_utc - pd.DateOffset(months=11)).to_period('M')
        full_period_range = pd.period_range(start=start_period, end=end_period, freq='M')

        # Group all data by month and priority in one go
        all_monthly_counts = df.groupby([df['datePublished'].dt.to_period('M'), 'Priority']).size().unstack(fill_value=0)
        
        # Reindex to ensure all 12 months are present for all priorities
        all_monthly_counts = all_monthly_counts.reindex(full_period_range, fill_value=0)

        for i, (priority, color) in enumerate(zip(priorities, colors)):
            # Total value for the metric
            total_value_series = total_by_priority.loc[total_by_priority['Priority'] == priority, 'v']
            total_value = total_value_series.values[0] if not total_value_series.empty else 0

            # --- Monthly data for sparkline (last 12 months) ---
            if priority in all_monthly_counts.columns:
                monthly_counts = all_monthly_counts[priority]
            else:
                # If a priority has no vulns, create a series of zeros
                monthly_counts = pd.Series([0] * 12, index=full_period_range)

            # --- Delta calculation ---
            delta = 0
            if len(monthly_counts) >= 2:
                # Compare the last two months in the 12-month period
                delta = int(monthly_counts.iloc[-1] - monthly_counts.iloc[-2])

            with metrics[i]:
                delta_color = "inverse" if delta != 0 else "off"
                st.metric(f":{color}[{priority}]", value=total_value, delta=delta, delta_color=delta_color, help="Delta from previous month")
                
                # --- Sparkline ---
                spark_fig = go.Figure(go.Scatter(
                    y=monthly_counts.values,
                    x=monthly_counts.index.to_timestamp(), # Convert period index to timestamp for plotting
                    mode='lines',
                    fill='tozeroy',
                    line_color=color_map.get(color, color), # Use mapped color, fallback to original
                    hoverinfo='none' # Clean look
                ))
                spark_fig.update_layout(
                    height=60, # Small height for sparkline
                    margin=dict(l=0, r=0, t=5, b=0), # Tight margin
                    xaxis=dict(visible=False),
                    yaxis=dict(visible=False),
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    showlegend=False,
                )
                st.plotly_chart(spark_fig, use_container_width=True, config={'displayModeBar': False})

st.divider()

# FiltersX
# ...existing code...

col1s, col2s, col3s, col4s = st.columns([2,2,2,1], vertical_alignment='center')
with col1s:
    priority_filter = st.multiselect(
        "Select SAP Priority Level",
        df['Priority'].unique(),
        default=['Critical','High','Medium','Low']
    )
with col2s:
    year_filter = st.multiselect(
        "Select SAP Note Year",
        df['sap_note_year'].unique(),
        default=sorted(df['sap_note_year'].unique())
    )
with col3s:
    # Definir el orden correcto de los meses
    month_order = [
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'
    ]
    
    # Filtrar los meses disponibles según los años seleccionados
    months_available = (
        df[df['sap_note_year'].isin(year_filter)]['monthName']
        .dropna()
        .unique()
        .tolist()
    )
    
    # Ordenar los meses disponibles según el orden cronológico correcto
    months_available_ordered = [month for month in month_order if month in months_available]
    
    # Agregar opción "All" al inicio de la lista
    months_options = ["All"] + months_available_ordered
    
    month_filter_selection = st.multiselect(
        "Select Month",
        months_options,
        default=["All"]
    )
    
    # Procesar la selección: si "All" está seleccionado, usar todos los meses disponibles
    if "All" in month_filter_selection:
        month_filter = months_available_ordered
    else:
        month_filter = [m for m in month_filter_selection if m != "All"]
   
with col4s:
    on = st.toggle(
        ":blue[:material/neurology:] Rethink Priorities",
        key="on_rethink",
        help="Run process Rethink Priority Score"
    )

filtered_df = df[
    (df['Priority'].isin(priority_filter)) &
    (df['sap_note_year'].isin(year_filter)) &
    (df['monthName'].isin(month_filter))
]

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
            st.header(f":violet[Top {top}] Priority Vulnerabilities of :blue[{filtered_df.shape[0]}] selected SAP Notes", anchor=False)
            st.header(f':orange[{top_vs.shape[0]}] Unique CVE-IDs & :red[{kev.shape[0]} on KEV]', anchor=False)
            
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
            st.subheader("EPSS Score Distribution", anchor=False)
            st.plotly_chart(fig, use_container_width=True)

        with tab2:
            st.subheader('CVE Details by Rethink Priority Score', anchor=False)
            st.header(f':orange[{top_vs.shape[0]} CVE-IDs] | :red[{kev.shape[0]} on KEV] | :blue[{cweT25.shape[0]} on CWE Top 25]', anchor=False)
            st.dataframe(
                top_vs[['cveInfo','Priority','priority_l','priority','cweId','epss','cvss',
                        'cvss_severity','kev','sap_note_year','cwe_t25','epss_l_30','epss_trend',
                        'epss_avg','kev_score','cvss_score','epss_score','cwe_score','priority_score',
                        'composite_score','vendor','product_l','descriptions']],
                column_config={
                    "cveInfo": st.column_config.LinkColumn("cveInfo", help="CVE Details", max_chars=50, display_text=r"(CVE-....-\d+)", pinned=True),
                    "epss_l_30": st.column_config.AreaChartColumn("EPSS (Last 30 days)", y_min=0, y_max=100),
                    "composite_score": st.column_config.NumberColumn("Score", help="Rethink Priority Score.", format="%.2f"),
                },
                hide_index=True
            )
            
            st.subheader('Treemap Score Priorities', anchor=False)
            fig_tm = px.treemap(top_vs, path=[px.Constant("CVE Details"), 'Priority', 'sap_note_year', 'priority', 'priority_l'], values='composite_score')
            fig_tm.update_traces(marker_colorscale=['#5eadf2','#3b2e8c','#04adbf','#ba38f2','#ff1493'])                                        
            fig_tm.update_layout(margin = dict(t=50, l=25, r=25, b=25))
            st.plotly_chart(fig_tm, theme=None, use_container_width=True)
  
    st.divider()

st.header(f":violet[{filtered_df.shape[0]}] Selected Vulnerabilities", anchor=False)
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
    st.subheader("EPSS Score Distribution", anchor=False)
    chart_data = filtered_df[["cvss","epss","cve_id","Note#"]]
    st.scatter_chart(chart_data,
                    y="epss",
                    x="cvss",
                    x_label="CVSS Score",
                    y_label="EPSS %",
                    color="#ff1493",
                    width='stretch')

with col2:
    # Potentially Display another chart (like by date)
    st.subheader("Vulns Year Published", anchor=False)
    filtered_df['yp'] = filtered_df['datePublished'].values.astype('datetime64[Y]')
    count_by_date = filtered_df.groupby(filtered_df['yp'].dt.date).size().reset_index(name='count')
    print(count_by_date)
    st.bar_chart(count_by_date, y="count", x="yp", x_label="CVE Year Published",
                 color="#ba38f2", use_container_width=True)



# Reemplaza la sección del Parallel Category Diagram (aproximadamente líneas 280-295)Dataset SAP Vulnerabilities


st.subheader("Parallel Category Diagram", anchor=False)

# Preparar datos con categorías ordenadas
dfp = filtered_df[['sap_note_year','year','priority_l','priority','Priority','cvss_severity']].copy()

# Definir el orden específico para cada categoría
sap_priority_order = ['Critical', 'High', 'Medium', 'Low']
cvss_severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
sploitscan_order = ['A+', 'A', 'B', 'C', 'D', 'E']
cve_prioritizer_order = ['Priority 1+', 'Priority 1', 'Priority 2', 'Priority 3', 'Priority 4']

# Convertir a categorías ordenadas
dfp['Priority'] = pd.Categorical(dfp['Priority'], categories=sap_priority_order, ordered=True)
dfp['cvss_severity'] = pd.Categorical(dfp['cvss_severity'], categories=cvss_severity_order, ordered=True)
dfp['priority_l'] = pd.Categorical(dfp['priority_l'], categories=sploitscan_order, ordered=True)
dfp['priority'] = pd.Categorical(dfp['priority'], categories=cve_prioritizer_order, ordered=True)

# Ordenar el DataFrame por año y luego por las categorías
dfp = dfp.sort_values(by=['sap_note_year', 'Priority', 'cvss_severity', 'priority_l', 'priority'])

#dfp = filtered_df[['sap_note_year','year','priority_l','priority','Priority','cvss_severity']].sort_values(by='sap_note_year')
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
            color_continuous_scale=['#210d4f','#610046','#070108','#04adbf','#4e79a7',
                                    '#5f45bf','#5eadf2','#3b2e8c','#ba38f2','#ff1493','#bf00c4'],
            color_continuous_midpoint=2022)
st.plotly_chart(fig_parallel, theme=None, use_container_width=True)

st.divider()

# Vista Comparativa de Meses entre Años
with st.expander("Comparative Analysis: Vulnerabilities by Month across Years",
                 expanded=False, icon=":material/view_timeline:"):
    
    # Preparar datos para la comparación mensual
    def prepare_monthly_comparison_data(df_data):
        # Definir el orden correcto de los meses
        month_order = [
            'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'
        ]
        
        # Agrupar por año y mes
        #monthly_data = df_data.groupby(['sap_note_year', 'monthName']).size().reset_index(name='vulnerability_count')
        #st.write(monthly_data)

        monthly_data = df_data.groupby(df_data['datePublished'].dt.to_period('M')).size().reset_index(name='vulnerability_count')
        monthly_data['monthName'] = monthly_data['datePublished'].apply(lambda x: x.strftime('%B'))
        monthly_data['sap_note_year'] = monthly_data['datePublished'].apply(lambda x: x.strftime('%Y'))
        #st.write(monthly_data)

        # Crear pivot table para facilitar la visualización
        pivot_data = monthly_data.pivot(index='monthName', columns='sap_note_year', values='vulnerability_count').fillna(0)
        
        # Reordenar los meses cronológicamente
        pivot_data = pivot_data.reindex([month for month in month_order if month in pivot_data.index])
        
        return pivot_data, monthly_data
    
    pivot_data, monthly_data = prepare_monthly_comparison_data(filtered_df)

    
    # Crear tabs para diferentes visualizaciones
    tab1, tab2, tab3, tab4 = st.tabs([":material/show_chart: Line Chart",
                                ":material/bar_chart_4_bars: Bar Chart",
                                ":material/shadow_add: Summary",
                                ":material/network_intel_node: Data Model"])
    
    with tab1:
        st.subheader("Trend Analysis: Monthly Vulnerabilities by Year", anchor=False)
        
        # Convertir pivot_data para plotly
        fig_line = go.Figure()
        
        colors = ['#ff1493', '#ba38f2', '#5eadf2', '#04adbf', '#3b2e8c', '#bf00c4', '#4e79a7', '#5f45bf']
        
        for i, year in enumerate(pivot_data.columns):
            fig_line.add_trace(go.Scatter(
                x=pivot_data.index,
                y=pivot_data[year],
                mode='lines+markers',
                name=f'Year {year}',
                line=dict(color=colors[i % len(colors)], width=3),
                marker=dict(size=8)
            ))
        
        fig_line.update_layout(
            title="Monthly Vulnerability Trends Across Years",
            xaxis_title="Month",
            yaxis_title="Number of Vulnerabilities",
            hovermode='x unified',
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        
        st.plotly_chart(fig_line, use_container_width=True)
    
    with tab2:
        st.subheader("Monthly Distribution: Vulnerabilities by Year", anchor=False)
        
        # Crear gráfico de barras agrupadas
        fig_bar = px.bar(
            monthly_data, 
            x='monthName', 
            y='vulnerability_count', 
            color='sap_note_year',
            title="Monthly Vulnerability Distribution by Year",
            labels={
                'monthName': 'Month',
                'vulnerability_count': 'Number of Vulnerabilities',
                'sap_note_year': 'Year'
            },
            color_discrete_sequence=['#ff1493', '#ba38f2', '#5eadf2', '#04adbf', '#3b2e8c', '#bf00c4', '#4e79a7', '#5f45bf']
        )
        
        # Ordenar meses cronológicamente
        month_order = [
            'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'
        ]
        fig_bar.update_xaxes(categoryorder='array', categoryarray=month_order)
        fig_bar.update_layout(legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
        
        st.plotly_chart(fig_bar, use_container_width=True)
    
    with tab3:
        st.subheader("Statistical Summary", anchor=False)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Top 3 Months (Total Vulnerabilities)**")
            monthly_totals = pivot_data.sum(axis=1).sort_values(ascending=False).head(3)
            for month, total in monthly_totals.items():
                st.metric(month, int(total), delta=int(total) - int(pivot_data.sum(axis=1).min()),
                            delta_color="inverse" if int(total) < int(pivot_data.sum(axis=1).mean()) else "normal", border=True,
                            help="Total vulnerabilities reported in this month across all selected years.")
        
        with col2:
            st.write("**Year with Most Vulnerabilities**")
            yearly_totals = pivot_data.sum(axis=0).sort_values(ascending=False)
            for year, total in yearly_totals.head(3).items():
                st.metric(f"Year {year}", int(total), delta=int(total) - int(yearly_totals.min()),
                          delta_color="inverse" if int(total) < int(yearly_totals.mean()) else "normal", border=True,
                          help="Total vulnerabilities reported in this year across all selected months.")
        
        st.write("**Detailed Monthly Statistics by Year**")
        st.dataframe(
            pivot_data.round(0).astype(int),
            width='stretch'
        )
        
        # Estadísticas adicionales
        st.write("**Monthly Averages and Peaks**")
        stats_df = pd.DataFrame({
            'Month': pivot_data.index,
            'Average': pivot_data.mean(axis=1).round(2),
            'Peak Year': pivot_data.idxmax(axis=1),
            'Peak Value': pivot_data.max(axis=1),
            'Total': pivot_data.sum(axis=1)
        })
        st.dataframe(stats_df, hide_index=True, width='stretch')

    with tab4:
            st.subheader(':primary[Data Flow] Diagram', anchor=False)
            st.image('assets/data_flow_rich.svg', width='stretch')

# Continúa con el resto del código original...# ...existing code...

with st.expander("Dataset SAP Vulnerabilities"):
    st.subheader("Dataset Raw", anchor = False)
    st.write(df)
