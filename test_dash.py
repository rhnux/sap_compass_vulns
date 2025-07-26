# sap_vulnerability_dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# Configure page
st.set_page_config(
    page_title="SAP Vulnerability Intelligence Dashboard",
    page_icon="🔒",
    layout="wide"
)

# Load data
@st.cache_data
def load_data():
    df = pd.read_csv("data/sap_cve_2025_aws.csv", parse_dates=['dateUpdated', 'datePublished'])
    # Extract month-year from dateUpdated
    df['datePublished'] = pd.to_datetime(df['datePublished'], format='mixed', utc=True)
    df['dateUpdated'] = pd.to_datetime(df['dateUpdated'], format='mixed', utc=True)
    df['update_month'] = df['dateUpdated'].dt.to_period('M').astype(str)
    df['update_quarter'] = df['dateUpdated'].dt.to_period('Q').astype(str)
    return df

df = load_data()

# Sidebar filters
st.sidebar.header("Filters")
selected_severity = st.sidebar.multiselect(
    "CVSS Severity", 
    options=df['cvss_severity'].unique(),
    default=df['cvss_severity'].unique()
)

selected_priority = st.sidebar.multiselect(
    "Priority Level", 
    options=df['priority_l'].unique(),
    default=df['priority_l'].unique()
)

selected_products = st.sidebar.multiselect(
    "Products", 
    options=df['product_l'].unique(),
    default=[]
)

date_range = st.sidebar.date_input(
    "Update Date Range",
    value=[df['dateUpdated'].min(), df['dateUpdated'].max()]
)

# Apply filters
filtered_df = df[
    (df['cvss_severity'].isin(selected_severity)) &
    (df['priority_l'].isin(selected_priority)) &
    (df['dateUpdated'].between(df['dateUpdated'].min(), df['dateUpdated'].max()))
]

if selected_products:
    filtered_df = filtered_df[filtered_df['product_l'].isin(selected_products)]

# Dashboard title
st.title("🔒 SAP Security Vulnerability Dashboard")
st.markdown("""
**Analysis period:** March 2024 - July 2025  
**Data source:** SAP Security Notes Vulnerability Data  
*Last updated: August 2025*
""")
st.divider()

# Key metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Vulnerabilities", len(filtered_df))
col2.metric("Critical Vulnerabilities", 
            len(filtered_df[filtered_df['cvss_severity'] == 'CRITICAL']))
col3.metric("Priority 2 Vulnerabilities", 
            len(filtered_df[filtered_df['priority_l'] == 'Priority 2']))
col4.metric("Avg Days to Update", 
            f"{(filtered_df['dateUpdated'] - filtered_df['datePublished']).dt.days.mean():.1f} days")

# Section 1: Temporal Analysis
st.header("📅 Temporal Vulnerability Trends")

col1, col2 = st.columns(2)

# Monthly trend
with col1:
    monthly_counts = filtered_df.groupby('update_month').size().reset_index(name='count')
    fig = px.bar(
        monthly_counts, 
        x='update_month', 
        y='count',
        title="Vulnerability Updates by Month",
        labels={'update_month': 'Month', 'count': 'Vulnerability Count'},
        color_discrete_sequence=['#1f77b4']
    )
    fig.update_layout(xaxis_tickangle=-45)
    st.plotly_chart(fig, use_container_width=True)

# Severity over time
with col2:
    severity_over_time = filtered_df.groupby(['update_month', 'cvss_severity']).size().reset_index(name='count')
    fig = px.area(
        severity_over_time,
        x='update_month',
        y='count',
        color='cvss_severity',
        title="Severity Distribution Over Time",
        labels={'update_month': 'Month', 'count': 'Vulnerability Count'},
        color_discrete_map={
            'CRITICAL': '#d62728',
            'HIGH': '#ff7f0e',
            'MEDIUM': '#f7e11a',
            'LOW': '#2ca02c'
        }
    )
    fig.update_layout(xaxis_tickangle=-45)
    st.plotly_chart(fig, use_container_width=True)

# Section 2: Severity and Priority Analysis
st.header("⚠️ Severity and Priority Analysis")

col1, col2 = st.columns(2)

# Severity distribution
with col1:
    severity_counts = filtered_df['cvss_severity'].value_counts().reset_index()
    fig = px.pie(
        severity_counts,
        names='cvss_severity',
        values='count',
        title="CVSS Severity Distribution",
        hole=0.3,
        color='cvss_severity',
        color_discrete_map={
            'CRITICAL': '#d62728',
            'HIGH': '#ff7f0e',
            'MEDIUM': '#f7e11a',
            'LOW': '#2ca02c'
        }
    )
    st.plotly_chart(fig, use_container_width=True)

# Priority vs Severity
with col2:
    priority_severity = pd.crosstab(filtered_df['priority_l'], filtered_df['cvss_severity'])
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(
        priority_severity, 
        annot=True, 
        fmt='d', 
        cmap='YlOrRd', 
        ax=ax,
        cbar=False
    )
    ax.set_title("Priority Level vs Severity")
    ax.set_xlabel("CVSS Severity")
    ax.set_ylabel("Priority Level")
    st.pyplot(fig)

# Section 3: Product and Vulnerability Analysis
st.header("📦 Product and Vulnerability Analysis")

col1, col2 = st.columns(2)

# Top vulnerable products
with col1:
    top_products = filtered_df['product_l'].value_counts().head(10).reset_index()
    fig = px.bar(
        top_products,
        x='count',
        y='product_l',
        orientation='h',
        title="Top 10 Vulnerable Products",
        labels={'product_l': 'Product', 'count': 'Vulnerability Count'},
        color='count',
        color_continuous_scale='OrRd'
    )
    st.plotly_chart(fig, use_container_width=True)

# Vulnerability types
with col2:
    cwe_counts = filtered_df['cweId'].value_counts().head(10).reset_index()
    fig = px.bar(
        cwe_counts,
        x='cweId',
        y='count',
        title="Top 10 Vulnerability Types (CWE)",
        labels={'cweId': 'CWE ID', 'count': 'Vulnerability Count'},
        text='count',
        color='count',
        color_continuous_scale='YlOrRd'
    )
    fig.update_traces(textposition='outside')
    st.plotly_chart(fig, use_container_width=True)

# Section 4: Detailed View and Recommendations
st.header("🔍 Vulnerability Details and Recommendations")

# Top critical vulnerabilities
st.subheader("Top Critical Vulnerabilities")
critical_df = filtered_df[filtered_df['cvss_severity'] == 'CRITICAL'].sort_values(
    'dateUpdated', ascending=False
).head(5)

st.dataframe(
    critical_df[[
        'cve_id', 'dateUpdated', 'product_l', 'cvss_severity', 'priority_l', 'descriptions'
    ]],
    column_config={
        "cve_id": "CVE ID",
        "dateUpdated": "Last Updated",
        "product_l": "Product",
        "cvss_severity": "Severity",
        "priority_l": "Priority",
        "descriptions": "Description"
    },
    hide_index=True,
    use_container_width=True
)

# Recommendations
st.subheader("Security Recommendations")
st.markdown("""
1. **February-July 2025 Focus**: Prioritize patching during high-risk months
2. **SAP NetWeaver**: Implement enhanced authorization checks
3. **SAP S/4HANA**: Audit code injection vulnerabilities
4. **EPSS Monitoring**: Track vulnerabilities with EPSS > 0.002
5. **Critical Systems**: Patch within 7 days for critical vulnerabilities
""")

# Data table
st.subheader("Full Vulnerability Data")
st.dataframe(
    filtered_df[[
        'cve_id', 'dateUpdated', 'product_l', 'cvss_severity', 
        'priority_l', 'cvss', 'epss_l', 'descriptions'
    ]],
    column_config={
        "cve_id": "CVE ID",
        "dateUpdated": "Last Updated",
        "product_l": "Product",
        "cvss_severity": "Severity",
        "priority_l": "Priority",
        "cvss": "CVSS Score",
        "epss_l": "EPSS Score",
        "descriptions": "Description"
    },
    hide_index=True,
    use_container_width=True
)

# Footer
st.divider()
st.caption("SAP Vulnerability Intelligence Dashboard | Data Source: SAP Security Notes")