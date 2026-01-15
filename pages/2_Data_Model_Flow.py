import streamlit as st
import streamlit_antd_components as sac

# UI Components
st.logo("static/logo.png", link="https://dub.sh/dso-days", icon_image="static/logo.png", size='large')

#sac.divider(label="<img height='96' width='96' src='https://cdn.simpleicons.org/SAP/white' /> Compass Priority Vulnerabilities", color='#ffffff')


st.title(':primary[:material/network_intel_node:] Data Flow Diagram', anchor=False)

with st.container():
    st.image('static/data_flow_rich.svg', width='stretch')
