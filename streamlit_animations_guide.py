"""
DASHBOARD DE VULNERABILIDADES CON ANIMACIONES EN STREAMLIT
Replica el estilo y animaciones de ProjectDiscovery Cloud Platform

Instalación requerida:
pip install streamlit plotly pandas numpy
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import time
from datetime import datetime, timedelta

# ============================================================================
# CONFIGURACIÓN INICIAL
# ============================================================================

st.set_page_config(
    page_title="Vulnerability Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado para animaciones
st.markdown("""
<style>
    /* Animación de fade-in */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .animated-card {
        animation: fadeIn 0.6s ease-out;
    }
    
    /* Animación de pulso */
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }
    
    .pulse-dot {
        animation: pulse 2s ease-in-out infinite;
    }
    
    /* Gradiente animado */
    @keyframes gradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    .gradient-bg {
        background: linear-gradient(-45deg, #667eea, #764ba2, #f093fb, #4facfe);
        background-size: 400% 400%;
        animation: gradient 15s ease infinite;
    }
    
    /* Shimmer effect */
    @keyframes shimmer {
        0% { background-position: -1000px 0; }
        100% { background-position: 1000px 0; }
    }
    
    .shimmer {
        background: linear-gradient(
            to right,
            #f6f7f8 0%,
            #edeef1 20%,
            #f6f7f8 40%,
            #f6f7f8 100%
        );
        background-size: 1000px 100%;
        animation: shimmer 2s linear infinite;
    }
    
    /* Estilos para métricas */
    .stMetric {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 0.5rem;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.title("🛡️ Vulnerability Dashboard")
    st.markdown("---")
    
    technique = st.selectbox(
        "Selecciona una técnica de animación:",
        [
            "1️⃣ Animación Progresiva",
            "2️⃣ Transiciones con Frames",
            "3️⃣ Tiempo Real (Auto-refresh)",
            "4️⃣ Indicadores Animados",
            "5️⃣ Heatmap Interactivo",
            "6️⃣ Bubble Chart",
            "7️⃣ Loading States",
            "8️⃣ Dashboard Completo"
        ]
    )
    
    st.markdown("---")
    st.markdown("""
    ### 📚 Técnicas Implementadas
    
    - **Plotly**: Gráficos interactivos
    - **st.session_state**: Estado persistente
    - **st.empty()**: Actualización dinámica
    - **time.sleep()**: Animaciones progresivas
    - **CSS personalizado**: Efectos visuales
    """)

# ============================================================================
# TÉCNICA 1: ANIMACIÓN PROGRESIVA DE DATOS
# ============================================================================

def technique_1_progressive_animation():
    st.title("📈 Técnica 1: Animación Progresiva de Datos")
    st.markdown("Esta técnica simula el efecto de 'dibujar' el gráfico progresivamente, como en React/Recharts")
    
    # Datos completos
    dates = pd.date_range(start='2024-01-01', end='2024-12-05', freq='W')
    full_data = pd.DataFrame({
        'date': dates,
        'total': np.cumsum(np.random.randint(5, 15, len(dates))),
        'critical': np.cumsum(np.random.randint(1, 4, len(dates))),
        'high': np.cumsum(np.random.randint(2, 6, len(dates)))
    })
    
    # Controles
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        animate = st.checkbox("▶️ Activar Animación", value=False)
    with col2:
        speed = st.slider("Velocidad (ms)", 50, 500, 100)
    with col3:
        if st.button("🔄 Reiniciar"):
            if 'progress_index' in st.session_state:
                del st.session_state.progress_index
            st.rerun()
    
    # Inicializar índice
    if 'progress_index' not in st.session_state:
        st.session_state.progress_index = 0
    
    # Placeholder para el gráfico
    chart_placeholder = st.empty()
    progress_placeholder = st.empty()
    
    if animate and st.session_state.progress_index < len(full_data):
        # Datos hasta el índice actual
        current_data = full_data.iloc[:st.session_state.progress_index + 1]
        
        # Crear gráfico
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=current_data['date'],
            y=current_data['total'],
            mode='lines',
            name='Total',
            line=dict(color='#3b82f6', width=3),
            fill='tozeroy',
            fillcolor='rgba(59, 130, 246, 0.2)'
        ))
        
        fig.add_trace(go.Scatter(
            x=current_data['date'],
            y=current_data['critical'],
            mode='lines',
            name='Critical',
            line=dict(color='#ef4444', width=2)
        ))
        
        fig.add_trace(go.Scatter(
            x=current_data['date'],
            y=current_data['high'],
            mode='lines',
            name='High',
            line=dict(color='#f97316', width=2)
        ))
        
        fig.update_layout(
            title="Vulnerability Exposure Timeline",
            xaxis_title="Date",
            yaxis_title="Count",
            height=450,
            template="plotly_dark",
            hovermode='x unified'
        )
        
        chart_placeholder.plotly_chart(fig, use_container_width=True)
        
        # Mostrar progreso
        progress = (st.session_state.progress_index + 1) / len(full_data)
        progress_placeholder.progress(progress, text=f"Progreso: {int(progress * 100)}%")
        
        # Incrementar índice
        st.session_state.progress_index += 1
        
        # Pausa y rerun
        time.sleep(speed / 1000)
        st.rerun()
    
    elif st.session_state.progress_index >= len(full_data):
        # Mostrar completo
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=full_data['date'],
            y=full_data['total'],
            mode='lines',
            name='Total',
            line=dict(color='#3b82f6', width=3),
            fill='tozeroy',
            fillcolor='rgba(59, 130, 246, 0.2)'
        ))
        
        fig.add_trace(go.Scatter(
            x=full_data['date'],
            y=full_data['critical'],
            mode='lines',
            name='Critical',
            line=dict(color='#ef4444', width=2)
        ))
        
        fig.update_layout(
            title="Vulnerability Exposure Timeline - COMPLETO",
            height=450,
            template="plotly_dark"
        )
        
        chart_placeholder.plotly_chart(fig, use_container_width=True)
        progress_placeholder.success("✅ Animación completada")
    
    else:
        # Mostrar estático
        fig = px.line(full_data, x='date', y=['total', 'critical', 'high'],
                     title="Vulnerability Exposure Timeline (Estático)")
        fig.update_layout(height=450, template="plotly_dark")
        chart_placeholder.plotly_chart(fig, use_container_width=True)

# ============================================================================
# TÉCNICA 2: TRANSICIONES CON FRAMES
# ============================================================================

def technique_2_frames():
    st.title("📊 Técnica 2: Transiciones con Frames de Plotly")
    st.markdown("Usa frames de Plotly para crear animaciones suaves entre estados")
    
    # Datos
    technologies = ['Kubernetes', 'Docker', 'Nginx', 'Apache', 'Redis']
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
    
    frames_data = []
    for month in months:
        frame_data = pd.DataFrame({
            'technology': technologies,
            'vulnerabilities': np.random.randint(10, 50, len(technologies)),
            'month': month
        })
        frames_data.append(frame_data)
    
    # Crear figura con frames
    fig = go.Figure(
        data=[go.Bar(
            x=frames_data[0]['technology'],
            y=frames_data[0]['vulnerabilities'],
            marker=dict(
                color=frames_data[0]['vulnerabilities'],
                colorscale='Reds',
                showscale=True
            ),
            text=frames_data[0]['vulnerabilities'],
            textposition='auto'
        )],
        layout=go.Layout(
            title=f"Vulnerabilities by Technology - {months[0]}",
            xaxis_title="Technology",
            yaxis_title="Vulnerabilities",
            yaxis_range=[0, 60],
            height=500,
            template="plotly_dark"
        )
    )
    
    # Agregar frames
    frames = []
    for i, frame_df in enumerate(frames_data):
        frames.append(go.Frame(
            data=[go.Bar(
                x=frame_df['technology'],
                y=frame_df['vulnerabilities'],
                marker=dict(
                    color=frame_df['vulnerabilities'],
                    colorscale='Reds'
                ),
                text=frame_df['vulnerabilities'],
                textposition='auto'
            )],
            name=months[i]
        ))
    
    fig.frames = frames
    
    # Botones de animación
    fig.update_layout(
        updatemenus=[dict(
            type="buttons",
            buttons=[
                dict(label="▶️ Play",
                     method="animate",
                     args=[None, {"frame": {"duration": 500}, "fromcurrent": True}]),
                dict(label="⏸️ Pause",
                     method="animate",
                     args=[[None], {"frame": {"duration": 0}, "mode": "immediate"}])
            ]
        )]
    )
    
    st.plotly_chart(fig, use_container_width=True)
    st.info("💡 Usa el botón Play para ver la animación automática")

# ============================================================================
# TÉCNICA 3: TIEMPO REAL
# ============================================================================

def technique_3_realtime():
    st.title("⚡ Técnica 3: Actualización en Tiempo Real")
    st.markdown("Simula un dashboard de monitoreo en vivo con auto-refresh")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        auto_refresh = st.checkbox("🔄 Auto-refresh (cada 2 seg)", value=False)
    with col2:
        if st.button("🔃 Actualizar"):
            st.rerun()
    
    # Inicializar datos
    if 'rt_data' not in st.session_state:
        st.session_state.rt_data = []
    
    # Nuevo punto
    timestamp = datetime.now()
    new_point = {
        'time': timestamp.strftime('%H:%M:%S'),
        'vulnerabilities': np.random.randint(80, 120),
        'critical': np.random.randint(15, 30)
    }
    
    st.session_state.rt_data.append(new_point)
    if len(st.session_state.rt_data) > 20:
        st.session_state.rt_data.pop(0)
    
    df = pd.DataFrame(st.session_state.rt_data)
    
    # Métricas
    col1, col2, col3 = st.columns(3)
    with col1:
        delta = new_point['vulnerabilities'] - st.session_state.rt_data[-2]['vulnerabilities'] if len(st.session_state.rt_data) > 1 else 0
        st.metric("Total Vulnerabilities", new_point['vulnerabilities'], delta)
    with col2:
        delta_crit = new_point['critical'] - st.session_state.rt_data[-2]['critical'] if len(st.session_state.rt_data) > 1 else 0
        st.metric("Critical", new_point['critical'], delta_crit, delta_color="inverse")
    with col3:
        st.metric("Last Update", timestamp.strftime('%H:%M:%S'))
    
    # Gráfico
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['time'], y=df['vulnerabilities'],
        mode='lines+markers',
        name='Total',
        line=dict(color='#3b82f6', width=3)
    ))
    fig.add_trace(go.Scatter(
        x=df['time'], y=df['critical'],
        mode='lines+markers',
        name='Critical',
        line=dict(color='#ef4444', width=2)
    ))
    
    fig.update_layout(
        title="Real-Time Monitoring",
        height=400,
        template="plotly_dark",
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    if auto_refresh:
        time.sleep(2)
        st.rerun()

# ============================================================================
# TÉCNICA 4: INDICADORES ANIMADOS
# ============================================================================

def technique_4_gauges():
    st.title("🎯 Técnica 4: Indicadores Animados (Gauges)")
    st.markdown("Medidores visuales con transiciones suaves")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        score = np.random.randint(65, 95)
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            title={'text': "Security Score"},
            delta={'reference': 80},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "#fee2e2"},
                    {'range': [50, 75], 'color': "#fef3c7"},
                    {'range': [75, 100], 'color': "#d1fae5"}
                ],
                'threshold': {'line': {'color': "red", 'width': 4}, 'value': 90}
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        exposure = np.random.randint(20, 80)
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=exposure,
            title={'text': "Exposure Level"},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#ef4444"},
                'steps': [
                    {'range': [0, 30], 'color': "#22c55e"},
                    {'range': [30, 70], 'color': "#eab308"},
                    {'range': [70, 100], 'color': "#dc2626"}
                ]
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col3:
        progress = np.random.randint(40, 90)
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=progress,
            title={'text': "Remediation"},
            delta={'reference': 70},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#8b5cf6"},
                'steps': [{'range': [0, 100], 'color': '#e9d5ff'}]
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)

# ============================================================================
# TÉCNICA 5: HEATMAP
# ============================================================================

def technique_5_heatmap():
    st.title("🔥 Técnica 5: Heatmap Interactivo")
    st.markdown("Visualización de detecciones por día y hora")
    
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    hours = list(range(24))
    z_data = np.random.randint(0, 20, size=(len(days), len(hours)))
    
    fig = go.Figure(data=go.Heatmap(
        z=z_data,
        x=hours,
        y=days,
        colorscale='Reds',
        text=z_data,
        texttemplate='%{text}',
        textfont={"size": 10}
    ))
    
    fig.update_layout(
        title="Vulnerability Detections by Day & Hour",
        xaxis_title="Hour",
        yaxis_title="Day",
        height=400,
        template="plotly_dark"
    )
    
    st.plotly_chart(fig, use_container_width=True)

# ============================================================================
# TÉCNICA 6: BUBBLE CHART
# ============================================================================

def technique_6_bubble():
    st.title("💫 Técnica 6: Bubble Chart Animado")
    st.markdown("Relación entre severidad, assets y tiempo de resolución")
    
    np.random.seed(42)
    df = pd.DataFrame({
        'cve': [f'CVE-2024-{i:04d}' for i in range(1, 31)],
        'cvss': np.random.uniform(4, 10, 30),
        'assets': np.random.randint(1, 100, 30),
        'days_open': np.random.randint(1, 90, 30),
        'severity': np.random.choice(['Critical', 'High', 'Medium', 'Low'], 30)
    })
    
    color_map = {
        'Critical': '#dc2626',
        'High': '#f97316',
        'Medium': '#eab308',
        'Low': '#3b82f6'
    }
    
    fig = go.Figure()
    
    for sev in ['Critical', 'High', 'Medium', 'Low']:
        df_f = df[df['severity'] == sev]
        fig.add_trace(go.Scatter(
            x=df_f['cvss'],
            y=df_f['days_open'],
            mode='markers',
            name=sev,
            marker=dict(
                size=df_f['assets'],
                sizemode='area',
                sizeref=2.*max(df['assets'])/(40.**2),
                color=color_map[sev],
                line=dict(width=2, color='white')
            ),
            text=df_f['cve']
        ))
    
    fig.update_layout(
        title="Vulnerability Analysis",
        xaxis_title="CVSS Score",
        yaxis_title="Days Open",
        height=500,
        template="plotly_dark"
    )
    
    st.plotly_chart(fig, use_container_width=True)

# ============================================================================
# TÉCNICA 7: LOADING STATES
# ============================================================================

def technique_7_loading():
    st.title("⏳ Técnica 7: Loading States")
    st.markdown("Diferentes técnicas de animaciones de carga")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Spinner")
        if st.button("Simular Escaneo", key="scan1"):
            with st.spinner("Escaneando vulnerabilidades..."):
                time.sleep(3)
            st.success("✅ Escaneo completado!")
    
    with col2:
        st.subheader("Progress Bar")
        if st.button("Escanear Assets", key="scan2"):
            bar = st.progress(0)
            for i in range(100):
                time.sleep(0.02)
                bar.progress(i + 1, text=f"Escaneando... {i+1}%")
            bar.empty()
            st.success("✅ 847 assets escaneados!")

# ============================================================================
# TÉCNICA 8: DASHBOARD COMPLETO
# ============================================================================

def technique_8_complete():
    st.title("🎨 Técnica 8: Dashboard Completo Animado")
    
    # Métricas superiores
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Vulnerabilities", "156", "+12")
    with col2:
        st.metric("Critical", "24", "+3", delta_color="inverse")
    with col3:
        st.metric("High", "45", "+5", delta_color="inverse")
    with col4:
        st.metric("Assets Scanned", "847", "+23")
    
    # Gráficos principales
    col1, col2 = st.columns(2)
    
    with col1:
        dates = pd.date_range(start='2024-01-01', periods=100, freq='D')
        data = pd.DataFrame({
            'date': dates,
            'vulnerabilities': np.cumsum(np.random.randint(1, 5, 100))
        })
        
        fig = px.area(data, x='date', y='vulnerabilities',
                     title="Vulnerability Trend")
        fig.update_layout(template="plotly_dark", height=350)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        df = pd.DataFrame({
            'severity': ['Critical', 'High', 'Medium', 'Low'],
            'count': [24, 45, 67, 20]
        })
        
        fig = px.pie(df, values='count', names='severity',
                    title="Vulnerabilities by Severity",
                    color='severity',
                    color_discrete_map={
                        'Critical': '#dc2626',
                        'High': '#f97316',
                        'Medium': '#eab308',
                        'Low': '#3b82f6'
                    })
        fig.update_layout(template="plotly_dark", height=350)
        st.plotly_chart(fig, use_container_width=True)
    
    # Tabla de vulnerabilidades
    st.subheader("Recent Detections")
    vulns = pd.DataFrame({
        'CVE': [f'CVE-2024-{i:04d}' for i in range(1, 11)],
        'Name': [f'Vulnerability {i}' for i in range(1, 11)],
        'Severity': np.random.choice(['Critical', 'High', 'Medium'], 10),
        'CVSS': np.random.uniform(7, 10, 10).round(1),
        'Assets': np.random.randint(1, 50, 10),
        'Detected': pd.date_range(end='2024-12-05', periods=10, freq='H').strftime('%Y-%m-%d %H:%M')
    })
    
    st.dataframe(
        vulns.style.background_gradient(subset=['CVSS'], cmap='Reds'),
        use_container_width=True,
        height=400
    )

# ============================================================================
# ROUTER PRINCIPAL
# ============================================================================

if technique == "1️⃣ Animación Progresiva":
    technique_1_progressive_animation()
elif technique == "2️⃣ Transiciones con Frames":
    technique_2_frames()
elif technique == "3️⃣ Tiempo Real (Auto-refresh)":
    technique_3_realtime()
elif technique == "4️⃣ Indicadores Animados":
    technique_4_gauges()
elif technique == "5️⃣ Heatmap Interactivo":
    technique_5_heatmap()
elif technique == "6️⃣ Bubble Chart":
    technique_6_bubble()
elif technique == "7️⃣ Loading States":
    technique_7_loading()
elif technique == "8️⃣ Dashboard Completo":
    technique_8_complete()
