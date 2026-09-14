import streamlit as st
import pandas as pd
import plotly.express as px
from utils import inject_css, load_data

inject_css()

st.markdown("# Analytics")
st.markdown('<div class="cg-section-header">Interactive ML & Cloud Data Analytics</div>', unsafe_allow_html=True)

df = load_data()
if df.empty:
    st.info("No cloud events available for analysis.")
    st.stop()

# Ensure timestamp is parsed properly
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
df['hourOfDay'] = df['timestamp'].dt.hour
df['dayOfWeek'] = df['timestamp'].dt.day_name()

# ── Sidebar Filters ──
st.sidebar.markdown("### 🔍 Analytics Filters")
data_src = st.sidebar.selectbox("Data Source", ["All", "Live AWS", "Demo/Simulation"])
anom_status = st.sidebar.selectbox("Anomaly Status", ["All", "Anomaly", "Normal"])
risk_range = st.sidebar.slider("Risk Score Range", 0, 100, (0, 100))
api_filter = st.sidebar.multiselect("Event/API Name", options=df['eventName'].unique())
region_filter = st.sidebar.multiselect("AWS Region", options=df['awsRegion'].unique())
principal_filter = st.sidebar.multiselect("Principal", options=df['userIdentitytype'].unique())

# Apply filters
filtered_df = df.copy()

if data_src == "Live AWS":
    filtered_df = filtered_df[filtered_df['is_demo'] == False]
elif data_src == "Demo/Simulation":
    filtered_df = filtered_df[filtered_df['is_demo'] == True]

if anom_status == "Anomaly":
    filtered_df = filtered_df[filtered_df['isAnomaly'] == True]
elif anom_status == "Normal":
    filtered_df = filtered_df[filtered_df['isAnomaly'] == False]

filtered_df = filtered_df[(filtered_df['riskScore'] >= risk_range[0]) & (filtered_df['riskScore'] <= risk_range[1])]

if api_filter:
    filtered_df = filtered_df[filtered_df['eventName'].isin(api_filter)]
if region_filter:
    filtered_df = filtered_df[filtered_df['awsRegion'].isin(region_filter)]
if principal_filter:
    filtered_df = filtered_df[filtered_df['userIdentitytype'].isin(principal_filter)]

if filtered_df.empty:
    st.success("No data matches the selected filters.")
    st.stop()

# ── Row 1: Event Timeline & Top APIs ──
c1, c2 = st.columns([2, 1])
with c1:
    st.markdown("#### Event Timeline")
    filtered_df['isAnomaly_str'] = filtered_df['isAnomaly'].apply(lambda x: "Anomaly" if x else "Normal")
    fig_time = px.histogram(
        filtered_df, 
        x="timestamp", 
        color="isAnomaly_str",
        color_discrete_map={'Anomaly': '#e05252', 'Normal': '#4f86c6'},
        nbins=40
    )
    fig_time.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350, margin=dict(t=10))
    st.plotly_chart(fig_time, use_container_width=True)

with c2:
    st.markdown("#### Top Cloud APIs")
    top_apis = filtered_df['eventName'].value_counts().reset_index().head(10)
    top_apis.columns = ['eventName', 'count']
    fig_api = px.bar(
        top_apis, 
        y="eventName", 
        x="count", 
        orientation='h', 
        color="count",
        color_continuous_scale="Blues"
    )
    fig_api.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", yaxis={'categoryorder':'total ascending'}, height=350, showlegend=False, margin=dict(t=10))
    st.plotly_chart(fig_api, use_container_width=True)

# ── Row 2: Heatmap & Distributions ──
c3, c4 = st.columns([1, 1])
with c3:
    st.markdown("#### Time-of-Day Anomaly Heatmap")
    heatmap_df = filtered_df[filtered_df['isAnomaly'] == True].groupby(['dayOfWeek', 'hourOfDay']).size().reset_index(name='count')
    # Reorder days
    days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    if not heatmap_df.empty:
        fig_heat = px.density_heatmap(
            heatmap_df, x="hourOfDay", y="dayOfWeek", z="count",
            category_orders={"dayOfWeek": days_order},
            color_continuous_scale="Reds",
            nbinsx=24
        )
        fig_heat.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350, margin=dict(t=10))
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No anomalies available for heatmap.")

with c4:
    st.markdown("#### Geographic Distribution (Regions)")
    reg_df = filtered_df['awsRegion'].value_counts().reset_index()
    reg_df.columns = ['awsRegion', 'count']
    fig_reg = px.pie(reg_df, names="awsRegion", values="count", hole=0.4, color_discrete_sequence=px.colors.sequential.Teal)
    fig_reg.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350, margin=dict(t=10))
    st.plotly_chart(fig_reg, use_container_width=True)

# ── Row 3: Principals & Risk vs API ──
c5, c6 = st.columns([1, 1])
with c5:
    st.markdown("#### Principal Distribution")
    princ_df = filtered_df['userIdentitytype'].value_counts().reset_index()
    princ_df.columns = ['userIdentitytype', 'count']
    fig_princ = px.bar(princ_df, x="userIdentitytype", y="count", color="count", color_continuous_scale="Blues")
    fig_princ.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350, margin=dict(t=10))
    st.plotly_chart(fig_princ, use_container_width=True)

with c6:
    st.markdown("#### Risk vs Event Type")
    fig_box = px.box(
        filtered_df,
        x="eventName",
        y="riskScore",
        color="isAnomaly_str",
        color_discrete_map={"Anomaly": "#e05252", "Normal": "#4f86c6"}
    )
    fig_box.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350, margin=dict(t=10))
    st.plotly_chart(fig_box, use_container_width=True)
