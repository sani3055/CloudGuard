import streamlit as st
import plotly.express as px

from utils import load_data, color_severity

# ----------------------------
# Page Config
# ----------------------------

st.set_page_config(
    page_title="CloudGuard",
    page_icon="🛡️",
    layout="wide"
)

# ----------------------------
# Load Data
# ----------------------------

df = load_data()

# ----------------------------
# Sidebar
# ----------------------------

st.sidebar.title("CloudGuard")

st.sidebar.markdown("---")

st.sidebar.success("AWS Security Monitoring")

if st.sidebar.button("Refresh Data"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")

st.sidebar.write("Services")

st.sidebar.write("• CloudTrail")
st.sidebar.write("• EventBridge")
st.sidebar.write("• Lambda")
st.sidebar.write("• DynamoDB")
st.sidebar.write("• SNS")

# ----------------------------
# Title
# ----------------------------

st.title("CloudGuard Dashboard")

st.caption("Real-Time AWS Cloud Security Monitoring Platform")

if df.empty:
    st.warning("No Threat Events Found")
    st.stop()

# ----------------------------
# KPI Values
# ----------------------------

total = len(df)

critical = len(df[df["severity"] == "Critical"])

high = len(df[df["severity"] == "High"])

avg = round(df["riskScore"].mean(), 1)

# ----------------------------
# Beautiful Cards
# ----------------------------

def metric_card(title, value, color):

    st.markdown(
        f"""
        <div style="
        background:{color};
        border-radius:15px;
        padding:25px;
        text-align:center;
        box-shadow:0 4px 10px rgba(0,0,0,0.3);
        ">
            <h4 style="color:white;">{title}</h4>
            <h1 style="color:white;">{value}</h1>
        </div>
        """,
        unsafe_allow_html=True
    )

col1, col2, col3, col4 = st.columns(4)

with col1:
    metric_card("Total Threats", total, "#2563EB")

with col2:
    metric_card("Critical", critical, "#DC2626")

with col3:
    metric_card("High", high, "#EA580C")

with col4:
    metric_card("Average Risk", avg, "#059669")

st.markdown("---")

# ----------------------------
# Charts
# ----------------------------

left, right = st.columns(2)

with left:

    severity_chart = px.pie(
        df,
        names="severity",
        hole=0.55,
        title="Threat Severity Distribution"
    )

    severity_chart.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )

    st.plotly_chart(
        severity_chart,
        use_container_width=True
    )

with right:

    event_chart = px.bar(
        df.groupby("eventName")
        .size()
        .reset_index(name="Threats"),
        x="eventName",
        y="Threats",
        title="Threats by Event"
    )

    event_chart.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )

    st.plotly_chart(
        event_chart,
        use_container_width=True
    )

st.markdown("---")

# ----------------------------
# Timeline
# ----------------------------

timeline = px.line(
    df.sort_values("timestamp"),
    x="timestamp",
    y="riskScore",
    markers=True,
    title="Threat Timeline"
)

timeline.update_layout(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)"
)

st.plotly_chart(
    timeline,
    use_container_width=True
)

st.markdown("---")

# ----------------------------
# Filters
# ----------------------------

col1, col2 = st.columns(2)

with col1:

    severity = st.selectbox(
        "Severity",
        [
            "All",
            "Critical",
            "High",
            "Medium",
            "Low"
        ]
    )

with col2:

    search = st.text_input(
        "Search Event"
    )

filtered = df.copy()

if severity != "All":

    filtered = filtered[
        filtered["severity"] == severity
    ]

if search:

    filtered = filtered[
        filtered["eventName"]
        .str.contains(
            search,
            case=False
        )
    ]

# ----------------------------
# Recent Threats
# ----------------------------

st.subheader("Recent Threats")

display = filtered[
[
"eventName",
"severity",
"riskScore",
"region",
"userType",
"eventSource",
"timestamp"
]
]

display = display.sort_values(
    "timestamp",
    ascending=False
)

st.dataframe(
    display.style.map(
        color_severity,
        subset=["severity"]
    ),
    use_container_width=True,
    height=450
)