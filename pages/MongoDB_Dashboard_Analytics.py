import streamlit as st

# Set the page configuration
st.set_page_config(
    page_title="MongoDB Dashboard",
    page_icon="📊",
    layout="wide"
)

st.title("MongoDB Dashboard 📈")

# Embed MongoDB Chart 1
st.subheader("MongoDB Charts - Data Analytics & Insights 📊")
chart_url_1 = "https://charts.mongodb.com/charts-project-0-zykqjpg/embed/charts?id=3d64209f-c1a0-457b-b478-a6514c3c7073&maxDataAge=3600&theme=light&autoRefresh=true"
st.components.v1.iframe(chart_url_1, width=2000, height=500)

# Create two columns for Chart 2 and Chart 3
col1, col2 = st.columns(2)

with col1:
    chart_url_2 = "https://charts.mongodb.com/charts-project-0-zykqjpg/embed/charts?id=c2e3e88d-a945-41d1-aba4-239cde2467e4&maxDataAge=3600&theme=light&autoRefresh=true"
    st.components.v1.iframe(chart_url_2, width=1000, height=500)

with col2:
    chart_url_3 = "https://charts.mongodb.com/charts-project-0-zykqjpg/embed/charts?id=7ac65ed2-9bbd-4b8f-b897-990b0cb289ff&maxDataAge=3600&theme=light&autoRefresh=true"
    st.components.v1.iframe(chart_url_3, width=1000, height=500)

# Embed MongoDB Chart 4 at the bottom
st.subheader("MongoDB Charts - Full Dashboard View 📊")
chart_url_4 = "https://charts.mongodb.com/charts-project-0-zykqjpg/public/dashboards/b0de42aa-c501-424e-81cb-24ea7ba36db1"
st.components.v1.iframe(chart_url_4, width=2000, height=1000)