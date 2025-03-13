import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
import matplotlib.pyplot as plt
import seaborn as sns  # Import Seaborn for advanced plotting

from db_connection import get_db
from db_utils import fetch_intrusion_logs

# Fx to load external CSS
def load_css(css_file="styles.css"):
    with open(css_file) as f:
        css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
    
load_css("styles.css")

st.title("Data visualization")

data = fetch_intrusion_logs()

df = pd.json_normalize(data)

with st.expander("Flattened Data:"):
        st.write(df.head())
        
option = st.selectbox(
    "Select a column to analyze", ["Select a column"] + list(df.columns)
)

if option != "Select a column":    
    
    st.write(f"You selected {option}")
    
    # Display charts in two columns
    col1, col2 = st.columns(2)

    with col1:
        fig = px.histogram(df, x=option, nbins=20, title=f"Distribution of {option}")
        st.plotly_chart(fig)
    
    with col2:
        fig = px.box(df, y=option, title=f"{option} Boxplot")
        st.plotly_chart(fig)
