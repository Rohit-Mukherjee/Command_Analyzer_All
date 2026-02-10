import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from datetime import datetime
import numpy as np

# Set page config
st.set_page_config(
    page_title="Command Line Threat Analyzer Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Command Line Threat Analyzer Dashboard")

# Sidebar for file uploads
st.sidebar.header("📁 Data Sources")
analysis_csv = st.sidebar.file_uploader("Upload Analysis Results CSV", type=['csv'])
rules_json = st.sidebar.file_uploader("Upload Rules JSON", type=['json'])

# Load data
df = None
rules_data = None

if analysis_csv is not None:
    df = pd.read_csv(analysis_csv)
    st.sidebar.success(f"Loaded {len(df)} command records")
else:
    # Default to existing analysis file if no upload
    try:
        df = pd.read_csv("Commands_analyzed.csv")
        st.sidebar.info("Using default Commands_analyzed.csv")
    except FileNotFoundError:
        st.info("👆 Please upload an analysis CSV file or run the analyzer first")

if rules_json is not None:
    rules_data = json.load(rules_json)
elif df is not None:
    try:
        with open("rules.json", 'r') as f:
            rules_data = json.load(f)
        st.sidebar.info("Using default rules.json")
    except FileNotFoundError:
        st.sidebar.warning("rules.json not found")

# Main dashboard content
if df is not None and 'Analysis' in df.columns:
    # Parse the Analysis column to extract components
    df[['Description', 'Category', 'OS']] = df['Analysis'].str.extract(r'(.*?) \| Category: (.*?) \| OS: (.*)')
    
    # Convert commandline to string if not already
    df['commandline'] = df['commandline'].astype(str)
    
    # Calculate metrics
    total_commands = len(df)
    unique_descriptions = df['Description'].nunique()
    unique_categories = df['Category'].nunique()
    unique_os = df['OS'].nunique()
    
    # Display key metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Commands", total_commands)
    col2.metric("Unique Threat Types", unique_descriptions)
    col3.metric("Categories", unique_categories)
    col4.metric("Platforms", unique_os)
    
    st.markdown("---")
    
    # Distribution charts
    st.header("📊 Analysis Distribution")
    
    # Create two columns for distribution charts
    dist_col1, dist_col2 = st.columns(2)
    
    with dist_col1:
        # Category distribution
        category_counts = df['Category'].value_counts()
        fig_cat = px.bar(
            x=category_counts.values, 
            y=category_counts.index,
            orientation='h',
            title="Threat Categories Distribution",
            labels={'x': 'Count', 'y': 'Category'}
        )
        fig_cat.update_layout(height=500)
        st.plotly_chart(fig_cat, use_container_width=True)
    
    with dist_col2:
        # OS distribution
        os_counts = df['OS'].value_counts()
        fig_os = px.pie(
            values=os_counts.values, 
            names=os_counts.index,
            title="Platform Distribution"
        )
        st.plotly_chart(fig_os, use_container_width=True)
    
    # Top threats
    st.header("🚨 Top Threats Identified")
    top_threats = df['Description'].value_counts().head(10)
    fig_threats = px.bar(
        x=top_threats.values, 
        y=top_threats.index,
        orientation='h',
        title="Top 10 Threat Types",
        labels={'x': 'Count', 'y': 'Threat Type'}
    )
    fig_threats.update_layout(height=500)
    st.plotly_chart(fig_threats, use_container_width=True)
    
    # Detailed table with filtering
    st.header("📝 Detailed Analysis Results")
    
    # Filters
    col_filter1, col_filter2 = st.columns(2)
    with col_filter1:
        selected_os = st.multiselect("Filter by OS", options=df['OS'].unique(), default=df['OS'].unique())
    with col_filter2:
        selected_category = st.multiselect("Filter by Category", options=df['Category'].unique(), default=df['Category'].unique())
    
    # Apply filters
    filtered_df = df[
        (df['OS'].isin(selected_os)) & 
        (df['Category'].isin(selected_category))
    ]
    
    # Show filtered results
    st.dataframe(
        filtered_df[['commandline', 'Description', 'Category', 'OS']].rename(columns={
            'commandline': 'Command Line',
            'Description': 'Threat Description'
        }),
        height=500
    )
    
    # Command line search
    st.header("🔍 Search Command Lines")
    search_term = st.text_input("Enter keyword to search in command lines:")
    if search_term:
        search_results = df[df['commandline'].str.contains(search_term, case=False, na=False)]
        st.write(f"Found {len(search_results)} matching commands:")
        st.dataframe(
            search_results[['commandline', 'Description', 'Category', 'OS']].rename(columns={
                'commandline': 'Command Line',
                'Description': 'Threat Description'
            })
        )
    
    # Export options
    st.header("💾 Export Results")
    col_export1, col_export2 = st.columns(2)
    
    with col_export1:
        st.download_button(
            label="Download Filtered Results as CSV",
            data=filtered_df.to_csv(index=False).encode('utf-8'),
            file_name=f"filtered_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime='text/csv'
        )
    
    with col_export2:
        if st.button("Generate Report Summary"):
            report = f"""
Command Line Threat Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Commands Analyzed: {total_commands}
Unique Threat Types: {unique_descriptions}
Coverage by Platform:
{df['OS'].value_counts().to_string()}
Top Threat Categories:
{df['Category'].value_counts().head().to_string()}
            """
            st.text_area("Report Summary", value=report, height=300)
    
    # Additional insights
    st.header("💡 Additional Insights")
    
    # Average command length by category
    df['command_length'] = df['commandline'].apply(len)
    avg_length_by_category = df.groupby('Category')['command_length'].mean().sort_values(ascending=False)
    
    col_insight1, col_insight2 = st.columns(2)
    
    with col_insight1:
        st.subheader("Average Command Length by Category")
        fig_length = px.bar(
            x=avg_length_by_category.values, 
            y=avg_length_by_category.index,
            orientation='h',
            title="Avg Command Length (chars)",
            labels={'x': 'Average Length', 'y': 'Category'}
        )
        fig_length.update_layout(height=400)
        st.plotly_chart(fig_length, use_container_width=True)
    
    with col_insight2:
        st.subheader("Commands per Platform")
        platform_summary = df.groupby(['OS', 'Category']).size().reset_index(name='Count')
        fig_platform = px.sunburst(platform_summary, path=['OS', 'Category'], values='Count',
                                  title="Platform vs Category Distribution")
        st.plotly_chart(fig_platform, use_container_width=True)

else:
    st.info("👆 Upload a CSV file with analysis results to view the dashboard")
    st.markdown("""
    ### Expected CSV Format
    The CSV file should contain at least these columns:
    - `commandline`: The original command line
    - `Analysis`: The analysis result in format "Description | Category: CategoryName | OS: OSName"
    """)

# Footer
st.markdown("---")
st.markdown("*Command Line Threat Analyzer Dashboard - Enhanced Visualization for Cybersecurity Analysis*")