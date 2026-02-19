import streamlit as st
import pandas as pd
import json
import time
import io
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import base64

# Import our modules
from log_analyzer import make_analyzer, load_rules, sanitize_text
from threat_intel import ThreatIntelligenceProvider
from behavioral_analyzer import BehavioralAnalyzer


def generate_summary_paragraph(df, total_commands, matched_commands, unknown_commands, anomaly_count):
    """
    Generate an executive summary paragraph based on the analysis results
    """
    # Calculate percentages
    match_rate = (matched_commands / total_commands) * 100 if total_commands > 0 else 0
    anomaly_rate = (anomaly_count / total_commands) * 100 if total_commands > 0 else 0

    # Identify top threat categories
    if 'Category' in df.columns:
        top_categories = df['Category'].value_counts().head(3)
        top_cats_list = [f"{cat} ({count} instances)" for cat, count in top_categories.items()]
        top_categories_str = ", ".join(top_cats_list)
    else:
        top_categories_str = "No categories identified"

    # Identify top platforms
    if 'OS' in df.columns:
        platform_counts = df['OS'].value_counts()
        platform_list = [f"{os} ({count})" for os, count in platform_counts.items()]
        platforms_str = ", ".join(platform_list)
    else:
        platforms_str = "Unknown platforms"

    # Identify severity distribution if available
    if 'Severity_Label' in df.columns:
        severity_counts = df['Severity_Label'].value_counts()
        if not severity_counts.empty:
            highest_severity = severity_counts.index[0]
            highest_severity_count = severity_counts.iloc[0]
        else:
            highest_severity = "Unknown"
            highest_severity_count = 0
    else:
        highest_severity = "Unknown"
        highest_severity_count = 0

    # Construct the summary paragraph
    summary = f"""
The analysis of {total_commands} command line entries revealed {matched_commands} potentially malicious activities ({match_rate:.1f}% of total), with {unknown_commands} commands not matching known patterns. A total of {int(anomaly_count)} anomalous commands were identified ({anomaly_rate:.1f}% of total), suggesting potential deviations from normal behavior patterns. The most frequently observed threat categories were: {top_categories_str}. The commands originated primarily from the following platforms: {platforms_str}. The highest severity threats identified were predominantly {highest_severity} level (appearing in {highest_severity_count} instances). These findings indicate potential security concerns requiring further investigation, particularly focusing on the identified threat categories and anomalous behavior patterns.
    """.strip()

    return summary

# Set page config
st.set_page_config(
    page_title="Command Line Threat Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
if 'results_df' not in st.session_state:
    st.session_state.results_df = None
if 'upload_key' not in st.session_state:
    st.session_state.upload_key = 0
if 'analysis_params' not in st.session_state:
    st.session_state.analysis_params = {
        'include_threat_intel': True,
        'include_behavioral': True,
        'confidence_threshold': 0.5
    }

st.title("🛡️ Command Line Threat Analyzer")
st.subheader("Upload your command line logs for comprehensive threat analysis")

# Sidebar with instructions and settings
with st.sidebar:
    st.header("📋 Instructions")
    st.markdown("""
    1. Upload a CSV file with a 'commandline' column
    2. Adjust analysis parameters (optional)
    3. Click 'Analyze' to process your data
    4. View detailed analysis results
    5. Download the analyzed results
    """)
    
    st.header("⚙️ Analysis Settings")
    st.session_state.analysis_params['include_threat_intel'] = st.checkbox(
        "Include Threat Intelligence", 
        value=st.session_state.analysis_params['include_threat_intel'],
        help="Enable MITRE ATT&CK framework integration"
    )
    st.session_state.analysis_params['include_behavioral'] = st.checkbox(
        "Include Behavioral Analysis", 
        value=st.session_state.analysis_params['include_behavioral'],
        help="Enable anomaly detection and behavioral analysis"
    )
    st.session_state.analysis_params['confidence_threshold'] = st.slider(
        "Confidence Threshold", 
        min_value=0.0, 
        max_value=1.0, 
        value=st.session_state.analysis_params['confidence_threshold'],
        step=0.05,
        help="Minimum confidence level for threat detection"
    )
    
    st.header("📊 Features")
    st.markdown("""
    - Threat detection across multiple platforms
    - MITRE ATT&CK framework integration
    - Behavioral anomaly detection
    - Performance metrics
    - Interactive visualizations
    - Customizable analysis parameters
    """)

# File uploader
uploaded_file = st.file_uploader(
    "Choose a file with command line data (CSV or Excel)",
    type=['csv', 'xlsx', 'xls'],
    accept_multiple_files=False,
    key=f"uploader_{st.session_state.upload_key}"
)

if uploaded_file is not None:
    # Read the uploaded file with error handling
    try:
        # Determine file type and read accordingly
        file_name = uploaded_file.name.lower()
        if file_name.endswith('.csv'):
            # Read CSV with flexible settings to handle problematic files
            df = pd.read_csv(uploaded_file,
                             on_bad_lines='skip',  # Skip problematic lines
                             quoting=1,  # QUOTE_ALL
                             sep=',',  # Explicitly set separator
                             encoding='utf-8',
                             low_memory=False)  # Handle large files better
        elif file_name.endswith('.xlsx') or file_name.endswith('.xls'):
            # Read Excel file
            df = pd.read_excel(uploaded_file)
        
        # Normalize column names to lowercase for comparison
        df.columns = df.columns.str.lower()
        
        # Check if 'commandline' or 'commandlines' column exists (case-insensitive)
        command_col = None
        for col in df.columns:
            if col in ['commandline', 'commandlines']:
                command_col = col
                break
        
        if command_col is None:
            st.error("❌ The uploaded file must contain a 'commandline' or 'commandlines' column")
            st.info("Please ensure your file has a column named 'commandline' or 'commandlines' (case-insensitive)")
        else:
            st.success(f"✅ Successfully loaded {len(df)} command entries from '{command_col}' column")
            
            # Rename the command column to 'commandline' for consistency
            df.rename(columns={command_col: 'commandline'}, inplace=True)
            
            # Show sample of data
            st.subheader("📄 Data Preview")
            st.dataframe(df.head())
            
            # Analysis button
            if st.button("🔍 Analyze Command Lines", type="primary"):
                with st.spinner("Performing comprehensive threat analysis..."):
                    # Load rules
                    rules_data = load_rules("rules.json")
                    analyze_command = make_analyzer(rules_data)
                    
                    # Initialize threat intelligence if enabled
                    threat_intel_provider = None
                    if st.session_state.analysis_params['include_threat_intel']:
                        threat_intel_provider = ThreatIntelligenceProvider()
                        threat_intel_provider.load_mitre_mappings()
                    
                    # Initialize behavioral analyzer if enabled
                    behavioral_analyzer = None
                    if st.session_state.analysis_params['include_behavioral']:
                        behavioral_analyzer = BehavioralAnalyzer()
                    
                    # Process commands
                    start_time = time.time()
                    
                    # Apply basic analysis
                    df["Analysis"] = df["commandline"].apply(analyze_command)
                    df["Analysis"] = df["Analysis"].apply(sanitize_text)
                    
                    # Apply threat intelligence enrichment if enabled
                    if threat_intel_provider:
                        df["Analysis"] = df["Analysis"].apply(threat_intel_provider.enrich_analysis_result)
                    
                    # Apply behavioral analysis if enabled
                    if behavioral_analyzer:
                        analyzed_df = behavioral_analyzer.detect_anomalies(df)
                    else:
                        analyzed_df = df  # Use original df if behavioral analysis is disabled
                    
                    processing_time = time.time() - start_time
                    
                    # Add timestamp for timeline visualization
                    analyzed_df['timestamp'] = pd.date_range(start=datetime.now(), periods=len(analyzed_df), freq='1min')
                    
                    # Store results in session state
                    st.session_state.results_df = analyzed_df
                    st.session_state.analysis_complete = True
                    
                    st.success(f"✅ Analysis complete! Processed {len(analyzed_df)} commands in {processing_time:.2f}s")
    
    except Exception as e:
        st.error(f"❌ Error reading the file: {str(e)}")

# Display results if analysis is complete
if st.session_state.analysis_complete and st.session_state.results_df is not None:
    st.header("📈 Analysis Results")
    
    df = st.session_state.results_df
    
    # Parse the Analysis column to extract components
    df[['Description', 'Category', 'OS']] = df['Analysis'].str.extract(r'(.*?) \| Category: (.*?) \| OS: (.*)')
    
    # Add severity scoring based on threat intel
    def calculate_severity(analysis_str):
        if 'Unknown Activity' in analysis_str:
            return 1  # Low
        elif 'MITRE:' in analysis_str:
            # Higher severity for MITRE-tagged items
            if any(high_severity in analysis_str.upper() for high_severity in ['CREDENTIAL_ACCESS', 'PERSISTENCE', 'EXECUTION']):
                return 5  # Critical
            elif any(med_severity in analysis_str.upper() for med_severity in ['LATERAL_MOVEMENT', 'DEFENSE_EVASION', 'IMPACT']):
                return 4  # High
            else:
                return 3  # Medium
        else:
            return 2  # Low
    
    df['Severity'] = df['Analysis'].apply(calculate_severity)
    severity_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Very High', 5: 'Critical'}
    df['Severity_Label'] = df['Severity'].map(severity_map)
    
    # Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total_commands = len(df)
    matched_commands = len(df[df['Analysis'] != 'Unknown Activity'])
    unknown_commands = len(df[df['Analysis'] == 'Unknown Activity'])
    anomaly_count = df['is_anomaly'].sum() if 'is_anomaly' in df.columns else 0
    
    col1.metric("Total Commands", total_commands)
    col2.metric("Matched", matched_commands)
    col3.metric("Unknown", unknown_commands)
    col4.metric("Anomalies", int(anomaly_count))
    col5.metric("Match Rate", f"{(matched_commands/total_commands)*100:.1f}%" if total_commands > 0 else "0%")
    
    # Severity metrics
    if 'Severity_Label' in df.columns:
        severity_counts = df['Severity_Label'].value_counts()
        severity_cols = st.columns(len(severity_counts))
        for i, (severity, count) in enumerate(severity_counts.items()):
            severity_cols[i % len(severity_cols)].metric(f"{severity}", count)
    
    # Charts
    st.subheader("📊 Distribution Charts")
    
    # Create two columns for distribution charts
    dist_col1, dist_col2 = st.columns(2)
    
    with dist_col1:
        # Category distribution
        if 'Category' in df.columns:
            category_counts = df['Category'].value_counts()
            fig_cat = go.Figure(data=[
                go.Bar(
                    y=category_counts.index.tolist(),
                    x=category_counts.values.tolist(),
                    orientation='h',
                    marker_color='rgb(55, 83, 109)'
                )
            ])
            fig_cat.update_layout(
                height=500,
                title="Threat Categories Distribution",
                xaxis_title="Count",
                yaxis_title="Category",
                showlegend=False
            )
            st.plotly_chart(fig_cat, use_container_width=True)
    
    with dist_col2:
        # OS distribution
        if 'OS' in df.columns:
            os_counts = df['OS'].value_counts()
            fig_os = px.pie(
                values=os_counts.values, 
                names=os_counts.index,
                title="Platform Distribution"
            )
            st.plotly_chart(fig_os, use_container_width=True)
    
    # Severity distribution
    if 'Severity_Label' in df.columns:
        st.subheader("🚨 Threat Severity Distribution")
        severity_counts = df['Severity_Label'].value_counts()
        fig_severity = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            title="Threat Severity Distribution",
            color_discrete_map={
                'Critical': '#FF0000',
                'Very High': '#FF4500',
                'High': '#FFA500',
                'Medium': '#FFFF00',
                'Low': '#90EE90'
            }
        )
        st.plotly_chart(fig_severity, use_container_width=True)
    
    # Top threats
    st.subheader("🔥 Top Threats Identified")
    if 'Description' in df.columns:
        top_threats = df['Description'].value_counts().head(10)
        fig_threats = go.Figure(data=[
            go.Bar(
                y=top_threats.index.tolist(),
                x=top_threats.values.tolist(),
                orientation='h',
                marker_color='rgb(26, 118, 255)'
            )
        ])
        fig_threats.update_layout(
            height=500,
            title="Top 10 Threat Types",
            xaxis_title="Count",
            yaxis_title="Threat Type",
            showlegend=False
        )
        st.plotly_chart(fig_threats, use_container_width=True)
    
    # Timeline visualization
    if 'timestamp' in df.columns:
        st.subheader("⏱️ Threat Timeline")
        df_sorted = df.sort_values('timestamp')
        fig_timeline = px.scatter(
            df_sorted, 
            x='timestamp', 
            y='Severity', 
            color='Severity_Label',
            hover_data=['commandline', 'Analysis'],
            title="Threat Activity Over Time",
            labels={'Severity': 'Severity Level', 'timestamp': 'Time'}
        )
        fig_timeline.update_layout(height=500)
        st.plotly_chart(fig_timeline, use_container_width=True)
    
    # Behavioral Analysis Section
    if 'is_anomaly' in df.columns:
        st.subheader("🔍 Behavioral Analysis")
        
        col_be1, col_be2 = st.columns(2)
        
        with col_be1:
            st.metric("Anomalous Commands", int(anomaly_count))
            st.metric("Normal Commands", int(total_commands - anomaly_count))
        
        with col_be2:
            if anomaly_count > 0:
                anomaly_pct = (anomaly_count / total_commands) * 100
                st.metric("Anomaly Percentage", f"{anomaly_pct:.2f}%")
                
                # Show anomalous commands
                anomalous_cmds = df[df['is_anomaly'] == True]['commandline'].head(5)
                if len(anomalous_cmds) > 0:
                    st.write("**Sample Anomalous Commands:**")
                    for cmd in anomalous_cmds:
                        st.code(cmd, language="bash")
    
    # Detailed results table with advanced filtering
    st.subheader("📋 Detailed Analysis Results")
    
    # Advanced filters
    col_filter1, col_filter2, col_filter3, col_filter4 = st.columns(4)
    with col_filter1:
        if 'OS' in df.columns:
            selected_os = st.multiselect("Filter by OS", options=df['OS'].unique(), default=df['OS'].unique())
    with col_filter2:
        if 'Category' in df.columns:
            selected_category = st.multiselect("Filter by Category", options=df['Category'].unique(), default=df['Category'].unique())
    with col_filter3:
        if 'Severity_Label' in df.columns:
            selected_severity = st.multiselect("Filter by Severity", options=df['Severity_Label'].unique(), default=df['Severity_Label'].unique())
    with col_filter4:
        if 'is_anomaly' in df.columns:
            show_anomalies = st.checkbox("Show Only Anomalies", value=False)
    
    # Apply filters
    filtered_df = df.copy()
    if 'OS' in df.columns:
        filtered_df = filtered_df[(filtered_df['OS'].isin(selected_os))]
    if 'Category' in df.columns:
        filtered_df = filtered_df[(filtered_df['Category'].isin(selected_category))]
    if 'Severity_Label' in df.columns:
        filtered_df = filtered_df[(filtered_df['Severity_Label'].isin(selected_severity))]
    if show_anomalies and 'is_anomaly' in df.columns:
        filtered_df = filtered_df[filtered_df['is_anomaly'] == True]
    
    # Show filtered results with search
    st.text_input("🔍 Search in command lines:", key="search_query")
    if st.session_state.search_query:
        filtered_df = filtered_df[filtered_df['commandline'].str.contains(st.session_state.search_query, case=False, na=False)]
    
    # Show filtered results
    st.dataframe(
        filtered_df[['commandline', 'Analysis', 'Severity_Label', 'is_anomaly']].rename(columns={
            'commandline': 'Command Line',
            'Analysis': 'Threat Analysis',
            'Severity_Label': 'Severity',
            'is_anomaly': 'Is Anomaly'
        }).head(100),  # Limit to 100 rows for performance
        height=500
    )
    
    # Quick Summary Section
    st.subheader("📋 Quick Summary")
    
    # Create summary statistics
    summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
    
    with summary_col1:
        st.metric("Total Commands", total_commands)
    with summary_col2:
        st.metric("Threats Found", matched_commands)
    with summary_col3:
        st.metric("Unknown Commands", unknown_commands)
    with summary_col4:
        st.metric("Anomalies", int(anomaly_count))
    
    # Threat breakdown
    st.subheader("🚨 Threat Breakdown")
    if 'Severity_Label' in df.columns:
        severity_breakdown = df['Severity_Label'].value_counts()
        severity_breakdown_df = pd.DataFrame({
            'Severity Level': severity_breakdown.index,
            'Count': severity_breakdown.values,
            'Percentage': [f"{(count/total_commands)*100:.1f}%" for count in severity_breakdown.values]
        })
        st.table(severity_breakdown_df)
    
    # Platform distribution
    st.subheader("🖥️ Platform Distribution")
    if 'OS' in df.columns:
        platform_breakdown = df['OS'].value_counts()
        platform_breakdown_df = pd.DataFrame({
            'Platform': platform_breakdown.index,
            'Count': platform_breakdown.values,
            'Percentage': [f"{(count/total_commands)*100:.1f}%" for count in platform_breakdown.values]
        })
        st.table(platform_breakdown_df)
    
    # Top 5 threat categories
    st.subheader("📊 Top 5 Threat Categories")
    if 'Category' in df.columns:
        category_breakdown = df['Category'].value_counts().head(5)
        category_breakdown_df = pd.DataFrame({
            'Category': category_breakdown.index,
            'Count': category_breakdown.values,
            'Percentage': [f"{(count/total_commands)*100:.1f}%" for count in category_breakdown.values]
        })
        st.table(category_breakdown_df)
    
    # Summary Paragraph
    st.subheader("📋 Executive Summary")
    
    # Generate a summary paragraph based on the analysis
    summary_text = generate_summary_paragraph(df, total_commands, matched_commands, unknown_commands, anomaly_count)
    st.text_area("Executive Summary", value=summary_text, height=200)
    
    # Export options
    st.subheader("💾 Export Results")
    
    # Create download buttons for different formats
    col_exp1, col_exp2, col_exp3 = st.columns(3)
    
    with col_exp1:
        # CSV export
        csv_buffer = io.StringIO()
        filtered_df.to_csv(csv_buffer, index=False)
        csv_string = csv_buffer.getvalue()
        
        st.download_button(
            label="📥 Download CSV",
            data=csv_string,
            file_name=f"analyzed_commands_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    with col_exp2:
        # JSON export
        json_string = filtered_df.to_json(orient='records', date_format='iso', indent=2)
        
        st.download_button(
            label="📥 Download JSON",
            data=json_string,
            file_name=f"analyzed_commands_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    with col_exp3:
        # Excel export (if available)
        try:
            from openpyxl import Workbook
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                filtered_df.to_excel(writer, index=False, sheet_name='Analysis Results')
                # Add summary sheet
                summary_df = pd.DataFrame({
                    'Metric': ['Total Commands', 'Matched', 'Unknown', 'Anomalies', 'Match Rate'],
                    'Value': [
                        total_commands,
                        matched_commands,
                        unknown_commands,
                        int(anomaly_count),
                        f"{(matched_commands/total_commands)*100:.1f}%" if total_commands > 0 else "0%"
                    ]
                })
                summary_df.to_excel(writer, index=False, sheet_name='Summary')
            
            st.download_button(
                label="📥 Download Excel",
                data=excel_buffer.getvalue(),
                file_name=f"analyzed_commands_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        except ImportError:
            st.info("Install openpyxl for Excel export: pip install openpyxl")
    
    # Option to reset and analyze another file
    if st.button("🔄 Analyze Another File"):
        st.session_state.analysis_complete = False
        st.session_state.results_df = None
        st.session_state.upload_key += 1
        st.rerun()

# Footer
st.markdown("---")
st.markdown("*Command Line Threat Analyzer - Advanced cybersecurity analysis for modern threats*")