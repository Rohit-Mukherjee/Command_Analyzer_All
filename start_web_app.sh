#!/bin/bash
# Startup script for Command Line Threat Analyzer

echo "🚀 Starting Command Line Threat Analyzer Web Application..."
echo "🌐 Access the application at: http://localhost:8501"
echo "💡 Upload your command line CSV files for analysis"
echo " "

# Start the Streamlit app
python3 -m streamlit run web_app.py --server.port 8501 --server.address 0.0.0.0