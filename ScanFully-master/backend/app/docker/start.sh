#!/bin/bash
# Start backend
uvicorn main:app --host 0.0.0.0 --port 8000 &

# Start frontend
streamlit run app.py --server.port 8501 --server.address 0.0.0.0