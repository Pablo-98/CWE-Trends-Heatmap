# CWE Heatmap: Multi-Year CWE Trend Analysis

The **CWE Heatmap** project is a Python-based analysis tool that visualizes how **Common Weakness Enumeration (CWE)** rankings change over time.  
It processes multiple years of CWE XML data and generates **heatmaps** that highlight trends in **software and hardware weaknesses** across years.


---

## Overview

This project:
- Parses yearly CWE XML files
- Extracts the **Top 25 CWEs** per year
- Classifies CWEs as **software** or **hardware**
- Generates heatmaps to visualize:
  - Software CWE rank changes over time
  - Hardware CWE presence across years

The output is saved as high-resolution PNG images for reporting or analysis.

---

## Key Features

- **Multi-Year CWE Comparison**  
  Analyze CWE trends across multiple years (e.g., 2019–2023).

- **Software Rank Heatmap**  
  Shows how software CWEs rise or fall in priority over time.

- **Hardware Presence Heatmap**  
  Indicates whether a hardware CWE appears in the Top 25 for each year.

- **Automated Visualization Output**  
  Heatmaps are saved directly to image files.

---

## Requirements

- Python 3 or later
- `venv` module (included by default in Python ≥ 3.3)

### Python Libraries
- pandas  
- seaborn  
- matplotlib  

## Installation:
Install Dependencies with this command
```pip install pandas seaborn matplotlib```
Running the Project with
``` python heatmap.py```

