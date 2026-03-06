# InsightLog GUI Manual

This project now includes a Streamlit frontend so you can analyze logs in a browser on localhost.

## 1. Install requirements

From the project root:

```bash
python -m pip install streamlit
```

## 2. Start the GUI

Run:

```bash
streamlit run streamlit_app.py
```

Apparently in the latest version, the library now asks for your email at this point. Just skip that, by pressing enter :-)

Streamlit will print a local URL (usually `http://localhost:8501`). Strg/Ctrl + click to open it in your browser (if it does not auto-open).

## 3. Upload a log file

In the page:

1. Choose the service (`nginx`, `apache2`, or `auth`)
2. Drag and drop a log file (or click to select one)

## 4. Add filters (optional)

- `Pattern`: text or regex to match
- `Regex`: treat pattern as regex
- `Case-sensitive`: match exact case
- `Reverse match`: exclude lines that match pattern

## 5. Analyze

Click **Analyze**.

The app will parse the file and show results in a table.

## 6. Download results

Use the download buttons to export parsed results as:

- JSON
- CSV
