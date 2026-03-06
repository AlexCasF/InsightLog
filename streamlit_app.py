import csv
import io
import json

import streamlit as st

from insightlog import get_requests


def decode_uploaded_bytes(raw_bytes):
    """Decode uploaded bytes using a small fallback chain."""
    if raw_bytes is None:
        return None
    if not raw_bytes:
        return ""

    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def records_to_csv(records):
    """Convert a list of dict records to CSV text."""
    if not records:
        return ""

    fieldnames = list(records[0].keys())
    for record in records[1:]:
        for key in record.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(records)
    return buffer.getvalue()


def main():
    st.set_page_config(page_title="InsightLog GUI", layout="wide")
    st.title("InsightLog GUI")
    st.caption("Upload a log file, apply filters, and parse requests using the existing InsightLog engine.")

    service = st.selectbox("Service", options=["nginx", "apache2", "auth"], index=0)
    uploaded_file = st.file_uploader("Drag and drop a log file here", type=["log", "sample", "txt"])

    st.subheader("Filters")
    filter_pattern = st.text_input("Pattern (optional)")
    col1, col2, col3 = st.columns(3)
    is_regex = col1.checkbox("Regex", value=False)
    is_casesensitive = col2.checkbox("Case-sensitive", value=True)
    is_reverse = col3.checkbox("Reverse match", value=False)

    analyze = st.button("Analyze", type="primary", disabled=uploaded_file is None)

    if uploaded_file is not None:
        st.write(f"Selected file: `{uploaded_file.name}` ({uploaded_file.size} bytes)")

    if not analyze:
        return

    raw_data = uploaded_file.getvalue() if uploaded_file is not None else None
    decoded_data = decode_uploaded_bytes(raw_data)
    if decoded_data is None:
        st.error("Unable to decode uploaded file.")
        return

    filters = None
    if filter_pattern:
        filters = [{
            "filter_pattern": filter_pattern,
            "is_casesensitive": is_casesensitive,
            "is_regex": is_regex,
            "is_reverse": is_reverse,
        }]

    try:
        requests = get_requests(service, data=decoded_data, filters=filters)
    except Exception as exc:
        st.error(f"Failed to analyze log: {exc}")
        return

    if requests is None:
        st.error("Analyzer returned no result due to a file/data handling error.")
        return

    if not requests:
        st.info("No matching requests found.")
        return

    st.success(f"Parsed {len(requests)} request(s).")
    st.dataframe(requests, use_container_width=True)

    json_data = json.dumps(requests, indent=2, ensure_ascii=False)
    csv_data = records_to_csv(requests)

    download_col1, download_col2 = st.columns(2)
    download_col1.download_button(
        "Download JSON",
        data=json_data,
        file_name=f"{uploaded_file.name}.json",
        mime="application/json",
    )
    download_col2.download_button(
        "Download CSV",
        data=csv_data,
        file_name=f"{uploaded_file.name}.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
