# InsightLog

InsightLog is a Python script for extracting and analyzing data from server log files (Nginx, Apache2, and Auth logs). It provides tools to filter, parse, and analyze common server log formats.

## Features

- Filter log files by date, IP, or custom patterns
- Extract web requests and authentication attempts from logs
- Analyze logs from Nginx, Apache2, and system Auth logs
- Filter parsed results by inferred log level (`info`, `warning`, `error`)
- Filter parsed results by datetime range (`--time-from`, `--time-to`)
- Export parsed output as plain text, JSON, or CSV

## Installation

Clone this repository:
```bash
git clone https://github.com/CyberstepsDE/insightlog.git
cd insightlog
```

You are ready to go!

## Command Line Usage

You can run the analyzer from the CLI:

```bash
python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample --filter 192.10.1.1
```

### CLI Options

- `--service`: `nginx`, `apache2`, or `auth` (required)
- `--logfile`: path to the log file (required)
- `--filter`: simple line filter before parsing (optional)
- `--log-level`: `info`, `warning`, or `error` (optional)
- `--time-from`: start datetime, inclusive, format `YYYY-MM-DD HH:MM:SS` (optional)
- `--time-to`: end datetime, inclusive, format `YYYY-MM-DD HH:MM:SS` (optional)
- `--output-format`: `text`, `json`, or `csv` (optional, default: `text`)

More examples:

- Analyze Apache2 logs for a specific IP:
  ```bash
  python3 insightlog.py --service apache2 --logfile logs-samples/apache1.sample --filter 127.0.1.1
  ```

- Analyze Auth logs for a specific string:
  ```bash
  python3 insightlog.py --service auth --logfile logs-samples/auth.sample --filter root
  ```

- Analyze all Nginx log entries (no filter):
  ```bash
  python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample
  ```

- Show only warning-level Apache2 requests (typically 4xx):
  ```bash
  python3 insightlog.py --service apache2 --logfile logs-samples/apache1.sample --log-level warning
  ```

- Limit results to a time range:
  ```bash
  python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample --time-from "2016-04-24 06:26:00" --time-to "2016-04-24 06:30:00"
  ```

- Export as JSON:
  ```bash
  python3 insightlog.py --service auth --logfile logs-samples/auth.sample --output-format json
  ```

- Export as CSV:
  ```bash
  python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample --output-format csv
  ```

- Combine filters (string + log level + time range + output format):
  ```bash
  python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample --filter 192.10.1.1 --log-level info --time-from "2016-04-24 06:26:00" --time-to "2016-04-24 06:27:00" --output-format json
  ```

## Known Bugs

See [KNOWN_BUGS.md](KNOWN_BUGS.md) for a list of current bugs and how to replicate them.

## Planned Features

See [ROADMAP.md](ROADMAP.md) for planned features and improvements.

## Running Tests

We use Python's built-in `unittest` module for testing. To run the tests:

```bash
python3 -m unittest discover -s tests -v
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
