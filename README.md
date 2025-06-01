# AbuseIPDB Bulk IP Checker

A simple tool to bulk query IPs against AbuseIPDB and export results to Excel.

## Requirements

- Python 3.x
- AbuseIPDB API key

## Setup

1. Clone the repo:

```bash
git clone https://github.com/YOURUSERNAME/YOURREPO.git
cd YOURREPO
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file and add your AbuseIPDB API key:

```bash
ABUSEIPDB_APIKEY=your_api_key_here
```

## Usage

```bash
python abuseipdbbulkcheck.py path/to/iplist.txt
```

Optional: use `--max-age` to set report age window (default: 90 days).

## Notes

- Your `.env` file and any result `.xlsx` files are ignored via `.gitignore`.
- Do **NOT** commit your API key.
