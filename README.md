# Log Guardian

Log Guardian is a Python tool that scans log files and flags suspicious activity like brute force login attempts, sensitive file access, and suspicious command patterns.

## Features
- Brute force login attempt detection (counts failures by IP)
- Keyword based alerts for suspicious activity
- Writes results to `output/report.txt` and `output/report.json`

## Project structure
- `src/log_guardian.py` main script
- `data/sample.log` sample input log
- `output/` generated reports (created when you run the tool)

## How to run
```bash
python3 src/log_guardian.py -f data/sample.log -o output
