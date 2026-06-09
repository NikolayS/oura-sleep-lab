# Oura Sleep Lab

Private-first tooling for one-off and repeatable sleep analysis from Oura data.

## Goal

Build a compact analysis pipeline for six-plus months of Oura sleep data:

- baseline sleep duration, efficiency, latency, wake time, REM, and deep sleep
- HRV, resting heart rate, body temperature, and readiness trends
- weekday/weekend drift and bedtime consistency
- outliers and likely drivers of bad nights
- short actionable reports without wellness filler

## Data Access

Oura API V2 uses OAuth2. Personal access tokens are no longer available, so the
clean path is to create an OAuth API application in Oura Cloud and authorize it.

Create an application:

1. Sign in at https://cloud.ouraring.com
2. Open API Applications.
3. Create a new app.
4. Use a local redirect URI for analysis, for example:

   `http://localhost:8765/callback`

5. Keep the client secret private. Do not commit it.

For first analysis, the useful scopes are:

- `daily`
- `heartrate`
- `spo2`
- `workout`
- `tag`
- `session`
- `personal`

## Project Shape

- `scripts/` - import and analysis scripts
- `data/raw/` - local raw Oura exports/API snapshots, ignored by git
- `reports/` - generated reports, ignored by git

## Status

Initial scaffold. Analysis scripts will be added once the data access path is
chosen.
