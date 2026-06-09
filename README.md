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

- `extapi:daily`
- `extapi:heartrate`
- `extapi:spo2`
- `extapi:workout`
- `extapi:tag`
- `extapi:session`
- `extapi:personal`

## Project Shape

- `scripts/` - import and analysis scripts
- `data/raw/` - local raw Oura exports/API snapshots, ignored by git
- `data/tokens/` - local OAuth tokens, ignored by git
- `reports/` - generated reports, ignored by git

## OAuth Helper

Create `.env` from `.env.example` and fill in the Oura OAuth application
credentials.

Print an authorization URL:

```bash
python3 scripts/oura_auth.py url
```

The helper uses Oura's OAuth issuer discovery document by default. If Oura
changes endpoints again, override with `OURA_AUTHORIZE_URL` and
`OURA_TOKEN_URL`.

If the browser runs on the same machine:

```bash
python3 scripts/oura_auth.py listen
```

If authorizing from another machine, copy the final localhost callback URL from
the browser address bar and exchange it locally:

```bash
python3 scripts/oura_auth.py exchange --callback-url 'http://localhost:8765/callback?code=...&state=...'
```

## Status

Initial scaffold with OAuth helper. Analysis scripts will be added once the
first Oura data snapshot is available.
