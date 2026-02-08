import os
import time
import base64
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Polar Connect Backend", version="1.0.0")

# -------------------------
# Config (Render Env Vars)
# -------------------------
POLAR_CLIENT_ID = os.environ.get("POLAR_CLIENT_ID", "")
POLAR_CLIENT_SECRET = os.environ.get("POLAR_CLIENT_SECRET", "")
POLAR_REDIRECT_URI = os.environ.get("POLAR_REDIRECT_URI", "")
BASE_URL = os.environ.get("BASE_URL", "")  # e.g. https://polar-connect.onrender.com

# For personal-use simplicity: store tokens in memory.
# IMPORTANT: Render instances can restart => you should use a DB for real usage.
TOKEN_STORE = {
    "access_token": None,
    "refresh_token": None,
    "expires_at": 0,  # unix epoch seconds
    "connected": False,
}

# -------------------------
# Helpers
# -------------------------
def _require_config():
    missing = []
    if not POLAR_CLIENT_ID: missing.append("POLAR_CLIENT_ID")
    if not POLAR_CLIENT_SECRET: missing.append("POLAR_CLIENT_SECRET")
    if not POLAR_REDIRECT_URI: missing.append("POLAR_REDIRECT_URI")
    if missing:
        raise HTTPException(status_code=500, detail=f"Missing env vars: {', '.join(missing)}")

def _basic_auth_header(client_id: str, client_secret: str) -> str:
    token = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"

def _is_token_valid() -> bool:
    # Add ~60s buffer
    return TOKEN_STORE["access_token"] is not None and time.time() < (TOKEN_STORE["expires_at"] - 60)

def _refresh_token_if_needed():
    if _is_token_valid():
        return

    if not TOKEN_STORE["refresh_token"]:
        raise HTTPException(status_code=401, detail="Polar not connected. Visit /auth/polar/start to connect.")

    _require_config()

    resp = requests.post(
        "https://polarremote.com/v2/oauth2/token",
        headers={
            "Authorization": _basic_auth_header(POLAR_CLIENT_ID, POLAR_CLIENT_SECRET),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "refresh_token",
            "refresh_token": TOKEN_STORE["refresh_token"],
        },
        timeout=20,
    )
    data = resp.json()
    if resp.status_code >= 400:
        raise HTTPException(status_code=400, detail={"refresh_failed": data})

    TOKEN_STORE["access_token"] = data.get("access_token")
    # Polar may or may not return a new refresh token; keep existing if absent
    TOKEN_STORE["refresh_token"] = data.get("refresh_token") or TOKEN_STORE["refresh_token"]
    expires_in = int(data.get("expires_in", 0))
    TOKEN_STORE["expires_at"] = int(time.time()) + expires_in
    TOKEN_STORE["connected"] = True


# -------------------------
# Health/Status
# -------------------------
@app.get("/polar/status")
def polar_status():
    return {
        "connected": bool(TOKEN_STORE["connected"]),
        "has_access_token": TOKEN_STORE["access_token"] is not None,
        "expires_at": TOKEN_STORE["expires_at"],
    }

@app.get("/")
def root():
    return {"ok": True, "service": "polar-connect-backend"}


# -------------------------
# OAuth endpoints
# -------------------------
@app.get("/auth/polar/start")
from urllib.parse import urlencode
from fastapi.responses import RedirectResponse

@app.get("/auth/polar/start")
def polar_oauth_start():
    _require_config()
    state = f"personal:{int(time.time())}"

    query = urlencode({
        "response_type": "code",
        "client_id": POLAR_CLIENT_ID,
        "redirect_uri": POLAR_REDIRECT_URI,
        "state": state,
    })

    url = f"https://flow.polar.com/oauth2/authorization?{query}"
    return RedirectResponse(url)


@app.get("/auth/polar/callback")
def polar_oauth_callback(request: Request):
    """
    Polar redirects here with ?code=...
    We exchange code for tokens and store them.
    """
    _require_config()

    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code in callback.")

    resp = requests.post(
        "https://polarremote.com/v2/oauth2/token",
        headers={
            "Authorization": _basic_auth_header(POLAR_CLIENT_ID, POLAR_CLIENT_SECRET),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": POLAR_REDIRECT_URI,
        },
        timeout=20,
    )
    data = resp.json()
    if resp.status_code >= 400:
        raise HTTPException(status_code=400, detail={"token_exchange_failed": data})

    TOKEN_STORE["access_token"] = data.get("access_token")
    TOKEN_STORE["refresh_token"] = data.get("refresh_token")
    expires_in = int(data.get("expires_in", 0))
    TOKEN_STORE["expires_at"] = int(time.time()) + expires_in
    TOKEN_STORE["connected"] = True

    # Nice human-readable response
    return {
        "ok": True,
        "message": "Polar connected! You can now call /polar/today, /polar/workouts, /polar/sleep.",
    }


# -------------------------
# Example data endpoints (stubbed)
# Replace these with real calls to Polar AccessLink resources you need.
# -------------------------
@app.get("/polar/today")
def polar_today():
    _refresh_token_if_needed()
    # TODO: Replace with your actual Polar data pull / cached result
    return {
        "date": time.strftime("%Y-%m-%d"),
        "steps": None,
        "calories": None,
        "activeMinutes": None,
        "distanceMeters": None,
        "notes": "Stub response. Wire this to your Polar ingestion logic."
    }

@app.get("/polar/sleep")
def polar_sleep(date: str):
    _refresh_token_if_needed()
    return {
        "date": date,
        "sleepSeconds": None,
        "bedtime": None,
        "waketime": None,
        "efficiency": None,
        "score": None,
        "notes": "Stub response. Wire this to Polar sleep endpoint/feeds."
    }

@app.get("/polar/workouts")
def polar_workouts(from_date: str, to: str, limit: int = 50):
    _refresh_token_if_needed()
    return {
        "workouts": [],
        "notes": "Stub response. Wire this to your Polar training data pull."
    }

@app.get("/polar/workouts/{workout_id}")
def polar_workout_by_id(workout_id: str):
    _refresh_token_if_needed()
    return {
        "id": workout_id,
        "startTime": None,
        "endTime": None,
        "type": None,
        "durationSeconds": None,
        "calories": None,
        "distanceMeters": None,
        "avgHr": None,
        "maxHr": None
    }

@app.post("/polar/sync")
def polar_sync(payload: Optional[dict] = None):
    _refresh_token_if_needed()
    # TODO: optionally trigger a background sync job; for now, just acknowledge
    return {"ok": True, "message": "Sync triggered (stub)."}

