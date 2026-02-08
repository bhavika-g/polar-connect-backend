import os
import time
import base64
from typing import Optional, Any, Dict, List
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Polar Connect Backend", version="1.0.0")

POLAR_CLIENT_ID = os.environ.get("POLAR_CLIENT_ID", "")
POLAR_CLIENT_SECRET = os.environ.get("POLAR_CLIENT_SECRET", "")
POLAR_REDIRECT_URI = os.environ.get("POLAR_REDIRECT_URI", "")
BASE_URL = os.environ.get("BASE_URL", "")  # optional

TOKEN_STORE: Dict[str, Any] = {
    "access_token": None,
    "refresh_token": None,
    "expires_at": 0,  # unix seconds
    "connected": False,
    "polar_user_id": None,  # returned by Register User
}


# -------------------------
# Helpers
# -------------------------
def _require_config():
    missing = []
    if not POLAR_CLIENT_ID:
        missing.append("POLAR_CLIENT_ID")
    if not POLAR_CLIENT_SECRET:
        missing.append("POLAR_CLIENT_SECRET")
    if not POLAR_REDIRECT_URI:
        missing.append("POLAR_REDIRECT_URI")
    if missing:
        raise HTTPException(status_code=500, detail=f"Missing env vars: {', '.join(missing)}")


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    token = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"


def _polar_headers_json() -> Dict[str, str]:
    if not TOKEN_STORE["access_token"]:
        raise HTTPException(status_code=401, detail="No access token; connect Polar first.")
    return {
        "Authorization": f"Bearer {TOKEN_STORE['access_token']}",
        "Accept": "application/json",
    }


def _is_token_valid() -> bool:
    # 60s safety buffer
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
    TOKEN_STORE["refresh_token"] = data.get("refresh_token") or TOKEN_STORE["refresh_token"]
    expires_in = int(data.get("expires_in", 0))
    TOKEN_STORE["expires_at"] = int(time.time()) + expires_in
    TOKEN_STORE["connected"] = True


def _register_user_if_needed() -> Optional[str]:
    """
    REQUIRED by Polar 'How to get started' step 7.
    POST /v3/users with Bearer access-token. Content-Type: application/xml, Accept: application/json.
    409 = already registered.
    """
    # If we already have a user id stored, assume registration done.
    if TOKEN_STORE.get("polar_user_id"):
        return TOKEN_STORE["polar_user_id"]

    r = requests.post(
        "https://www.polaraccesslink.com/v3/users",
        headers={
            "Authorization": f"Bearer {TOKEN_STORE['access_token']}",
            "Accept": "application/json",
            "Content-Type": "application/xml",
        },
        data="",  # empty body per docs example
        timeout=20,
    )

    if r.status_code == 409:
        # Already registered; Polar may not return user-id here.
        # In a real implementation you would persist user-id on first successful registration.
        return TOKEN_STORE.get("polar_user_id")

    if r.status_code >= 400:
        try:
            raise HTTPException(status_code=400, detail={"register_user_failed": r.json()})
        except Exception:
            raise HTTPException(status_code=400, detail={"register_user_failed": r.text})

    data = r.json()
    user_id = data.get("user-id") or data.get("user_id") or data.get("id")
    TOKEN_STORE["polar_user_id"] = user_id
    return user_id


def _date_in_range(date_yyyy_mm_dd: str, start: str, end: str) -> bool:
    # Lexicographic compare works for YYYY-MM-DD
    return (date_yyyy_mm_dd >= start) and (date_yyyy_mm_dd <= end)


# -------------------------
# Status
# -------------------------
@app.get("/polar/status")
def polar_status():
    return {
        "connected": bool(TOKEN_STORE["connected"]),
        "has_access_token": TOKEN_STORE["access_token"] is not None,
        "expires_at": TOKEN_STORE["expires_at"],
        "expires_in": max(0, int(TOKEN_STORE["expires_at"] - time.time())),
        "polar_user_id": TOKEN_STORE.get("polar_user_id"),
    }


@app.get("/")
def root():
    return {"ok": True, "service": "polar-connect-backend"}


# -------------------------
# OAuth endpoints
# -------------------------
@app.get("/auth/polar/start")
def polar_oauth_start():
    _require_config()
    state = f"personal:{int(time.time())}"

    query = urlencode(
        {
            "response_type": "code",
            "client_id": POLAR_CLIENT_ID,
            "redirect_uri": POLAR_REDIRECT_URI,
            "state": state,
        }
    )
    url = f"https://flow.polar.com/oauth2/authorization?{query}"
    return RedirectResponse(url)


@app.get("/auth/polar/callback")
def polar_oauth_callback(request: Request):
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

    # REQUIRED: register user so you can access data (Polar docs step 7)
    try:
        _register_user_if_needed()
    except HTTPException:
        # If registration fails, keep tokens but report problem
        return {
            "ok": False,
            "message": "OAuth succeeded but user registration failed. Check /polar/status and logs.",
            "token_expires_in": max(0, TOKEN_STORE["expires_at"] - int(time.time())),
        }

    return {
        "ok": True,
        "message": "Polar connected & user registered. You can now call /polar/workouts, /polar/sleep, etc.",
        "token_expires_in": max(0, TOKEN_STORE["expires_at"] - int(time.time())),
        "polar_user_id": TOKEN_STORE.get("polar_user_id"),
    }


# -------------------------
# Real workouts via v3 Exercises endpoints (non-deprecated)
# -------------------------
@app.get("/polar/workouts")
def polar_workouts(
    # Accept BOTH styles:
    from_date: Optional[str] = Query(None, alias="from_date"),
    from_alias: Optional[str] = Query(None, alias="from"),
    to: str = Query(...),
    limit: int = Query(50, ge=1, le=200),
):
    _refresh_token_if_needed()

    start = from_alias or from_date
    if not start:
        raise HTTPException(status_code=422, detail="Missing required query parameter: from_date (or from).")

    # Ensure user registration happened (required)
    _register_user_if_needed()

    # 1) List exercises (returns exercise IDs)
    list_resp = requests.get(
        "https://www.polaraccesslink.com/v3/exercises",
        headers=_polar_headers_json(),
        timeout=20,
    )
    if list_resp.status_code >= 400:
        raise HTTPException(status_code=list_resp.status_code, detail={"list_exercises_failed": list_resp.text})

    listing = list_resp.json()
    exercises = listing.get("exercises", [])

    workouts: List[Dict[str, Any]] = []

    # 2) Fetch details for each exercise and filter by date window
    # Docs define "Get exercise" endpoint under Exercises. :contentReference[oaicite:6]{index=6}
    for ex in exercises:
        ex_id = ex.get("id") or ex.get("exerciseId") or ex.get("exercise_id")
        if not ex_id:
            continue

        d_resp = requests.get(
            f"https://www.polaraccesslink.com/v3/exercises/{ex_id}",
            headers=_polar_headers_json(),
            timeout=20,
        )
        if d_resp.status_code >= 400:
            # skip bad items rather than failing whole request
            continue

        d = d_resp.json()

        # Start time fields can vary; keep robust
        start_time = d.get("start-time") or d.get("start_time") or d.get("startTime")
        if start_time:
            date_part = str(start_time)[:10]
            if not _date_in_range(date_part, start, to):
                continue

        workouts.append(
            {
                "id": str(ex_id),
                "startTime": start_time,
                "type": d.get("sport") or d.get("sport-id") or d.get("sportId"),
                "durationSeconds": d.get("duration") or d.get("durationSeconds") or d.get("duration_seconds"),
                "calories": d.get("calories"),
                "distanceMeters": d.get("distance") or d.get("distanceMeters"),
                # heart-rate object in schema exists; be defensive
                "avgHr": (d.get("heart-rate") or {}).get("average") if isinstance(d.get("heart-rate"), dict) else d.get("avgHr"),
                "maxHr": (d.get("heart-rate") or {}).get("maximum") if isinstance(d.get("heart-rate"), dict) else d.get("maxHr"),
                # Uncomment for one round of debugging:
                # "raw": d,
            }
        )

        if len(workouts) >= limit:
            break

    return {"workouts": workouts, "from": start, "to": to, "count": len(workouts)}


# -------------------------
# Sleep endpoints are still stubs here; implement with /v3/users/sleep etc later
# -------------------------
@app.get("/polar/sleep")
def polar_sleep(date: str):
    _refresh_token_if_needed()
    _register_user_if_needed()
    return {
        "date": date,
        "notes": "Stub. Implement using v3 Sleep endpoints (List nights / Get sleep).",
    }


@app.post("/polar/sync")
def polar_sync(payload: Optional[dict] = None):
    _refresh_token_if_needed()
    _register_user_if_needed()
    return {"ok": True, "message": "Sync triggered (no-op stub)."}
