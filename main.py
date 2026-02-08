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

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
POLAR_CLIENT_ID = os.environ.get("POLAR_CLIENT_ID", "")
POLAR_CLIENT_SECRET = os.environ.get("POLAR_CLIENT_SECRET", "")
POLAR_REDIRECT_URI = os.environ.get("POLAR_REDIRECT_URI", "")
POLAR_MEMBER_ID = os.environ.get("POLAR_MEMBER_ID", "personal_user")

TOKEN_STORE: Dict[str, Any] = {
    "access_token": None,
    "refresh_token": None,
    "expires_at": 0,
    "connected": False,
    "polar_user_id": None,
}

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
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
    token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return f"Basic {token}"


def _polar_headers():
    if not TOKEN_STORE["access_token"]:
        raise HTTPException(status_code=401, detail="No access token")
    return {
        "Authorization": f"Bearer {TOKEN_STORE['access_token']}",
        "Accept": "application/json",
    }


def _is_token_valid() -> bool:
    return TOKEN_STORE["access_token"] and time.time() < (TOKEN_STORE["expires_at"] - 60)


def _refresh_token_if_needed():
    if _is_token_valid():
        return

    if not TOKEN_STORE["refresh_token"]:
        raise HTTPException(status_code=401, detail="Polar not connected")

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

    TOKEN_STORE["access_token"] = data["access_token"]
    TOKEN_STORE["refresh_token"] = data.get("refresh_token") or TOKEN_STORE["refresh_token"]
    TOKEN_STORE["expires_at"] = int(time.time()) + int(data.get("expires_in", 0))
    TOKEN_STORE["connected"] = True


def _register_user_if_needed():
    """
    REQUIRED by Polar AccessLink.
    POST /v3/users with member-id in body.
    """
    if TOKEN_STORE.get("polar_user_id"):
        return TOKEN_STORE["polar_user_id"]

    r = requests.post(
        "https://www.polaraccesslink.com/v3/users",
        headers={
            "Authorization": f"Bearer {TOKEN_STORE['access_token']}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json={"member-id": POLAR_MEMBER_ID},
        timeout=20,
    )

    # 409 = already registered (OK)
    if r.status_code == 409:
        return None

    if r.status_code >= 400:
        raise HTTPException(
            status_code=400,
            detail={
                "register_user_failed": {
                    "status": r.status_code,
                    "body": r.text,
                }
            },
        )

    data = r.json()
    TOKEN_STORE["polar_user_id"] = data.get("polar-user-id") or data.get("polar_user_id")
    return TOKEN_STORE["polar_user_id"]


def _date_in_range(date: str, start: str, end: str) -> bool:
    return start <= date <= end


# -------------------------------------------------------------------
# Status
# -------------------------------------------------------------------
@app.get("/polar/status")
def polar_status():
    return {
        "connected": TOKEN_STORE["connected"],
        "has_access_token": bool(TOKEN_STORE["access_token"]),
        "expires_in": max(0, int(TOKEN_STORE["expires_at"] - time.time())),
        "polar_user_id": TOKEN_STORE.get("polar_user_id"),
    }


@app.get("/")
def root():
    return {"ok": True}


# -------------------------------------------------------------------
# OAuth
# -------------------------------------------------------------------
@app.get("/auth/polar/start")
def polar_oauth_start():
    try:
        _require_config()
    except HTTPException as e:
        return {"ok": False, "error": e.detail}

    query = urlencode(
        {
            "response_type": "code",
            "client_id": POLAR_CLIENT_ID,
            "redirect_uri": POLAR_REDIRECT_URI,
            "state": f"personal:{int(time.time())}",
        }
    )
    return RedirectResponse(f"https://flow.polar.com/oauth2/authorization?{query}")


@app.get("/auth/polar/callback")
def polar_oauth_callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")

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
        raise HTTPException(status_code=400, detail=data)

    TOKEN_STORE["access_token"] = data["access_token"]
    TOKEN_STORE["refresh_token"] = data.get("refresh_token")
    TOKEN_STORE["expires_at"] = int(time.time()) + int(data.get("expires_in", 0))
    TOKEN_STORE["connected"] = True

    try:
        _register_user_if_needed()
    except HTTPException as e:
        return {
            "ok": False,
            "message": "OAuth succeeded but user registration failed",
            "error": e.detail,
        }

    return {
        "ok": True,
        "message": "Polar connected and user registered",
        "polar_user_id": TOKEN_STORE.get("polar_user_id"),
    }


# -------------------------------------------------------------------
# Workouts (real endpoint stub)
# -------------------------------------------------------------------

@app.get("/polar/workouts")
def polar_workouts(
    from_date: Optional[str] = Query(None, alias="from_date"),
    from_alias: Optional[str] = Query(None, alias="from"),
    to: str = Query(...),
    limit: int = Query(50, ge=1, le=200),
):
    _refresh_token_if_needed()
    _register_user_if_needed()

    start = from_alias or from_date
    if not start:
        raise HTTPException(status_code=422, detail="Missing from_date (or from)")

    # 1) List exercises
    list_resp = requests.get(
        "https://www.polaraccesslink.com/v3/exercises",
        headers=_polar_headers(),
        timeout=20,
    )
    if list_resp.status_code >= 400:
        raise HTTPException(
            status_code=list_resp.status_code,
            detail={"list_exercises_failed": list_resp.text},
        )

    data = list_resp.json()

    # Polar may return either:
    #   - {"exercises": [...]}  (dict)
    #   - [...]                (list)
    if isinstance(data, list):
        exercises = data
    elif isinstance(data, dict):
        exercises = data.get("exercises", [])
    else:
        exercises = []

    workouts = []

    # 2) Fetch details for each exercise, filter by date range
    for ex in exercises:
        if not isinstance(ex, dict):
            continue

        ex_id = ex.get("id")
        if not ex_id:
            continue

        d_resp = requests.get(
            f"https://www.polaraccesslink.com/v3/exercises/{ex_id}",
            headers=_polar_headers(),
            timeout=20,
        )
        if d_resp.status_code >= 400:
            # Skip broken items rather than failing the whole request
            continue

        d = d_resp.json()

        start_time = d.get("start-time") or d.get("startTime") or d.get("start_time")
        if start_time:
            date_part = str(start_time)[:10]
            if not _date_in_range(date_part, start, to):
                continue

        workouts.append(
            {
                "id": ex_id,
                "startTime": start_time,
                "sport": d.get("sport"),
                "durationSeconds": d.get("duration"),
                "calories": d.get("calories"),
                "distanceMeters": d.get("distance"),
            }
        )

        if len(workouts) >= limit:
            break

    return {"workouts": workouts, "count": len(workouts), "from": start, "to": to}


# -------------------------------------------------------------------
# Sleep + Sync (stubs)
# -------------------------------------------------------------------
@app.get("/polar/sleep")
def polar_sleep(date: str):
    _refresh_token_if_needed()
    _register_user_if_needed()
    return {"date": date, "notes": "stub"}


@app.post("/polar/sync")
def polar_sync():
    _refresh_token_if_needed()
    _register_user_if_needed()
    return {"ok": True}
