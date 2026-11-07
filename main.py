import asyncio
import json
import os
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from database import get_conn, init_db, now_iso
from telegram_engine import (
    PENDING_LOGINS,
    campaign_scheduler_loop,
    confirm_2fa_password,
    confirm_phone_code,
    fetch_saved_messages,
    start_phone_login,
    start_qr_login,
    sync_account_destinations,
)

init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(campaign_scheduler_loop())
    yield
    task.cancel()


app = FastAPI(title="TeleCampaign Pro VPS", lifespan=lifespan)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ==================== MODELS ====================
class AccountCreate(BaseModel):
    name: str
    phone: str = ""
    api_id: int = 2040
    api_hash: str = "b18441a1ff607e10a989891a5462e627"
    session_string: str = ""
    proxy_id: Optional[int] = None
    daily_quota: int = 1500


class CodeConfirm(BaseModel):
    code: str
    password: Optional[str] = None


class PasswordConfirm(BaseModel):
    password: str


class ProxyCreate(BaseModel):
    name: str
    proxy_type: str = "socks5"
    host: str
    port: int
    username: str = ""
    password: str = ""


class TemplateCreate(BaseModel):
    name: str
    mode: str = "text"
    content: str = ""
    parse_mode: str = "html"
    source_account_id: Optional[int] = None
    source_message_id: Optional[int] = None


class CampaignCreate(BaseModel):
    name: str
    account_id: int
    template_id: int
    destination_ids: List[int]
    repeat_count: int = 300
    round_delay_min_seconds: int = 15
    round_delay_max_seconds: int = 45
    group_interval_minutes: int = 10
    simulate_typing: int = 1
    scheduled_at: Optional[str] = None


class CampaignStatusUpdate(BaseModel):
    status: str


class DestinationCategoryUpdate(BaseModel):
    category: str
    allow_forwards: Optional[int] = None


# ==================== DASHBOARD OVERVIEW ====================
@app.get("/")
async def index_page():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/dashboard")
async def get_dashboard():
    conn = get_conn()
    accounts_total = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    accounts_connected = conn.execute("SELECT COUNT(*) FROM accounts WHERE status = 'connected'").fetchone()[0]
    groups_total = conn.execute("SELECT COUNT(*) FROM destinations").fetchone()[0]
    groups_can_post = conn.execute("SELECT COUNT(*) FROM destinations WHERE can_post = 1").fetchone()[0]
    campaigns_running = conn.execute("SELECT COUNT(*) FROM campaigns WHERE status = 'running'").fetchone()[0]
    campaigns_total = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    sent_total = conn.execute("SELECT COALESCE(SUM(total_sent), 0) FROM campaigns").fetchone()[0]
    failed_total = conn.execute("SELECT COALESCE(SUM(total_failed), 0) FROM campaigns").fetchone()[0]
    recent_logs = [
        dict(r)
        for r in conn.execute("SELECT * FROM delivery_logs ORDER BY id DESC LIMIT 25").fetchall()
    ]
    conn.close()
    return {
        "accounts_total": accounts_total,
        "accounts_connected": accounts_connected,
        "groups_total": groups_total,
        "groups_can_post": groups_can_post,
        "campaigns_running": campaigns_running,
        "campaigns_total": campaigns_total,
        "sent_total": sent_total,
        "failed_total": failed_total,
        "recent_logs": recent_logs,
    }


# ==================== TELEGRAM ACCOUNTS ====================
@app.get("/api/telegram/accounts")
async def list_accounts():
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT a.*, p.name as proxy_name, p.host as proxy_host, p.port as proxy_port,
        (SELECT COUNT(*) FROM destinations d WHERE d.account_id = a.id) as group_count,
        (SELECT COUNT(*) FROM destinations d WHERE d.account_id = a.id AND d.can_post = 1) as writable_group_count
        FROM accounts a
        LEFT JOIN proxies p ON a.proxy_id = p.id
        ORDER BY a.id DESC
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/telegram/accounts")
async def create_account(payload: AccountCreate):
    conn = get_conn()
    status = "connected" if payload.session_string.strip() else "disconnected"
    cur = conn.execute(
        """
        INSERT INTO accounts (name, phone, api_id, api_hash, session_string, proxy_id, status, daily_quota, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload.name.strip() or "Telegram Account",
            payload.phone.strip(),
            payload.api_id,
            payload.api_hash.strip(),
            payload.session_string.strip(),
            payload.proxy_id,
            status,
            payload.daily_quota,
            now_iso(),
        ),
    )
    acc_id = cur.lastrowid
    conn.commit()
    conn.close()
    return {"id": acc_id, "status": status}


@app.delete("/api/telegram/accounts/{account_id}")
async def delete_account(account_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM destinations WHERE account_id = ?", (account_id,))
    conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}


@app.post("/api/telegram/accounts/{account_id}/login")
async def login_phone(account_id: int):
    try:
        return await start_phone_login(account_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/telegram/accounts/{account_id}/login/code")
async def login_code(account_id: int, payload: CodeConfirm):
    try:
        return await confirm_phone_code(account_id, payload.code, payload.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/telegram/accounts/{account_id}/login/password")
async def login_password(account_id: int, payload: PasswordConfirm):
    try:
        return await confirm_2fa_password(account_id, payload.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/telegram/accounts/{account_id}/login/qr")
async def login_qr(account_id: int):
    try:
        return await start_qr_login(account_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/telegram/accounts/{account_id}/login/qr/status")
async def login_qr_status(account_id: int):
    pending = PENDING_LOGINS.get(account_id)
    conn = get_conn()
    acc = conn.execute("SELECT status, phone, username, name FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    if acc and acc["status"] == "connected":
        return {"status": "connected", "account": dict(acc)}
    if pending:
        return {"status": pending.get("status", "waiting_qr")}
    return {"status": acc["status"] if acc else "disconnected"}


@app.post("/api/telegram/accounts/{account_id}/sync")
async def sync_destinations(account_id: int, deep_scan: bool = False):
    try:
        return await sync_account_destinations(account_id, deep_scan=deep_scan)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/destinations/auto-scan")
async def auto_scan_all_destinations():
    """Deep-scans all connected Telegram accounts' groups (permissions, slowmode, description & pinned rules) and assigns tags & categories."""
    conn = get_conn()
    accs = conn.execute("SELECT id FROM accounts WHERE status = 'connected'").fetchall()
    conn.close()
    if not accs:
        raise HTTPException(status_code=400, detail="No connected Telegram account found.")
    total_scanned = 0
    for a in accs:
        res = await sync_account_destinations(a["id"], deep_scan=True)
        total_scanned += res.get("count", 0)
    return {"scanned": total_scanned}


@app.patch("/api/destinations/{dest_id}")
async def update_destination_category(dest_id: int, payload: DestinationCategoryUpdate):
    conn = get_conn()
    allow_fwd = 0 if payload.category == "no_forward" else (payload.allow_forwards if payload.allow_forwards is not None else 1)
    conn.execute(
        "UPDATE destinations SET category = ?, allow_forwards = ? WHERE id = ?",
        (payload.category, allow_fwd, dest_id),
    )
    conn.commit()
    conn.close()
    return {"id": dest_id, "category": payload.category}


@app.get("/api/telegram/accounts/{account_id}/saved-messages")
async def get_saved_messages(account_id: int):
    try:
        return await fetch_saved_messages(account_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ==================== DESTINATIONS ====================
@app.get("/api/destinations")
async def list_destinations(account_id: Optional[int] = None):
    conn = get_conn()
    if account_id:
        rows = conn.execute(
            "SELECT d.*, a.name as account_name FROM destinations d LEFT JOIN accounts a ON d.account_id = a.id WHERE d.account_id = ? ORDER BY d.can_post DESC, d.title ASC",
            (account_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT d.*, a.name as account_name FROM destinations d LEFT JOIN accounts a ON d.account_id = a.id ORDER BY d.can_post DESC, d.title ASC"
        ).fetchall()
    conn.close()
    res = []
    for r in rows:
        d = dict(r)
        try:
            d["auto_tags"] = json.loads(d.get("auto_tags") or '["standard"]')
        except Exception:
            d["auto_tags"] = ["standard"]
        res.append(d)
    return res


# ==================== TEMPLATES ====================
@app.get("/api/message-templates")
async def list_templates():
    conn = get_conn()
    rows = conn.execute(
        "SELECT t.*, a.name as source_account_name FROM templates t LEFT JOIN accounts a ON t.source_account_id = a.id ORDER BY t.id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/message-templates")
async def create_template(payload: TemplateCreate):
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO templates (name, mode, content, parse_mode, source_account_id, source_message_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload.name.strip(),
            payload.mode,
            payload.content,
            payload.parse_mode,
            payload.source_account_id,
            payload.source_message_id,
            now_iso(),
        ),
    )
    tid = cur.lastrowid
    conn.commit()
    conn.close()
    return {"id": tid}


@app.delete("/api/message-templates/{template_id}")
async def delete_template(template_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}


# ==================== CAMPAIGNS ====================
@app.get("/api/campaigns")
async def list_campaigns():
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT c.*, a.name as account_name, a.phone as account_phone, t.name as template_name, t.mode as template_mode
        FROM campaigns c
        LEFT JOIN accounts a ON c.account_id = a.id
        LEFT JOIN templates t ON c.template_id = t.id
        ORDER BY c.id DESC
        """
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["destination_ids"] = json.loads(d["destination_ids"] or "[]")
        result.append(d)
    return result


@app.post("/api/campaigns")
async def create_campaign(payload: CampaignCreate):
    if payload.round_delay_min_seconds > payload.round_delay_max_seconds:
        raise HTTPException(status_code=400, detail="Minimum delay cannot exceed maximum delay.")
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO campaigns (
            name, account_id, template_id, destination_ids, repeat_count,
            round_delay_min_seconds, round_delay_max_seconds, group_interval_seconds,
            simulate_typing, scheduled_at, next_run_at, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?)
        """,
        (
            payload.name.strip(),
            payload.account_id,
            payload.template_id,
            json.dumps(payload.destination_ids),
            payload.repeat_count,
            payload.round_delay_min_seconds,
            payload.round_delay_max_seconds,
            payload.group_interval_minutes * 60,
            payload.simulate_typing,
            payload.scheduled_at,
            payload.scheduled_at or now_iso(),
            now_iso(),
        ),
    )
    cid = cur.lastrowid
    conn.commit()
    conn.close()
    return {"id": cid, "status": "running"}


@app.patch("/api/campaigns/{campaign_id}")
async def update_campaign_status(campaign_id: int, payload: CampaignStatusUpdate):
    conn = get_conn()
    if payload.status == "running":
        conn.execute(
            "UPDATE campaigns SET status = 'running', next_run_at = ?, current_round = CASE WHEN status = 'completed' THEN 0 ELSE current_round END WHERE id = ?",
            (now_iso(), campaign_id),
        )
    else:
        conn.execute("UPDATE campaigns SET status = ? WHERE id = ?", (payload.status, campaign_id))
    conn.commit()
    conn.close()
    return {"id": campaign_id, "status": payload.status}


@app.post("/api/campaigns/{campaign_id}/clone")
async def clone_campaign(campaign_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Campaign not found")
    c = dict(row)
    cur = conn.execute(
        """
        INSERT INTO campaigns (
            name, account_id, template_id, destination_ids, repeat_count,
            round_delay_min_seconds, round_delay_max_seconds, group_interval_seconds,
            simulate_typing, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paused', ?)
        """,
        (
            f"{c['name']} (Copy)",
            c["account_id"],
            c["template_id"],
            c["destination_ids"],
            c["repeat_count"],
            c["round_delay_min_seconds"],
            c["round_delay_max_seconds"],
            c["group_interval_seconds"],
            c["simulate_typing"],
            now_iso(),
        ),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return {"id": new_id}


@app.delete("/api/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}


# ==================== PROXIES ====================
@app.get("/api/proxies")
async def list_proxies():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM proxies ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/proxies")
async def create_proxy(payload: ProxyCreate):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO proxies (name, proxy_type, host, port, username, password, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            payload.name.strip(),
            payload.proxy_type,
            payload.host.strip(),
            payload.port,
            payload.username.strip(),
            payload.password.strip(),
            now_iso(),
        ),
    )
    pid = cur.lastrowid
    conn.commit()
    conn.close()
    return {"id": pid}


@app.post("/api/proxies/{proxy_id}/test")
async def test_proxy(proxy_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Proxy not found")
    p = dict(row)
    try:
        sock = socket.create_connection((p["host"], int(p["port"])), timeout=5)
        sock.close()
        status = "online"
    except Exception:
        status = "offline"
    conn.execute("UPDATE proxies SET status = ? WHERE id = ?", (status, proxy_id))
    conn.commit()
    conn.close()
    return {"id": proxy_id, "status": status}


@app.delete("/api/proxies/{proxy_id}")
async def delete_proxy(proxy_id: int):
    conn = get_conn()
    conn.execute("UPDATE accounts SET proxy_id = NULL WHERE proxy_id = ?", (proxy_id,))
    conn.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}


# ==================== ACTIVITY LOGS ====================
@app.get("/api/activity")
async def list_activity():
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT l.*, c.name as campaign_name, a.name as account_name
        FROM delivery_logs l
        LEFT JOIN campaigns c ON l.campaign_id = c.id
        LEFT JOIN accounts a ON l.account_id = a.id
        ORDER BY l.id DESC LIMIT 200
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=9095, reload=False)
