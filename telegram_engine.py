import asyncio
import base64
import io
import json
import random
import re
import traceback
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List

import qrcode
from telethon import TelegramClient, functions, types
from telethon.sessions import StringSession
from telethon.errors import (
    SessionPasswordNeededError,
    FloodWaitError,
    SlowModeWaitError,
    ChatWriteForbiddenError,
    UserBannedInChannelError,
    ChannelPrivateError,
    PeerFloodError,
    ChatAdminRequiredError,
    ChatForwardsRestrictedError,
)

from database import get_conn, now_iso

# Active Telethon clients cache: { account_id: TelegramClient }
ACTIVE_CLIENTS: Dict[int, TelegramClient] = {}
# Pending login state: { account_id: {"client": TelegramClient, "phone_code_hash": str, "qr_login": Any} }
PENDING_LOGINS: Dict[int, Dict[str, Any]] = {}


def parse_spintax(text: str) -> str:
    """Evaluates nested {option1|option2|option3} spintax and dynamic variables for anti-spam."""
    if not text:
        return ""
    pattern = re.compile(r"\{([^{}]*)\}")
    while True:
        match = pattern.search(text)
        if not match:
            break
        options = match.group(1).split("|")
        text = text[:match.start()] + random.choice(options) + text[match.end():]
    text = text.replace("{{time}}", datetime.now().strftime("%H:%M"))
    text = text.replace("{{date}}", datetime.now().strftime("%Y-%m-%d"))
    text = text.replace("{{rand}}", str(random.randint(1000, 9999)))
    return text


def get_proxy_dict(proxy_id: Optional[int]) -> Optional[dict]:
    if not proxy_id:
        return None
    conn = get_conn()
    row = conn.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)).fetchone()
    conn.close()
    if not row:
        return None
    p = dict(row)
    proxy_cfg = {
        "proxy_type": p["proxy_type"].lower(),
        "addr": p["host"],
        "port": int(p["port"]),
        "rdns": True,
    }
    if p.get("username"):
        proxy_cfg["username"] = p["username"]
    if p.get("password"):
        proxy_cfg["password"] = p["password"]
    return proxy_cfg


async def get_or_create_client(account_id: int) -> TelegramClient:
    if account_id in ACTIVE_CLIENTS:
        client = ACTIVE_CLIENTS[account_id]
        if not client.is_connected():
            await client.connect()
        return client

    conn = get_conn()
    acc = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    if not acc:
        raise ValueError(f"Account {account_id} not found")

    proxy_cfg = get_proxy_dict(acc["proxy_id"])
    client = TelegramClient(
        StringSession(acc["session_string"] or ""),
        int(acc["api_id"]),
        acc["api_hash"],
        proxy=proxy_cfg,
        device_model="TeleCampaign VPS Pro",
        system_version="Linux 6.1 LTS",
        app_version="4.16.8 x64",
        lang_code="en",
        system_lang_code="en-US",
    )
    await client.connect()
    ACTIVE_CLIENTS[account_id] = client
    return client


async def start_phone_login(account_id: int) -> dict:
    conn = get_conn()
    acc = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    if not acc:
        raise ValueError("Account not found")

    proxy_cfg = get_proxy_dict(acc["proxy_id"])
    client = TelegramClient(
        StringSession(),
        int(acc["api_id"]),
        acc["api_hash"],
        proxy=proxy_cfg,
        device_model="TeleCampaign VPS Pro",
        system_version="Linux 6.1 LTS",
        app_version="4.16.8 x64",
    )
    await client.connect()
    sent = await client.send_code_request(acc["phone"])
    PENDING_LOGINS[account_id] = {
        "client": client,
        "phone": acc["phone"],
        "phone_code_hash": sent.phone_code_hash,
    }
    conn = get_conn()
    conn.execute("UPDATE accounts SET status = 'code_sent' WHERE id = ?", (account_id,))
    conn.commit()
    conn.close()
    return {"status": "code_sent", "phone": acc["phone"]}


async def confirm_phone_code(account_id: int, code: str, password: Optional[str] = None) -> dict:
    pending = PENDING_LOGINS.get(account_id)
    if not pending:
        raise ValueError("No pending login session for this account. Request code again.")
    client: TelegramClient = pending["client"]
    try:
        await client.sign_in(
            phone=pending["phone"],
            code=code.strip(),
            phone_code_hash=pending["phone_code_hash"],
        )
    except SessionPasswordNeededError:
        if not password:
            conn = get_conn()
            conn.execute("UPDATE accounts SET status = '2fa_required' WHERE id = ?", (account_id,))
            conn.commit()
            conn.close()
            return {"status": "2fa_required", "message": "Two-Step Verification (2FA) password is required."}
        await client.sign_in(password=password)

    return await finalize_login(account_id, client)


async def confirm_2fa_password(account_id: int, password: str) -> dict:
    pending = PENDING_LOGINS.get(account_id)
    if not pending:
        raise ValueError("No pending login session for this account.")
    client: TelegramClient = pending["client"]
    await client.sign_in(password=password)
    return await finalize_login(account_id, client)


async def start_qr_login(account_id: int) -> dict:
    conn = get_conn()
    acc = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    if not acc:
        raise ValueError("Account not found")

    proxy_cfg = get_proxy_dict(acc["proxy_id"])
    client = TelegramClient(
        StringSession(),
        int(acc["api_id"]),
        acc["api_hash"],
        proxy=proxy_cfg,
        device_model="TeleCampaign VPS Pro",
        system_version="Linux 6.1 LTS",
        app_version="4.16.8 x64",
    )
    await client.connect()
    qr_login = await client.qr_login()

    img = qrcode.make(qr_login.url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")

    PENDING_LOGINS[account_id] = {
        "client": client,
        "qr_login": qr_login,
        "qr_b64": qr_b64,
        "status": "waiting_qr",
    }

    async def _wait_qr():
        try:
            await qr_login.wait(timeout=120)
            await finalize_login(account_id, client)
            if account_id in PENDING_LOGINS:
                PENDING_LOGINS[account_id]["status"] = "connected"
        except SessionPasswordNeededError:
            if account_id in PENDING_LOGINS:
                PENDING_LOGINS[account_id]["status"] = "2fa_required"
            conn_inner = get_conn()
            conn_inner.execute("UPDATE accounts SET status = '2fa_required' WHERE id = ?", (account_id,))
            conn_inner.commit()
            conn_inner.close()
        except Exception as e:
            if account_id in PENDING_LOGINS:
                PENDING_LOGINS[account_id]["status"] = f"error: {str(e)}"

    asyncio.create_task(_wait_qr())
    return {"status": "waiting_qr", "qr_image": qr_b64, "url": qr_login.url}


async def finalize_login(account_id: int, client: TelegramClient) -> dict:
    me = await client.get_me()
    session_str = client.session.save()
    phone = f"+{me.phone}" if getattr(me, "phone", None) else ""
    username = getattr(me, "username", "") or ""
    full_name = f"{getattr(me, 'first_name', '') or ''} {getattr(me, 'last_name', '') or ''}".strip()

    conn = get_conn()
    conn.execute(
        """
        UPDATE accounts
        SET session_string = ?, status = 'connected', phone = COALESCE(NULLIF(?, ''), phone),
            username = ?, telegram_user_id = ?, name = COALESCE(NULLIF(name, 'New Account'), ?)
        WHERE id = ?
        """,
        (session_str, phone, username, str(me.id), full_name or username or phone, account_id),
    )
    conn.commit()
    conn.close()

    ACTIVE_CLIENTS[account_id] = client
    PENDING_LOGINS.pop(account_id, None)
    return {
        "status": "connected",
        "account_id": account_id,
        "phone": phone,
        "username": username,
        "name": full_name,
    }


def analyze_entity_and_rules(entity, rule_text: str = "") -> dict:
    """
    Analyzes a Telegram group/channel entity + optional description/pinned rules text
    and returns detected permissions, auto_tags, and primary category.
    """
    can_post = 1
    restriction_until = None
    allow_forwards = 1
    allow_links = 1
    allow_media = 1
    slowmode_seconds = getattr(entity, "slowmode_seconds", 0) or 0
    tags: List[str] = []
    reasons: List[str] = []

    if getattr(entity, "broadcast", False) and not getattr(entity, "creator", False):
        admin_rights = getattr(entity, "admin_rights", None)
        if not admin_rights or not getattr(admin_rights, "post_messages", False):
            can_post = 0

    banned_rights = getattr(entity, "banned_rights", None)
    default_banned = getattr(entity, "default_banned_rights", None)

    for rights_obj in [banned_rights, default_banned]:
        if not rights_obj:
            continue
        if getattr(rights_obj, "send_messages", False):
            if not getattr(entity, "creator", False) and not getattr(entity, "admin_rights", None):
                can_post = 0
                until_date = getattr(rights_obj, "until_date", None)
                if until_date and until_date.year < 2099:
                    restriction_until = until_date.isoformat()
        if getattr(rights_obj, "embed_links", False):
            allow_links = 0
        if getattr(rights_obj, "send_media", False) or getattr(rights_obj, "send_photos", False):
            allow_media = 0

    if getattr(entity, "noforwards", False):
        allow_forwards = 0

    # Parse rule text (English + Vietnamese + Urdu/Hindi transliteration keywords)
    txt = (rule_text or "").lower()
    if any(k in txt for k in ["no forward", "don't forward", "do not forward", "forwarding not allowed", "cấm forward", "không forward"]):
        allow_forwards = 0
        reasons.append("Rule: No Forwarding")

    if any(k in txt for k in ["no link", "links not allowed", "don't send link", "cấm link", "không chèn link", "no url"]):
        allow_links = 0
        reasons.append("Rule: No Links")

    is_24h = False
    if slowmode_seconds >= 3600 or any(
        k in txt
        for k in [
            "24h",
            "24 hour",
            "24 hours",
            "1 post per day",
            "1 post/day",
            "once a day",
            "once per day",
            "1 bài/ngày",
            "1 lần/ngày",
            "mỗi ngày 1",
        ]
    ):
        is_24h = True
        reasons.append("Rule: 1 Post / 24h")

    if any(k in txt for k in ["no emoji", "no custom emoji", "no sticker", "no media", "text only"]):
        tags.append("text_only")
        reasons.append("Rule: Text Only / No Custom Emoji")
    elif allow_media:
        tags.append("premium_emoji_ok")

    if not can_post:
        tags.append("restricted")
    else:
        if is_24h:
            tags.append("24h_once")
        elif slowmode_seconds > 0:
            tags.append("slowmode")

        if not allow_forwards:
            tags.append("no_forward")
        else:
            tags.append("forward_ok")

        if not allow_links:
            tags.append("no_links")

        if not allow_media:
            tags.append("text_only")

        if not tags or tags == ["premium_emoji_ok", "forward_ok"]:
            tags.append("standard")

    # Determine primary distribution category
    if not can_post:
        category = "restricted"
    elif is_24h:
        category = "24h_once"
    elif not allow_forwards:
        category = "no_forward"
    elif not allow_media or "text_only" in tags:
        category = "text_only"
    elif not allow_links:
        category = "no_links"
    elif slowmode_seconds > 0:
        category = "slowmode"
    else:
        category = "standard"

    if slowmode_seconds > 0:
        reasons.append(f"Slowmode: {slowmode_seconds}s")
    if not allow_links and "Rule: No Links" not in reasons:
        reasons.append("Telegram Permission: Links Disabled")
    if not allow_media:
        reasons.append("Telegram Permission: Media Disabled")
    if not allow_forwards and "Rule: No Forwarding" not in reasons:
        reasons.append("Group Protection: Forwarding Restricted")

    return {
        "can_post": can_post,
        "restriction_until": restriction_until,
        "allow_forwards": allow_forwards,
        "allow_links": allow_links,
        "allow_media": allow_media,
        "slowmode_seconds": slowmode_seconds,
        "auto_tags": json.dumps(sorted(list(set(tags)))),
        "category": category,
        "rules_summary": " · ".join(reasons) if reasons else "All standard posts, forwards & premium emojis allowed",
    }


async def sync_account_destinations(account_id: int, deep_scan: bool = False) -> dict:
    """
    Syncs all joined Groups, Supergroups, Channels, and Forum Topics from Telegram.
    Also runs automatic permission + rule tag analysis.
    """
    client = await get_or_create_client(account_id)
    if not await client.is_user_authorized():
        conn = get_conn()
        conn.execute("UPDATE accounts SET status = 'disconnected' WHERE id = ?", (account_id,))
        conn.commit()
        conn.close()
        raise ValueError("Telegram account is not authorized. Please log in again.")

    dialogs = await client.get_dialogs(limit=None)
    conn = get_conn()
    synced_count = 0

    for d in dialogs:
        entity = d.entity
        if not (d.is_group or d.is_channel):
            continue

        title = d.title or "Untitled"
        username = getattr(entity, "username", "") or ""
        participants = getattr(entity, "participants_count", 0) or 0
        is_forum = getattr(entity, "forum", False)
        kind = "forum" if is_forum else ("channel" if getattr(entity, "broadcast", False) else "group")

        rule_text = title
        if deep_scan:
            # Fetch group description / about and latest pinned message for rule keywords
            try:
                if isinstance(entity, types.Channel):
                    full = await client(functions.channels.GetFullChannelRequest(channel=entity))
                    about = getattr(full.full_chat, "about", "") or ""
                    rule_text += " " + about
                elif isinstance(entity, types.Chat):
                    full = await client(functions.messages.GetFullChatRequest(chat_id=entity.id))
                    about = getattr(full.full_chat, "about", "") or ""
                    rule_text += " " + about
            except Exception:
                pass
            try:
                pinned = await client.get_messages(
                    entity, filter=types.InputMessagesFilterPinned(), limit=1
                )
                if pinned and len(pinned) > 0 and getattr(pinned[0], "message", None):
                    rule_text += " " + pinned[0].message
            except Exception:
                pass
            await asyncio.sleep(0.08)

        analysis = analyze_entity_and_rules(entity, rule_text)

        conn.execute(
            """
            INSERT INTO destinations (
                account_id, telegram_id, topic_id, title, parent_title, username,
                kind, can_post, restriction_until, slowmode_seconds, participants_count,
                auto_tags, category, allow_forwards, allow_links, allow_media, rules_summary, updated_at
            ) VALUES (?, ?, NULL, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id, telegram_id, topic_id) DO UPDATE SET
                title=excluded.title,
                username=excluded.username,
                kind=excluded.kind,
                can_post=excluded.can_post,
                restriction_until=excluded.restriction_until,
                slowmode_seconds=excluded.slowmode_seconds,
                participants_count=excluded.participants_count,
                auto_tags=excluded.auto_tags,
                category=excluded.category,
                allow_forwards=excluded.allow_forwards,
                allow_links=excluded.allow_links,
                allow_media=excluded.allow_media,
                rules_summary=excluded.rules_summary,
                updated_at=excluded.updated_at
            """,
            (
                account_id,
                d.id,
                title,
                username,
                kind,
                analysis["can_post"],
                analysis["restriction_until"],
                analysis["slowmode_seconds"],
                participants,
                analysis["auto_tags"],
                analysis["category"],
                analysis["allow_forwards"],
                analysis["allow_links"],
                analysis["allow_media"],
                analysis["rules_summary"],
                now_iso(),
            ),
        )
        synced_count += 1

        if is_forum and analysis["can_post"]:
            try:
                res = await client(
                    functions.channels.GetForumTopicsRequest(
                        channel=entity,
                        offset_date=None,
                        offset_id=0,
                        offset_topic=0,
                        limit=50,
                    )
                )
                for topic in getattr(res, "topics", []):
                    topic_title = getattr(topic, "title", None)
                    topic_id = getattr(topic, "id", None)
                    topic_closed = getattr(topic, "closed", False)
                    if topic_title and topic_id:
                        t_analysis = analyze_entity_and_rules(entity, rule_text + " " + topic_title)
                        conn.execute(
                            """
                            INSERT INTO destinations (
                                account_id, telegram_id, topic_id, title, parent_title, username,
                                kind, can_post, restriction_until, slowmode_seconds, participants_count,
                                auto_tags, category, allow_forwards, allow_links, allow_media, rules_summary, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, 'topic', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(account_id, telegram_id, topic_id) DO UPDATE SET
                                title=excluded.title,
                                parent_title=excluded.parent_title,
                                can_post=excluded.can_post,
                                auto_tags=excluded.auto_tags,
                                category=excluded.category,
                                allow_forwards=excluded.allow_forwards,
                                allow_links=excluded.allow_links,
                                allow_media=excluded.allow_media,
                                rules_summary=excluded.rules_summary,
                                updated_at=excluded.updated_at
                            """,
                            (
                                account_id,
                                d.id,
                                topic_id,
                                topic_title,
                                title,
                                username,
                                0 if topic_closed else t_analysis["can_post"],
                                t_analysis["restriction_until"],
                                t_analysis["slowmode_seconds"],
                                participants,
                                t_analysis["auto_tags"],
                                "restricted" if topic_closed else t_analysis["category"],
                                t_analysis["allow_forwards"],
                                t_analysis["allow_links"],
                                t_analysis["allow_media"],
                                t_analysis["rules_summary"],
                                now_iso(),
                            ),
                        )
                        synced_count += 1
            except Exception:
                pass

    conn.execute("UPDATE accounts SET last_sync_at = ?, status = 'connected' WHERE id = ?", (now_iso(), account_id))
    conn.commit()
    conn.close()
    return {"count": synced_count, "deep_scan": deep_scan}


async def fetch_saved_messages(account_id: int, limit: int = 25) -> list:
    """Fetches recent messages from 'Saved Messages' ('me') for forward campaigns."""
    client = await get_or_create_client(account_id)
    if not await client.is_user_authorized():
        raise ValueError("Account is not connected")

    messages = await client.get_messages("me", limit=limit)
    results = []
    for m in messages:
        if not m.message and not m.media:
            continue
        media_type = "text"
        if m.photo:
            media_type = "photo"
        elif m.video:
            media_type = "video"
        elif m.document:
            media_type = "document"
        results.append(
            {
                "id": m.id,
                "text": (m.message or f"[{media_type.upper()} Media Message]")[:300],
                "media_type": media_type,
                "date": m.date.isoformat() if m.date else "",
            }
        )
    return results


def reset_daily_quota_if_needed(conn, acc: dict) -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if acc["quota_date"] != today:
        conn.execute(
            "UPDATE accounts SET sent_today = 0, quota_date = ? WHERE id = ?",
            (today, acc["id"]),
        )
        conn.commit()
        return 0
    return acc["sent_today"]


async def send_saved_message_as_clean_copy(client: TelegramClient, source_msg_id: int, target_peer: int, topic_id: Optional[int] = None):
    """
    Fetches the message from 'Saved Messages' ('me') and sends it as a brand new message
    (preserving formatting entities, premium custom emojis, and media) WITHOUT the 'Forwarded from' header!
    Used automatically for 'no_forward' groups.
    """
    src_msg = await client.get_messages("me", ids=int(source_msg_id))
    if not src_msg:
        raise ValueError(f"Saved message #{source_msg_id} not found in 'Saved Messages'")

    sent = await client.send_message(
        entity=target_peer,
        message=src_msg.message or "",
        file=src_msg.media,
        formatting_entities=src_msg.entities,
        reply_to=int(topic_id) if topic_id else None,
    )
    return sent.id if hasattr(sent, "id") else 0


async def execute_campaign_round(campaign: dict):
    """
    Executes 1 round of a campaign across its selected destinations with full Anti-Ban & Category protection:
    - Respects 24h_once category (skips if sent in the last 24 hours)
    - Automatically switches to Clean Copy (Drop Author / No Forward Tag) if group is 'no_forward'
    - Auto-learns if group rejects forwards and updates category to 'no_forward'
    """
    camp_id = campaign["id"]
    account_id = campaign["account_id"]
    template_id = campaign["template_id"]
    dest_ids = json.loads(campaign["destination_ids"] or "[]")

    conn = get_conn()
    acc_row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    tmpl_row = conn.execute("SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()
    conn.close()

    if not acc_row or not tmpl_row:
        conn = get_conn()
        conn.execute(
            "UPDATE campaigns SET status = 'paused', last_error = 'Missing account or template' WHERE id = ?",
            (camp_id,),
        )
        conn.commit()
        conn.close()
        return

    acc = dict(acc_row)
    tmpl = dict(tmpl_row)

    if acc.get("cooldown_until"):
        cd_dt = datetime.fromisoformat(acc["cooldown_until"])
        if cd_dt > datetime.now(timezone.utc):
            conn = get_conn()
            conn.execute(
                "UPDATE campaigns SET next_run_at = ?, last_error = ? WHERE id = ?",
                (
                    (cd_dt + timedelta(minutes=2)).isoformat(),
                    f"Account in FloodWait cooldown until {cd_dt.strftime('%H:%M:%S UTC')}",
                    camp_id,
                ),
            )
            conn.commit()
            conn.close()
            return

    try:
        client = await get_or_create_client(account_id)
        if not await client.is_user_authorized():
            raise ValueError("Account session expired or disconnected")
    except Exception as e:
        conn = get_conn()
        conn.execute(
            "UPDATE campaigns SET status = 'paused', last_error = ? WHERE id = ?",
            (f"Account connection error: {str(e)}", camp_id),
        )
        conn.commit()
        conn.close()
        return

    next_round = int(campaign["current_round"]) + 1
    min_delay = max(1, int(campaign["round_delay_min_seconds"]))
    max_delay = max(min_delay, int(campaign["round_delay_max_seconds"]))

    for idx, dest_id in enumerate(dest_ids):
        conn = get_conn()
        fresh_camp = conn.execute("SELECT status FROM campaigns WHERE id = ?", (camp_id,)).fetchone()
        dest_row = conn.execute("SELECT * FROM destinations WHERE id = ?", (dest_id,)).fetchone()
        acc_fresh = dict(conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone())
        sent_today = reset_daily_quota_if_needed(conn, acc_fresh)
        conn.close()

        if not fresh_camp or fresh_camp["status"] != "running":
            return

        if not dest_row:
            continue
        dest = dict(dest_row)

        if sent_today >= int(acc_fresh["daily_quota"]):
            tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).replace(hour=0, minute=5, second=0)
            conn = get_conn()
            conn.execute(
                "UPDATE campaigns SET next_run_at = ?, last_error = 'Daily account quota reached. Auto-resuming tomorrow.' WHERE id = ?",
                (tomorrow.isoformat(), camp_id),
            )
            conn.commit()
            conn.close()
            return

        if not dest["can_post"]:
            log_delivery(camp_id, account_id, dest_id, dest["title"], next_round, "skipped", "No posting permission")
            continue

        if dest.get("restriction_until"):
            rest_dt = datetime.fromisoformat(dest["restriction_until"])
            if rest_dt > datetime.now(timezone.utc):
                log_delivery(
                    camp_id,
                    account_id,
                    dest_id,
                    dest["title"],
                    next_round,
                    "skipped",
                    f"Temporarily restricted until {rest_dt.strftime('%H:%M UTC')}",
                )
                continue

        # Anti-Spam Check: 24-Hour (1 Post/Day) Category Guard
        dest_cat = dest.get("category") or "standard"
        dest_tags = json.loads(dest.get("auto_tags") or "[]")
        if (dest_cat == "24h_once" or "24h_once" in dest_tags) and dest.get("last_sent_at"):
            try:
                last_dt = datetime.fromisoformat(dest["last_sent_at"])
                if datetime.now(timezone.utc) - last_dt < timedelta(hours=24):
                    rem_hours = int((timedelta(hours=24) - (datetime.now(timezone.utc) - last_dt)).total_seconds() // 3600)
                    log_delivery(
                        camp_id,
                        account_id,
                        dest_id,
                        dest["title"],
                        next_round,
                        "skipped",
                        f"24h Rule Guard: Already posted today ({rem_hours}h remaining)",
                    )
                    continue
            except Exception:
                pass

        try:
            target_peer = int(dest["telegram_id"])
            topic_id = dest.get("topic_id")
            delivery_note = "Delivered OK"

            if tmpl["mode"] == "forward" and tmpl.get("source_message_id"):
                # Check if group blocks forwards -> automatically send as clean copy without 'Forwarded from' tag!
                if not dest.get("allow_forwards", 1) or dest_cat == "no_forward" or "no_forward" in dest_tags:
                    msg_id = await send_saved_message_as_clean_copy(
                        client, int(tmpl["source_message_id"]), target_peer, topic_id
                    )
                    delivery_note = "Sent as Clean Copy (No-Forward Rule Bypass)"
                else:
                    try:
                        if topic_id:
                            sent_msg = await client(
                                functions.messages.ForwardMessagesRequest(
                                    from_peer="me",
                                    id=[int(tmpl["source_message_id"])],
                                    to_peer=target_peer,
                                    top_msg_id=int(topic_id),
                                    random_id=[random.randint(-2**63, 2**63 - 1)],
                                )
                            )
                            msg_id = getattr(sent_msg, "id", 0)
                        else:
                            res = await client.forward_messages(
                                entity=target_peer,
                                messages=int(tmpl["source_message_id"]),
                                from_peer="me",
                            )
                            msg_id = res.id if hasattr(res, "id") else 0
                    except ChatForwardsRestrictedError:
                        # Auto-learn that this group blocks forwards and fallback to Clean Copy!
                        msg_id = await send_saved_message_as_clean_copy(
                            client, int(tmpl["source_message_id"]), target_peer, topic_id
                        )
                        conn_learn = get_conn()
                        conn_learn.execute(
                            "UPDATE destinations SET allow_forwards = 0, category = 'no_forward' WHERE id = ?",
                            (dest_id,),
                        )
                        conn_learn.commit()
                        conn_learn.close()
                        delivery_note = "Auto-Learned No-Forward -> Sent as Clean Copy"
            else:
                final_text = parse_spintax(tmpl["content"])
                if campaign.get("simulate_typing", 1):
                    try:
                        async with client.action(target_peer, "typing"):
                            await asyncio.sleep(random.uniform(1.2, 3.0))
                    except Exception:
                        pass

                sent_msg = await client.send_message(
                    entity=target_peer,
                    message=final_text,
                    parse_mode=tmpl.get("parse_mode") or "html",
                    reply_to=int(topic_id) if topic_id else None,
                )
                msg_id = sent_msg.id

            conn = get_conn()
            conn.execute("UPDATE campaigns SET total_sent = total_sent + 1 WHERE id = ?", (camp_id,))
            conn.execute("UPDATE accounts SET sent_today = sent_today + 1 WHERE id = ?", (account_id,))
            conn.execute("UPDATE destinations SET last_sent_at = ? WHERE id = ?", (now_iso(), dest_id))
            conn.commit()
            conn.close()
            log_delivery(camp_id, account_id, dest_id, dest["title"], next_round, "sent", delivery_note, msg_id)

        except SlowModeWaitError as e:
            safe_until = datetime.now(timezone.utc) + timedelta(seconds=e.seconds + 300)
            conn = get_conn()
            conn.execute(
                "UPDATE destinations SET restriction_until = ?, category = CASE WHEN ? >= 3600 THEN '24h_once' ELSE 'slowmode' END WHERE id = ?",
                (safe_until.isoformat(), e.seconds, dest_id),
            )
            conn.execute("UPDATE campaigns SET total_failed = total_failed + 1 WHERE id = ?", (camp_id,))
            conn.commit()
            conn.close()
            log_delivery(
                camp_id,
                account_id,
                dest_id,
                dest["title"],
                next_round,
                "cooldown",
                f"SlowModeWait ({e.seconds}s) + 5m safety buffer",
            )

        except FloodWaitError as e:
            safe_until = datetime.now(timezone.utc) + timedelta(seconds=e.seconds + 300)
            conn = get_conn()
            conn.execute(
                "UPDATE accounts SET cooldown_until = ? WHERE id = ?",
                (safe_until.isoformat(), account_id),
            )
            conn.execute(
                "UPDATE campaigns SET next_run_at = ?, total_failed = total_failed + 1, last_error = ? WHERE id = ?",
                (
                    safe_until.isoformat(),
                    f"FloodWait {e.seconds}s — Cooldown active (+5m safety buffer)",
                    camp_id,
                ),
            )
            conn.commit()
            conn.close()
            log_delivery(
                camp_id,
                account_id,
                dest_id,
                dest["title"],
                next_round,
                "cooldown",
                f"FloodWait {e.seconds}s — Pausing account until safe",
            )
            return

        except (ChatWriteForbiddenError, UserBannedInChannelError, ChannelPrivateError, ChatAdminRequiredError) as e:
            conn = get_conn()
            conn.execute("UPDATE destinations SET can_post = 0, category = 'restricted' WHERE id = ?", (dest_id,))
            conn.execute("UPDATE campaigns SET total_failed = total_failed + 1 WHERE id = ?", (camp_id,))
            conn.commit()
            conn.close()
            log_delivery(
                camp_id,
                account_id,
                dest_id,
                dest["title"],
                next_round,
                "failed",
                f"Posting forbidden ({type(e).__name__}) — Auto-disabled group",
            )

        except PeerFloodError:
            safe_until = datetime.now(timezone.utc) + timedelta(hours=6)
            conn = get_conn()
            conn.execute("UPDATE accounts SET cooldown_until = ? WHERE id = ?", (safe_until.isoformat(), account_id))
            conn.execute(
                "UPDATE campaigns SET next_run_at = ?, last_error = 'PeerFlood detected — Auto-cooling for 6h to protect account' WHERE id = ?",
                (safe_until.isoformat(), camp_id),
            )
            conn.commit()
            conn.close()
            log_delivery(
                camp_id,
                account_id,
                dest_id,
                dest["title"],
                next_round,
                "cooldown",
                "PeerFlood Warning — Auto-cooling account 6h",
            )
            return

        except Exception as e:
            conn = get_conn()
            conn.execute(
                "UPDATE campaigns SET total_failed = total_failed + 1, last_error = ? WHERE id = ?",
                (str(e)[:200], camp_id),
            )
            conn.commit()
            conn.close()
            log_delivery(camp_id, account_id, dest_id, dest["title"], next_round, "failed", str(e)[:200])

        if idx < len(dest_ids) - 1:
            jitter_sleep = random.uniform(min_delay, max_delay)
            await asyncio.sleep(jitter_sleep)

    conn = get_conn()
    repeat_count = int(campaign["repeat_count"])
    if next_round >= repeat_count:
        conn.execute(
            "UPDATE campaigns SET current_round = ?, status = 'completed', next_run_at = NULL WHERE id = ?",
            (next_round, camp_id),
        )
    else:
        group_interval = max(10, int(campaign["group_interval_seconds"]))
        next_run = datetime.now(timezone.utc) + timedelta(seconds=group_interval + random.randint(2, 15))
        conn.execute(
            "UPDATE campaigns SET current_round = ?, next_run_at = ? WHERE id = ?",
            (next_round, next_run.isoformat(), camp_id),
        )
    conn.commit()
    conn.close()


def log_delivery(
    campaign_id: int,
    account_id: int,
    destination_id: int,
    destination_title: str,
    round_number: int,
    status: str,
    reason: str,
    message_id: Optional[int] = None,
):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO delivery_logs (
            campaign_id, account_id, destination_id, destination_title,
            round_number, status, reason, message_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            campaign_id,
            account_id,
            destination_id,
            destination_title,
            round_number,
            status,
            reason,
            message_id,
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()


RUNNING_CAMPAIGN_TASKS: Dict[int, asyncio.Task] = {}


async def campaign_scheduler_loop():
    """Background worker loop that checks runnable campaigns every 3 seconds."""
    while True:
        try:
            now_dt = datetime.now(timezone.utc)
            conn = get_conn()
            rows = conn.execute("SELECT * FROM campaigns WHERE status = 'running'").fetchall()
            conn.close()

            for row in rows:
                camp = dict(row)
                cid = camp["id"]
                if cid in RUNNING_CAMPAIGN_TASKS and not RUNNING_CAMPAIGN_TASKS[cid].done():
                    continue

                if camp.get("scheduled_at"):
                    try:
                        sched_dt = datetime.fromisoformat(camp["scheduled_at"].replace("Z", "+00:00"))
                        if sched_dt.tzinfo is None:
                            sched_dt = sched_dt.replace(tzinfo=timezone.utc)
                        if sched_dt > now_dt:
                            continue
                    except Exception:
                        pass

                if camp.get("next_run_at"):
                    try:
                        next_dt = datetime.fromisoformat(camp["next_run_at"].replace("Z", "+00:00"))
                        if next_dt.tzinfo is None:
                            next_dt = next_dt.replace(tzinfo=timezone.utc)
                        if next_dt > now_dt:
                            continue
                    except Exception:
                        pass

                RUNNING_CAMPAIGN_TASKS[cid] = asyncio.create_task(execute_campaign_round(camp))

        except Exception as e:
            print("Scheduler loop error:", e)
            traceback.print_exc()

        await asyncio.sleep(3)
