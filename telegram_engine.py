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
from telethon import TelegramClient, functions, types, utils
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


async def fetch_telegram_folder_map(client: TelegramClient) -> Dict[int, List[str]]:
    """
    Fetches user's custom Telegram Chat Folders (Dialog Filters) via MTProto
    and maps every peer ID (both -100... dialog ID and raw entity ID) to its folder titles.
    """
    folder_map: Dict[int, List[str]] = {}
    try:
        res = await client(functions.messages.GetDialogFiltersRequest())
        filters = getattr(res, "filters", res) or []
        for f in filters:
            raw_title = getattr(f, "title", None)
            if not raw_title:
                continue
            title_str = getattr(raw_title, "text", None) if hasattr(raw_title, "text") else str(raw_title)
            title_str = (title_str or "").strip()
            if not title_str:
                continue

            peers = list(getattr(f, "include_peers", []) or []) + list(getattr(f, "pinned_peers", []) or [])
            for p in peers:
                try:
                    pid = utils.get_peer_id(p)
                    folder_map.setdefault(pid, [])
                    if title_str not in folder_map[pid]:
                        folder_map[pid].append(title_str)
                except Exception:
                    pass
                for attr in ("channel_id", "chat_id", "user_id"):
                    raw_id = getattr(p, attr, None)
                    if raw_id:
                        folder_map.setdefault(int(raw_id), [])
                        if title_str not in folder_map[int(raw_id)]:
                            folder_map[int(raw_id)].append(title_str)
    except Exception as e:
        print("Warning: Could not fetch Telegram dialog folders:", e)
    return folder_map


def analyze_entity_and_rules(
    entity,
    rule_text: str = "",
    folder_names: Optional[List[str]] = None,
    cannot_post_reason: str = "",
    chat_behavior: Optional[dict] = None,
) -> dict:
    """
    Analyzes a Telegram group/channel entity + Telegram Chat Folders + description/pinned rules/bot warnings
    + live seller chat behavior patterns and returns detected permissions, auto_tags, folder_name, and primary category.
    """
    can_post = 1
    restriction_until = None
    allow_forwards = 1
    allow_links = 1
    allow_media = 1
    slowmode_seconds = getattr(entity, "slowmode_seconds", 0) or 0
    tags: List[str] = []
    reasons: List[str] = []
    folder_names = folder_names or []
    chat_behavior = chat_behavior or {}

    admin_rights = getattr(entity, "admin_rights", None)
    is_creator = bool(getattr(entity, "creator", False))
    is_admin = bool(admin_rights)

    if getattr(entity, "left", False) or getattr(entity, "kicked", False):
        can_post = 0
        reasons.append("Not a Member / Left Group")

    if getattr(entity, "broadcast", False) and not is_creator:
        if not admin_rights or not getattr(admin_rights, "post_messages", False):
            can_post = 0
            reasons.append("Broadcast Channel (Admin Only)")

    banned_rights = getattr(entity, "banned_rights", None)
    default_banned = getattr(entity, "default_banned_rights", None)

    for rights_obj in [banned_rights, default_banned]:
        if not rights_obj:
            continue
        # Modern Telegram API splits text permission into send_plain alongside legacy send_messages
        if getattr(rights_obj, "send_messages", False) or getattr(rights_obj, "send_plain", False) or getattr(rights_obj, "view_messages", False):
            if not is_creator and not is_admin:
                can_post = 0
                if "Sending Messages Not Allowed" not in " ".join(reasons):
                    reasons.append("Telegram Permission: Sending Messages Not Allowed")
                until_date = getattr(rights_obj, "until_date", None)
                if until_date and until_date.year < 2099:
                    restriction_until = until_date.isoformat()
        if getattr(rights_obj, "embed_links", False):
            allow_links = 0
        if getattr(rights_obj, "send_media", False) or getattr(rights_obj, "send_photos", False):
            allow_media = 0

    if cannot_post_reason and not is_creator and not is_admin:
        can_post = 0
        if cannot_post_reason not in reasons:
            reasons.append(cannot_post_reason)

    # Also check if title itself indicates a read-only Bot Logs / Order Logs feed where user is not admin
    ent_title_low = (getattr(entity, "title", "") or "").lower()
    ent_uname_low = (getattr(entity, "username", "") or "").lower()
    if not is_creator and not is_admin:
        if any(kw in ent_title_low for kw in ("bot log", "bot logs", "ai log", "ai logs", "order log", "purchase log", "payment log", "stock update")):
            can_post = 0
            if not any("Bot Logs" in r for r in reasons):
                reasons.append("Restricted: Read-Only Bot Logs / Feed Group")

    if getattr(entity, "noforwards", False):
        allow_forwards = 0

    # If user cannot post at all in this group/channel, immediately return restricted tag & category
    if not can_post:
        specific_folders = [f for f in folder_names if f.lower() not in ("groups", "channels", "all", "bots")]
        display_folder = ", ".join(specific_folders) if specific_folders else (", ".join(folder_names) if folder_names else "")
        return {
            "can_post": 0,
            "restriction_until": restriction_until,
            "allow_forwards": 0,
            "allow_links": 0,
            "allow_media": 0,
            "slowmode_seconds": slowmode_seconds,
            "auto_tags": json.dumps(["restricted"]),
            "category": "restricted",
            "folder_name": display_folder,
            "rules_summary": " · ".join(reasons) if reasons else "Sending messages is not allowed in this group",
        }

    is_24h = False
    is_no_emoji = False
    folder_no_forward = False
    folder_no_emoji = False
    folder_24h = False

    # 1. Check User's Telegram Chat Folders first
    for fn in folder_names:
        fn_low = fn.lower()
        if any(k in fn_low for k in ["emji", "emoji", "withut", "without", "text only", "no media"]):
            is_no_emoji = True
            folder_no_emoji = True
            tags.append("text_only")
            tags.append("no_emoji")
            reasons.append(f"Telegram Folder: {fn} (No Premium Emojis)")
        if any(k in fn_low for k in ["forwrd", "forward", "dnt", "dont", "don't", "no fwd", "clean"]):
            allow_forwards = 0
            folder_no_forward = True
            tags.append("no_forward")
            reasons.append(f"Telegram Folder: {fn} (No Forwarding -> Auto Clean Copy)")
        if any(k in fn_low for k in ["24h", "24 hour", "1 post", "daily", "once"]):
            is_24h = True
            folder_24h = True
            tags.append("24h_once")
            reasons.append(f"Telegram Folder: {fn} (1 Post / 24h)")
        if any(k in fn_low for k in ["no link", "nolink"]):
            allow_links = 0
            tags.append("no_links")
            reasons.append(f"Telegram Folder: {fn} (No Links)")

    # 2. Parse official rule text (Group Bio + Pinned Rules + Moderation Bot Messages ONLY — never regular seller ads)
    txt = (rule_text or "").lower()

    # No-Forward detection from official rules, bot warnings, or seller chat behavior
    if any(
        k in txt
        for k in [
            "no forward",
            "don't forward",
            "do not forward",
            "forwarding not allowed",
            "forwarding is not allowed",
            "forward not allowed",
            "no forwarded",
            "cấm forward",
            "không forward",
            "ko forward",
            "cấm chuyển tiếp",
            "không chuyển tiếp",
            "ko chuyển tiếp",
            "tin nhắn chuyển tiếp",
            "hạn chế chuyển tiếp",
        ]
    ):
        allow_forwards = 0
        if not any("No Forwarding" in r for r in reasons):
            reasons.append("Bot/Group Rule: No Forwarding (Auto Clean Copy)")
    elif chat_behavior.get("inferred_no_forward"):
        allow_forwards = 0
        if not any("Forward" in r for r in reasons):
            reasons.append("Seller Chat & Bot Pattern: 0 Forwarded Posts Allowed (Auto Clean Copy)")

    # No-Link detection from rules & bot warnings
    if any(
        k in txt
        for k in [
            "no link",
            "links not allowed",
            "links are not allowed",
            "don't send link",
            "no external link",
            "cấm link",
            "không chèn link",
            "không gửi link",
            "link bị cấm",
            "no url",
        ]
    ):
        allow_links = 0
        if not any("No Links" in r for r in reasons):
            reasons.append("Bot/Group Rule: No Links")

    # 24h / Daily post limit detection from official rules, moderation bots (e.g. vocvn_bot / @nghienvoc), & slowmode
    if (
        slowmode_seconds >= 3600
        or ent_uname_low == "nghienvoc"
        or "nghiện vọc" in ent_title_low
        or chat_behavior.get("bot_enforces_24h")
        or any(
            k in txt
            for k in [
                "24h",
                "24 giờ",
                "24 hour",
                "24 hours",
                "1 post per day",
                "1 post/day",
                "1 post / day",
                "1 post per 24h",
                "1 post / 24h",
                "1 post in 24h",
                "once a day",
                "once per day",
                "once per 24h",
                "one post per day",
                "only 1 post",
                "1 bài/ngày",
                "1 bài / ngày",
                "1 bài/24h",
                "1 bài / 24h",
                "1 lần/ngày",
                "mỗi ngày 1",
                "giới hạn bài đăng",
                "giới hạn 1 bài",
                "đạt 2/2 cảnh cáo",
                "vocvn_bot",
            ]
        )
    ):
        is_24h = True
        if not any("24h" in r for r in reasons):
            reasons.append("Bot/Group Rule: 1 Post / 24h Limit")

    # No Emoji / No Custom Emoji restriction detection:
    # IMPORTANT: Telegram's send_media/send_photos permission (allow_media=0) ONLY blocks image/video files;
    # Telegram Premium Emojis (MessageEntityCustomEmoji) are text entities and ARE allowed even when Media is disabled!
    # Only mark is_no_emoji if in user's 'Withut emji' folder, or explicit rule/bot forbids emojis (and sellers aren't using them).
    if folder_no_emoji or (
        not chat_behavior.get("sellers_use_custom_emoji")
        and (
            chat_behavior.get("inferred_no_emoji")
            or any(
                k in txt
                for k in [
                    "no emoji",
                    "no custom emoji",
                    "no premium emoji",
                    "emoji not allowed",
                    "emojis not allowed",
                    "without emoji",
                    "withut emji",
                    "cấm emoji",
                    "không dùng emoji",
                    "emoji premium",
                    "cấm icon",
                    "không dùng icon",
                ]
            )
        )
    ):
        is_no_emoji = True
        tags.append("text_only")
        tags.append("no_emoji")
        if not any("No Premium Emoji" in r for r in reasons):
            reasons.append("Bot/Group Rule: No Premium Emoji / Text Only")
    else:
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

        if is_no_emoji:
            tags.append("text_only")

        if not is_24h and allow_forwards and not is_no_emoji:
            tags.append("standard")

    # Determine primary distribution category:
    # 1. Restricted (Cannot Post)
    # 2. 24h Limit (1 Post/Day) — e.g. @nghienvoc (also preserves allow_forwards=0 if in Dnt forwrd folder)
    # 3. No Emoji / Text Only — e.g. user's 'Withut emji ❌' folder (GC MMO CHAT, GC MMO MARKET) or explicit no-emoji rule
    # 4. No-Forward (Clean Copy) — e.g. user's 'Dnt forwrd ❌' folder or noforwards group protection
    # 5. Standard (Forward OK + Premium Emoji OK) — includes groups like Smart Sellers, Illuminati's Escrower, Trust Selling!
    if not can_post:
        category = "restricted"
    elif is_24h or folder_24h:
        category = "24h_once"
    elif folder_no_emoji or is_no_emoji:
        category = "text_only"
    elif folder_no_forward or not allow_forwards:
        category = "no_forward"
    elif slowmode_seconds >= 300:
        category = "slowmode"
    else:
        category = "standard"

    if slowmode_seconds > 0:
        reasons.append(f"Slowmode: {slowmode_seconds}s")
    if not allow_links and not any("Links" in r for r in reasons):
        reasons.append("Note: Links Disabled (Text & Premium Emojis OK)")
    if not allow_forwards and not any("Forward" in r for r in reasons):
        reasons.append("Group Protection: Forwarding Restricted (Auto Clean Copy)")

    # Pick display folder badge (prefer specific custom folders over generic "Groups")
    specific_folders = [f for f in folder_names if f.lower() not in ("groups", "channels", "all", "bots")]
    display_folder = ", ".join(specific_folders) if specific_folders else (", ".join(folder_names) if folder_names else "")

    if display_folder and not any("Telegram Folder:" in r for r in reasons):
        reasons.insert(0, f"Folder: {display_folder}")

    return {
        "can_post": can_post,
        "restriction_until": restriction_until,
        "allow_forwards": allow_forwards,
        "allow_links": allow_links,
        "allow_media": allow_media,
        "slowmode_seconds": slowmode_seconds,
        "auto_tags": json.dumps(sorted(list(set(tags)))),
        "category": category,
        "folder_name": display_folder,
        "rules_summary": " · ".join(reasons) if reasons else "All standard posts, forwards & premium emojis allowed",
    }


async def find_best_forum_selling_topic(client: TelegramClient, entity) -> tuple:
    """
    For a Forum Supergroup (group with multiple sub-chats/topics), finds the SINGLE best open
    Public / General / Market / Buying-Selling sub-chat where members actively post marketing/selling ads,
    and ignores Admin/Rules/Scam-Report/Support topics.
    Returns (best_topic_id, best_topic_title, has_open_topic).
    """
    try:
        req_cls = getattr(functions.messages, "GetForumTopicsRequest", None)
        if req_cls:
            res = await asyncio.wait_for(
                client(req_cls(peer=entity, offset_date=None, offset_id=0, offset_topic=0, limit=50)),
                timeout=3.0,
            )
        else:
            res = await asyncio.wait_for(
                client(
                    functions.channels.GetForumTopicsRequest(
                        channel=entity, offset_date=None, offset_id=0, offset_topic=0, limit=50
                    )
                ),
                timeout=3.0,
            )
    except Exception:
        return (1, "General", True)

    topics = getattr(res, "topics", []) or []
    if not topics:
        return (1, "General", True)

    blocked_keywords = (
        "scam", "report", "legit", "check", "rule", "nội quy", "quy định",
        "thông báo", "announce", "support", "hỗ trợ", "admin", "uy tín",
        "cảnh báo", "warning", "khiếu nại", "feedback", "event", "minigame",
        "282", "956", "mở khoá", "unlock", "tut", "báo cáo", "verify", "xác minh",
    )
    market_keywords = (
        "mua bán", "trao đổi", "chợ", "market", "buy", "sell", "trade",
        "quảng cáo", "bán", "shop", "store", "promo", "marketing", "dịch vụ",
        "service", "giao dịch",
    )
    general_keywords = (
        "general", "chat", "cộng đồng", "giao lưu", "thảo luận", "public", "main", "tán gẫu",
    )
    selling_msg_indicators = (
        "$", "usdt", "vnd", "₫", "giá", "price", "buy", "sell", "mua", "bán",
        "stock", "acc", "pro", "plus", "ib", "inbox", "dm", "@", "t.me",
    )

    candidates = []
    any_open = False
    for t in topics:
        t_id = getattr(t, "id", None)
        t_title = (getattr(t, "title", None) or "").strip()
        t_closed = bool(getattr(t, "closed", False))
        if not t_id or not t_title or t_closed:
            continue
        any_open = True
        low = t_title.lower()

        if any(bk in low for bk in blocked_keywords):
            continue

        score = 10
        if any(mk in low for mk in market_keywords):
            score += 60
        elif any(gk in low for gk in general_keywords) or int(t_id) == 1:
            score += 45

        candidates.append({"id": int(t_id), "title": t_title, "score": score})

    if not any_open:
        return (None, "All Topics Closed", False)

    if not candidates:
        for t in topics:
            if getattr(t, "id", None) and not getattr(t, "closed", False):
                return (int(t.id), str(getattr(t, "title", "General")), True)
        return (1, "General", True)

    candidates.sort(key=lambda x: x["score"], reverse=True)
    top_candidates = candidates[:3]

    for cand in top_candidates:
        try:
            msgs = await asyncio.wait_for(
                client.get_messages(entity, reply_to=cand["id"], limit=8),
                timeout=2.0,
            )
            sell_hits = 0
            for m in (msgs or []):
                mtxt = (getattr(m, "message", None) or "").lower()
                if mtxt and any(ind in mtxt for ind in selling_msg_indicators):
                    sell_hits += 1
            cand["score"] += sell_hits * 10
        except Exception:
            pass

    top_candidates.sort(key=lambda x: x["score"], reverse=True)
    winner = top_candidates[0]
    return (winner["id"], winner["title"], True)


async def sync_account_destinations(account_id: int, deep_scan: bool = True) -> dict:
    """
    Syncs all joined Groups, Supergroups, Channels, Forum Topics, and Telegram Chat Folders.
    Also runs automatic permission + folder + rule tag analysis and cleans up any duplicates.
    """
    client = await get_or_create_client(account_id)
    if not await client.is_user_authorized():
        conn = get_conn()
        conn.execute("UPDATE accounts SET status = 'disconnected' WHERE id = ?", (account_id,))
        conn.commit()
        conn.close()
        raise ValueError("Telegram account is not authorized. Please log in again.")

    # 1. Fetch user's Telegram Chat Folders (e.g. 'Withut emji ❌', 'Dnt forwrd ❌', 'Groups')
    folder_map = await fetch_telegram_folder_map(client)

    conn_pre = get_conn()
    deleted_main_ids = {
        int(r[0])
        for r in conn_pre.execute(
            "SELECT telegram_id FROM destinations WHERE account_id = ? AND COALESCE(topic_id, 0) = 0 AND COALESCE(is_deleted, 0) = 1",
            (account_id,),
        ).fetchall()
    }
    deleted_topic_pairs = {
        (int(r[0]), int(r[1]))
        for r in conn_pre.execute(
            "SELECT telegram_id, COALESCE(topic_id, 0) FROM destinations WHERE account_id = ? AND COALESCE(is_deleted, 0) = 1",
            (account_id,),
        ).fetchall()
    }
    conn_pre.close()

    dialogs = await client.get_dialogs(limit=None)
    group_dialogs = [d for d in dialogs if (d.is_group or d.is_channel) and int(d.id) not in deleted_main_ids]

    # 2. Deep-scan group description, pinned rules, recent moderation bot messages, seller chat behavior, AND active Forum Selling/General topic concurrently
    extra_rules: Dict[int, str] = {}
    forum_topic_map: Dict[int, tuple] = {}
    cannot_post_map: Dict[int, str] = {}
    behavior_map: Dict[int, dict] = {}
    sem = asyncio.Semaphore(8)

    async def _scan_one(d):
        entity = d.entity
        text_parts = []
        behavior = {
            "inferred_no_forward": False,
            "inferred_no_emoji": False,
            "bot_enforces_24h": False,
            "sellers_use_custom_emoji": False,
        }
        is_creator_or_admin = bool(getattr(entity, "creator", False)) or bool(getattr(entity, "admin_rights", None))
        async with sem:
            if getattr(entity, "forum", False):
                try:
                    forum_topic_map[d.id] = await find_best_forum_selling_topic(client, entity)
                except Exception:
                    forum_topic_map[d.id] = (1, "General", True)

            # Live participant permission check (catches personal mutes & modern send_plain group locks)
            if not is_creator_or_admin:
                try:
                    perms = await asyncio.wait_for(client.get_permissions(entity, "me"), timeout=2.0)
                    if getattr(perms, "is_admin", False) or getattr(perms, "is_creator", False):
                        is_creator_or_admin = True
                    else:
                        if getattr(perms, "send_messages", True) is False or getattr(perms, "send_plain", True) is False:
                            cannot_post_map[d.id] = "Telegram Permission: Sending Messages Not Allowed"
                        p_banned = getattr(perms, "banned_rights", None)
                        if p_banned and (getattr(p_banned, "send_messages", False) or getattr(p_banned, "send_plain", False)):
                            cannot_post_map[d.id] = "Telegram Permission: Sending Messages Not Allowed"
                except Exception:
                    pass

            if deep_scan:
                # A) Group Description / Bio + Full Chat Default Banned Rights
                try:
                    if isinstance(entity, types.Channel):
                        full = await asyncio.wait_for(
                            client(functions.channels.GetFullChannelRequest(channel=entity)),
                            timeout=2.5,
                        )
                        about = getattr(full.full_chat, "about", "") or ""
                        if about:
                            text_parts.append(about)
                        for ch_obj in getattr(full, "chats", []) or []:
                            for r_attr in ("banned_rights", "default_banned_rights"):
                                r_obj = getattr(ch_obj, r_attr, None)
                                if r_obj and (getattr(r_obj, "send_messages", False) or getattr(r_obj, "send_plain", False)):
                                    if not is_creator_or_admin:
                                        cannot_post_map[d.id] = "Telegram Permission: Sending Messages Not Allowed"
                    elif isinstance(entity, types.Chat):
                        full = await asyncio.wait_for(
                            client(functions.messages.GetFullChatRequest(chat_id=entity.id)),
                            timeout=2.5,
                        )
                        about = getattr(full.full_chat, "about", "") or ""
                        if about:
                            text_parts.append(about)
                except Exception:
                    pass

                # B) Up to 5 Pinned Rules Messages
                try:
                    pinned = await asyncio.wait_for(
                        client.get_messages(entity, filter=types.InputMessagesFilterPinned(), limit=5),
                        timeout=2.5,
                    )
                    for pm in (pinned or []):
                        if getattr(pm, "message", None):
                            text_parts.append(pm.message)
                except Exception:
                    pass

                # C) Recent 35 Group Messages — Analyze Moderation Bots + Other Sellers' Chat Patterns
                try:
                    target_topic = forum_topic_map.get(d.id, (None,))[0] if getattr(entity, "forum", False) else None
                    if target_topic and target_topic > 1:
                        recent_msgs = await asyncio.wait_for(
                            client.get_messages(entity, reply_to=target_topic, limit=35),
                            timeout=2.5,
                        )
                    else:
                        recent_msgs = await asyncio.wait_for(
                            client.get_messages(entity, limit=35),
                            timeout=2.5,
                        )
                    real_msgs = [rm for rm in (recent_msgs or []) if getattr(rm, "message", None) or getattr(rm, "media", None)]
                    bot_or_admin_count = 0
                    seller_msg_count = 0
                    seller_fwd_count = 0
                    has_strict_mod_bot = False

                    for rm in real_msgs:
                        msg_txt = getattr(rm, "message", None) or ""
                        sender = getattr(rm, "sender", None)
                        is_bot = bool(getattr(sender, "bot", False))
                        sender_uname = (getattr(sender, "username", "") or "").lower()
                        sender_fname = (getattr(sender, "first_name", "") or "").lower()
                        from_peer = getattr(rm, "from_id", None)
                        is_anon_admin = isinstance(from_peer, types.PeerChannel) or bool(getattr(rm, "post", False))

                        if is_bot or sender_uname.endswith("bot") or is_anon_admin:
                            bot_or_admin_count += 1
                            if msg_txt:
                                text_parts.append(msg_txt)
                            low_bot_msg = msg_txt.lower()
                            if "vocvn_bot" in sender_uname or "v o c v n" in sender_fname or "đạt 2/2 cảnh cáo" in low_bot_msg or "1/2 cảnh cáo" in low_bot_msg:
                                behavior["bot_enforces_24h"] = True
                                has_strict_mod_bot = True
                            if any(b in sender_uname for b in ("rose", "grouphelp", "shieldy", "combot", "vocvn", "clean")):
                                has_strict_mod_bot = True
                            if any(w in low_bot_msg for w in ("forward", "chuyển tiếp")):
                                behavior["inferred_no_forward"] = True
                            if any(w in low_bot_msg for w in ("1 bài/ngày", "1 bài / ngày", "24h", "24 giờ", "1 post per day", "once a day", "quá số lần")):
                                behavior["bot_enforces_24h"] = True
                        else:
                            seller_msg_count += 1
                            if getattr(rm, "fwd_from", None) is not None:
                                seller_fwd_count += 1
                            for ent in getattr(rm, "entities", None) or []:
                                if isinstance(ent, types.MessageEntityCustomEmoji):
                                    behavior["sellers_use_custom_emoji"] = True
                                    break

                    # If a group has >= 4 recent messages and 100% of them are from Bots or anonymous channel admins (e.g. VEXORIX BOT LOGS, GGSoma Group), normal users cannot post
                    if not is_creator_or_admin and len(real_msgs) >= 4 and bot_or_admin_count == len(real_msgs):
                        cannot_post_map.setdefault(d.id, "Restricted: Bot Logs / Admin-Only Group")

                    # If there are >= 10 seller ads and 0 of them are forwarded while a strict moderation bot is active in the group, sellers are avoiding forwards -> Clean Copy
                    if seller_msg_count >= 10 and seller_fwd_count == 0 and has_strict_mod_bot:
                        behavior["inferred_no_forward"] = True
                except Exception:
                    pass

        behavior_map[d.id] = behavior
        if text_parts:
            extra_rules[d.id] = " ".join(text_parts)

    await asyncio.gather(*[_scan_one(d) for d in group_dialogs], return_exceptions=True)

    conn = get_conn()
    # Clean up any legacy NULL topic_id duplicates or separate topic rows before upserting
    conn.execute("DELETE FROM destinations WHERE kind = 'topic' OR COALESCE(topic_id, 0) > 0")
    conn.execute("""
        DELETE FROM destinations
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM destinations
            GROUP BY account_id, telegram_id, COALESCE(topic_id, 0)
        )
    """)
    conn.execute("UPDATE destinations SET topic_id = 0 WHERE topic_id IS NULL")

    synced_count = 0

    for d in group_dialogs:
        entity = d.entity
        title = d.title or "Untitled"
        username = getattr(entity, "username", "") or ""
        participants = getattr(entity, "participants_count", 0) or 0
        is_forum = getattr(entity, "forum", False)
        kind = "forum" if is_forum else ("channel" if getattr(entity, "broadcast", False) else "group")

        # Lookup folders by dialog ID (-100...) and raw entity ID
        raw_ent_id = getattr(entity, "id", 0)
        folders = list(dict.fromkeys((folder_map.get(d.id) or []) + (folder_map.get(raw_ent_id) or [])))

        rule_text = title + " " + extra_rules.get(d.id, "")
        analysis = analyze_entity_and_rules(
            entity,
            rule_text,
            folders,
            cannot_post_reason=cannot_post_map.get(d.id, ""),
            chat_behavior=behavior_map.get(d.id),
        )

        forum_topic_id = None
        forum_topic_title = ""
        if is_forum:
            ft_id, ft_title, ft_open = forum_topic_map.get(d.id, (1, "General", True))
            if not ft_open or not analysis["can_post"]:
                analysis["can_post"] = 0
                analysis["category"] = "restricted"
                analysis["auto_tags"] = json.dumps(["restricted"])
                if not ft_open:
                    analysis["rules_summary"] = "All Forum Topics Closed"
            else:
                forum_topic_id = ft_id
                forum_topic_title = ft_title
                analysis["rules_summary"] = f"Target Chat: #{ft_title} · " + analysis["rules_summary"]

        conn.execute(
            """
            INSERT INTO destinations (
                account_id, telegram_id, topic_id, title, parent_title, username,
                kind, can_post, restriction_until, slowmode_seconds, participants_count,
                auto_tags, category, allow_forwards, allow_links, allow_media,
                rules_summary, folder_name, forum_topic_id, forum_topic_title, updated_at
            ) VALUES (?, ?, 0, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id, telegram_id, topic_id) DO UPDATE SET
                title=excluded.title,
                username=excluded.username,
                kind=excluded.kind,
                can_post=excluded.can_post,
                restriction_until=excluded.restriction_until,
                slowmode_seconds=excluded.slowmode_seconds,
                participants_count=excluded.participants_count,
                auto_tags=excluded.auto_tags,
                category=CASE
                    WHEN excluded.can_post = 0 THEN 'restricted'
                    WHEN COALESCE(destinations.user_modified_category, 0) = 1 THEN destinations.category
                    ELSE excluded.category
                END,
                allow_forwards=CASE WHEN COALESCE(destinations.user_modified_category, 0) = 1 THEN destinations.allow_forwards ELSE excluded.allow_forwards END,
                allow_links=excluded.allow_links,
                allow_media=excluded.allow_media,
                rules_summary=excluded.rules_summary,
                folder_name=excluded.folder_name,
                forum_topic_id=excluded.forum_topic_id,
                forum_topic_title=excluded.forum_topic_title,
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
                analysis["folder_name"],
                forum_topic_id,
                forum_topic_title,
                now_iso(),
            ),
        )
        synced_count += 1

    conn.execute("UPDATE accounts SET last_sync_at = ?, status = 'connected' WHERE id = ?", (now_iso(), account_id))
    conn.commit()
    conn.close()
    return {"count": synced_count, "deep_scan": deep_scan, "folders_detected": len(folder_map)}


async def fetch_saved_messages(account_id: int, limit: int = 80) -> list:
    """
    Fetches all recent AND pinned messages from 'Saved Messages' ('me' / InputPeerSelf),
    including forwarded messages (from channels, groups, bots, or users), direct messages,
    custom/premium emoji messages, and media messages.
    """
    client = await get_or_create_client(account_id)
    if not await client.is_user_authorized():
        raise ValueError("Account is not connected")

    peer_map: Dict[int, str] = {}
    raw_messages = []
    seen_ids = set()

    # 1. Fetch fresh un-cached history directly from InputPeerSelf
    try:
        hist = await client(
            functions.messages.GetHistoryRequest(
                peer=types.InputPeerSelf(),
                offset_id=0,
                offset_date=None,
                add_offset=0,
                limit=limit,
                max_id=0,
                min_id=0,
                hash=0,
            )
        )
        for c in getattr(hist, "chats", []) or []:
            cid = getattr(c, "id", None)
            ctitle = getattr(c, "title", None)
            if cid and ctitle:
                peer_map[int(cid)] = str(ctitle)
        for u in getattr(hist, "users", []) or []:
            uid = getattr(u, "id", None)
            uname = f"{getattr(u, 'first_name', '') or ''} {getattr(u, 'last_name', '') or ''}".strip() or getattr(u, "username", "")
            if uid and uname:
                peer_map[int(uid)] = str(uname)
        for m in getattr(hist, "messages", []) or []:
            if hasattr(m, "id") and m.id not in seen_ids:
                seen_ids.add(m.id)
                raw_messages.append(m)
    except Exception:
        pass

    # 2. Also fetch via client.get_messages("me") and Pinned messages in Saved Messages
    try:
        std_msgs = await client.get_messages(types.InputPeerSelf(), limit=limit)
        for m in std_msgs or []:
            if hasattr(m, "id") and m.id not in seen_ids:
                seen_ids.add(m.id)
                raw_messages.append(m)
    except Exception:
        pass

    try:
        pinned_msgs = await client.get_messages(
            types.InputPeerSelf(), filter=types.InputMessagesFilterPinned(), limit=30
        )
        for m in pinned_msgs or []:
            if hasattr(m, "id") and m.id not in seen_ids:
                seen_ids.add(m.id)
                raw_messages.append(m)
    except Exception:
        pass

    # Sort newest first (pinned or highest ID first)
    raw_messages.sort(key=lambda x: getattr(x, "id", 0), reverse=True)

    results = []
    for m in raw_messages:
        if isinstance(m, types.MessageEmpty) or getattr(m, "action", None):
            continue

        msg_text = getattr(m, "message", None) or getattr(m, "raw_text", None) or ""
        fwd = getattr(m, "fwd_from", None)
        media = getattr(m, "media", None)

        if not msg_text and not media and not fwd:
            continue

        # Detect forwarded source name
        is_forwarded = bool(fwd)
        forwarded_from = ""
        if fwd:
            if getattr(fwd, "from_name", None):
                forwarded_from = str(fwd.from_name)
            elif getattr(fwd, "from_id", None):
                fid_obj = fwd.from_id
                raw_fid = (
                    getattr(fid_obj, "channel_id", None)
                    or getattr(fid_obj, "chat_id", None)
                    or getattr(fid_obj, "user_id", None)
                )
                if raw_fid and int(raw_fid) in peer_map:
                    forwarded_from = peer_map[int(raw_fid)]
                else:
                    forwarded_from = "Forwarded Chat"

        media_type = "text"
        if getattr(m, "photo", None) or isinstance(media, types.MessageMediaPhoto):
            media_type = "photo"
        elif getattr(m, "video", None):
            media_type = "video"
        elif getattr(m, "document", None) or isinstance(media, types.MessageMediaDocument):
            media_type = "document"
        elif isinstance(media, types.MessageMediaWebPage):
            media_type = "webpage"

        entities = getattr(m, "entities", None) or []
        custom_emoji_count = sum(1 for e in entities if isinstance(e, types.MessageEntityCustomEmoji))
        is_pinned = bool(getattr(m, "pinned", False))

        display_text = msg_text.strip()
        if not display_text:
            if forwarded_from:
                display_text = f"[Forwarded from {forwarded_from}] ({media_type.upper()})"
            else:
                display_text = f"[{media_type.upper()} Message #{m.id}]"

        dt_obj = getattr(m, "date", None)
        results.append(
            {
                "id": m.id,
                "text": display_text[:600],
                "media_type": media_type,
                "is_forwarded": is_forwarded,
                "forwarded_from": forwarded_from,
                "is_pinned": is_pinned,
                "custom_emoji_count": custom_emoji_count,
                "date": dt_obj.isoformat() if dt_obj else "",
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


async def send_saved_message_as_clean_copy(
    client: TelegramClient,
    source_msg_id: int,
    target_peer: int,
    topic_id: Optional[int] = None,
    strip_custom_emoji: bool = False,
):
    """
    Fetches the message from 'Saved Messages' ('me') and sends it as a brand new message
    WITHOUT the 'Forwarded from' header!
    If strip_custom_emoji=True (for 'Withut emji ❌' / 'text_only' groups), strips
    MessageEntityCustomEmoji so premium emojis automatically fall back to normal standard emojis.
    """
    src_msg = await client.get_messages("me", ids=int(source_msg_id))
    if not src_msg:
        raise ValueError(f"Saved message #{source_msg_id} not found in 'Saved Messages'")

    entities = src_msg.entities
    if strip_custom_emoji and entities:
        entities = [e for e in entities if not isinstance(e, types.MessageEntityCustomEmoji)]

    sent = await client.send_message(
        entity=target_peer,
        message=src_msg.message or "",
        file=src_msg.media,
        formatting_entities=entities,
        reply_to=int(topic_id) if (topic_id and int(topic_id) > 0) else None,
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

        if dest.get("is_deleted", 0) or not dest.get("is_enabled", 1):
            log_delivery(camp_id, account_id, dest_id, dest["title"], next_round, "skipped", "Disabled or removed by user")
            continue

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
            raw_topic = dest.get("forum_topic_id") or dest.get("topic_id")
            topic_id = int(raw_topic) if (raw_topic and int(raw_topic) > 0) else None
            topic_note = f" [Topic: #{dest.get('forum_topic_title')}]" if dest.get("forum_topic_title") else ""
            delivery_note = f"Delivered OK{topic_note}"
            strip_emoji = (dest_cat == "text_only" or "no_emoji" in dest_tags or "text_only" in dest_tags)

            if tmpl["mode"] == "forward" and tmpl.get("source_message_id"):
                # Check if group blocks forwards OR requires stripping premium emojis -> send as clean copy!
                if strip_emoji or not dest.get("allow_forwards", 1) or dest_cat == "no_forward" or "no_forward" in dest_tags:
                    msg_id = await send_saved_message_as_clean_copy(
                        client,
                        int(tmpl["source_message_id"]),
                        target_peer,
                        topic_id,
                        strip_custom_emoji=strip_emoji,
                    )
                    if strip_emoji:
                        delivery_note = "Sent without Premium Emojis (Clean Copy)"
                    else:
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
                            client,
                            int(tmpl["source_message_id"]),
                            target_peer,
                            topic_id,
                            strip_custom_emoji=strip_emoji,
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

            # Live Self-Learning Guard: Check if a moderation bot (Rose, GroupHelp, vocvn_bot, etc.)
            # immediately warned or deleted the post due to a group rule
            try:
                await asyncio.sleep(2.2)
                after_msgs = await asyncio.wait_for(client.get_messages(target_peer, limit=3), timeout=2.0)
                for am in (after_msgs or []):
                    sender = getattr(am, "sender", None)
                    if not getattr(sender, "bot", False):
                        continue
                    btxt = (getattr(am, "message", None) or "").lower()
                    if not btxt:
                        continue
                    learned_cat = None
                    learned_rule = None
                    if any(w in btxt for w in ["emoji", "cấm icon", "custom emoji", "sticker"]):
                        learned_cat = "text_only"
                        learned_rule = "Bot Auto-Detected: No Premium Emojis"
                    elif any(w in btxt for w in ["forward", "chuyển tiếp"]):
                        learned_cat = "no_forward"
                        learned_rule = "Bot Auto-Detected: No Forwarding"
                    elif any(w in btxt for w in ["24h", "1 bài", "1 post", "once a day", "mỗi ngày 1"]):
                        learned_cat = "24h_once"
                        learned_rule = "Bot Auto-Detected: 1 Post / 24h Limit"
                    elif any(w in btxt for w in ["no link", "cấm link", "không chèn link", "link not allowed"]):
                        learned_cat = "no_links"
                        learned_rule = "Bot Auto-Detected: No Links"
                    if learned_cat and learned_cat != dest_cat:
                        new_tags = sorted(list(set(dest_tags + [learned_cat])))
                        conn_bot = get_conn()
                        conn_bot.execute(
                            "UPDATE destinations SET category = ?, auto_tags = ?, allow_forwards = CASE WHEN ? = 'no_forward' THEN 0 ELSE allow_forwards END, rules_summary = ? WHERE id = ?",
                            (learned_cat, json.dumps(new_tags), learned_cat, learned_rule, dest_id),
                        )
                        conn_bot.commit()
                        conn_bot.close()
                        break
            except Exception:
                pass

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
