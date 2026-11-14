# main.py
# 运行: python main.py
# 依赖: pip install websockets

import asyncio
import json
import os
import sqlite3
import hashlib
import secrets
import time
from http import HTTPStatus
import websockets

BOARD_SIZE = 15
DB_FILE = "gomoku.db"
TOKEN_MAX_AGE = 7 * 24 * 3600
MAX_ROOMS = 100

# ==================== 数据库 ====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            wins INTEGER DEFAULT 0,
            losses INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_tokens_username ON tokens(username)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ip_regs_ip_time ON ip_registrations(ip, created_at)")
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000
    ).hex()
    return pwd_hash, salt

def verify_password(password, stored_hash, salt):
    pwd_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(pwd_hash, stored_hash)

# ==================== 用户操作 ====================
def register_user(username, password, client_ip):
    if len(username) < 2 or len(username) > 16:
        return False, "用户名长度需2-16个字符"
    if len(password) < 4:
        return False, "密码至少4位"
    
    conn = get_db()
    try:
        c = conn.cursor()
        
        # 3天（3 * 24 * 3600 秒）内最多 50 个账号
        three_days_ago = int(time.time()) - 3 * 24 * 3600
        c.execute("SELECT COUNT(*) as cnt FROM ip_registrations WHERE ip=? AND created_at >= ?", (client_ip, three_days_ago))
        row = c.fetchone()
        if row and row["cnt"] >= 50:
            return False, "该 IP 地址 3 天内注册账号已达上限（50个）"

        c.execute("SELECT id FROM users WHERE username=?", (username,))
        if c.fetchone():
            return False, "用户名已被注册"
        
        pwd_hash, salt = hash_password(password)
        c.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                  (username, pwd_hash, salt))
        
        c.execute("INSERT INTO ip_registrations (ip, created_at) VALUES (?, ?)",
                  (client_ip, int(time.time())))
        
        conn.commit()
        return True, "注册成功"
    except Exception as e:
        return False, f"注册失败: {e}"
    finally:
        conn.close()

def login_user(username, password):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row or not verify_password(password, row["password_hash"], row["salt"]):
            return False, "用户名或密码错误", None
        return True, "登录成功", {
            "username": row["username"],
            "wins": row["wins"],
            "losses": row["losses"],
        }
    finally:
        conn.close()

def delete_user(username, password):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False, "账号不存在"
        if not verify_password(password, row["password_hash"], row["salt"]):
            return False, "密码错误"
        c.execute("DELETE FROM users WHERE username=?", (username,))
        c.execute("DELETE FROM tokens WHERE username=?", (username,))
        conn.commit()
        return True, "账号已注销"
    except Exception as e:
        return False, f"注销失败: {e}"
    finally:
        conn.close()

def get_user_stats(username):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT wins, losses FROM users WHERE username=?", (username,))
        row = c.fetchone()
        return {"wins": row["wins"], "losses": row["losses"]} if row else {"wins": 0, "losses": 0}
    finally:
        conn.close()

def update_stats(winner_name, loser_name):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET wins = wins + 1 WHERE username=?", (winner_name,))
        c.execute("UPDATE users SET losses = losses + 1 WHERE username=?", (loser_name,))
        conn.commit()
    finally:
        conn.close()

# ==================== Token ====================
def create_token(username):
    token = secrets.token_urlsafe(32)
    expires = int(time.time()) + TOKEN_MAX_AGE
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM tokens WHERE expires_at < ?", (int(time.time()),))
        c.execute("INSERT INTO tokens (token, username, expires_at) VALUES (?, ?, ?)",
                  (token, username, expires))
        conn.commit()
        return token
    finally:
        conn.close()

def verify_token(token):
    if not token:
        return None
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT username, expires_at FROM tokens WHERE token=?", (token,))
        row = c.fetchone()
        if not row:
            return None
        if row["expires_at"] < int(time.time()):
            c.execute("DELETE FROM tokens WHERE token=?", (token,))
            conn.commit()
            return None
        return row["username"]
    finally:
        conn.close()

def delete_tokens_for_user(username):
    conn = get_db()
    try:
        conn.execute("DELETE FROM tokens WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()

# ==================== 规则 ====================
def check_win(board, row, col, player):
    for dx, dy in [(1, 0), (0, 1), (1, 1), (1, -1)]:
        count = 1
        for i in range(1, 5):
            nr, nc = row + dx * i, col + dy * i
            if 0 <= nr < BOARD_SIZE and 0 <= nc < BOARD_SIZE and board[nr][nc] == player:
                count += 1
            else:
                break
        for i in range(1, 5):
            nr, nc = row - dx * i, col - dy * i
            if 0 <= nr < BOARD_SIZE and 0 <= nc < BOARD_SIZE and board[nr][nc] == player:
                count += 1
            else:
                break
        if count >= 5:
            return True
    return False

# ==================== 房间 ====================
class Room:
    def __init__(self, room_id):
        self.room_id = room_id
        self.board = [[0] * BOARD_SIZE for _ in range(BOARD_SIZE)]
        self.current_player = 1
        self.game_over = False
        self.winner = 0
        self.black_player = None
        self.white_player = None
        self.clients = {}
        self.restart_requested = None
        self.draw_requested = None
        self.swap_on_restart = False

    def reset_board(self):
        self.board = [[0] * BOARD_SIZE for _ in range(BOARD_SIZE)]
        self.current_player = 1
        self.game_over = False
        self.winner = 0
        self.restart_requested = None
        self.draw_requested = None

    def get_public_state(self):
        stats = {}
        if self.black_player:
            stats[self.black_player] = get_user_stats(self.black_player)
        if self.white_player:
            stats[self.white_player] = get_user_stats(self.white_player)
        restart_req = {"from": self.restart_requested} if self.restart_requested else None
        draw_req = {"from": self.draw_requested} if self.draw_requested else None
        return {
            "roomId": self.room_id,
            "board": self.board,
            "currentPlayer": self.current_player,
            "gameOver": self.game_over,
            "winner": self.winner,
            "blackPlayer": self.black_player,
            "whitePlayer": self.white_player,
            "winStats": stats,
            "restartRequest": restart_req,
            "drawRequest": draw_req,
            "swapOnRestart": self.swap_on_restart,
        }

    def has_player(self, username):
        return username in (self.black_player, self.white_player)

    def is_full(self):
        return self.black_player is not None and self.white_player is not None

    def release_color(self, username):
        if self.black_player == username:
            self.black_player = None
        if self.white_player == username:
            self.white_player = None

    def try_assign_color(self, username):
        if self.has_player(username):
            return (1 if username == self.black_player else 2), None
        if self.black_player is None:
            self.black_player = username
            return 1, None
        if self.white_player is None:
            self.white_player = username
            return 2, None
        # 房间已满时，允许以旁观者身份加入（color = None）
        return None, None

    def swap_colors(self):
        if not (self.black_player and self.white_player):
            return
        self.black_player, self.white_player = self.white_player, self.black_player
        for c in self.clients.values():
            if c["username"] == self.black_player:
                c["color"] = 1
            elif c["username"] == self.white_player:
                c["color"] = 2

# ==================== 全局状态 ====================
rooms = {}
user_to_room = {}
ws_to_room = {}
ws_global_user = {}
all_clients = set()

# ==================== 广播 ====================
def is_open(ws):
    try:
        return ws.close_code is None
    except AttributeError:
        return getattr(ws, 'open', False)

async def broadcast_to_room(room, message, exclude=None):
    if not room.clients:
        return
    msg_str = json.dumps(message)
    tasks = []
    for ws in list(room.clients.keys()):
        if ws == exclude:
            continue
        if is_open(ws):
            tasks.append(ws.send(msg_str))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

async def send_to(ws, message):
    try:
        if not is_open(ws):
            return
        await ws.send(json.dumps(message))
    except Exception:
        pass

async def broadcast_room_state(room, exclude=None):
    await broadcast_to_room(room, {"type": "state", "data": room.get_public_state()}, exclude=exclude)

def build_room_list():
    result = []
    for rid, r in rooms.items():
        if r.is_full():
            continue  # 只显示未满的房间
        result.append({
            "roomId": rid,
            "black": r.black_player,
            "white": r.white_player,
            "players": (1 if r.black_player else 0) + (1 if r.white_player else 0),
        })
    return result

async def broadcast_room_list():
    msg = {"type": "room_list", "data": build_room_list()}
    msg_str = json.dumps(msg)
    tasks = []
    for ws in list(all_clients):
        if ws in ws_to_room:
            continue
        if is_open(ws):
            tasks.append(ws.send(msg_str))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

# ==================== 单点登录：踢旧连接 ====================
async def ensure_single_session(name, new_ws):
    old_ws = None
    for w, uname in list(ws_global_user.items()):
        if uname == name and w is not new_ws:
            old_ws = w
            break
    if old_ws is None:
        return
    try:
        await old_ws.send(json.dumps({
            "type": "kicked",
            "message": "您的账号在别处登录，此连接已断开"
        }))
    except Exception:
        pass
    if old_ws in ws_to_room:
        await leave_room(old_ws, reason="账号在别处登录", silent=True)
    try:
        await old_ws.close(code=4001, reason="账号在别处登录")
    except Exception:
        pass
    ws_global_user.pop(old_ws, None)
    all_clients.discard(old_ws)

# ==================== 消息处理 ====================
async def handle_message(ws, message, client_ip):
    msg_type = message.get("type")
    current_room = ws_to_room.get(ws)
    username = ws_global_user.get(ws)

    if msg_type == "register":
        name = (message.get("username") or "").strip()
        pwd = message.get("password") or ""
        ok, msg = register_user(name, pwd, client_ip)
        await send_to(ws, {"type": "register_result", "success": ok, "message": msg})
        return

    if msg_type == "login":
        name = (message.get("username") or "").strip()
        pwd = message.get("password") or ""
        remember = bool(message.get("remember", False))
        ok, msg, user = login_user(name, pwd)
        if not ok:
            await send_to(ws, {"type": "login_result", "success": False, "message": msg})
            return
        await ensure_single_session(name, ws)
        token = create_token(name)
        ws_global_user[ws] = name
        await send_to(ws, {
            "type": "login_result", "success": True, "message": "登录成功",
            "username": name, "stats": user,
            "token": token, "remember": remember
        })
        await broadcast_room_list()
        return

    if msg_type == "auto_login":
        token = message.get("token") or ""
        auto_user = verify_token(token)
        if not auto_user:
            await send_to(ws, {"type": "login_result", "success": False, "auto": True,
                               "message": "登录已过期，请重新登录"})
            return
        await ensure_single_session(auto_user, ws)
        ws_global_user[ws] = auto_user
        stats = get_user_stats(auto_user)
        await send_to(ws, {
            "type": "login_result", "success": True, "auto": True,
            "username": auto_user, "stats": stats
        })
        await broadcast_room_list()
        return

    if msg_type == "delete_account":
        if not username:
            await send_to(ws, {"type": "error", "message": "请先登录"})
            return
        pwd = message.get("password") or ""
        ok, msg = delete_user(username, pwd)
        if ok:
            if username in user_to_room:
                await leave_room(ws, reason="账号已注销", silent=True)
            ws_global_user.pop(ws, None)
            await send_to(ws, {"type": "delete_account_result", "success": True, "message": msg})
        else:
            await send_to(ws, {"type": "delete_account_result", "success": False, "message": msg})
        return

    if msg_type == "logout":
        if username:
            if username in user_to_room:
                await leave_room(ws, reason="主动登出")
            delete_tokens_for_user(username)
            ws_global_user.pop(ws, None)
        await send_to(ws, {"type": "logout_done"})
        await broadcast_room_list()
        return

    if not username:
        await send_to(ws, {"type": "error", "message": "请先登录"})
        return

    if msg_type == "list_rooms":
        await send_to(ws, {"type": "room_list", "data": build_room_list()})
        return

    if msg_type == "create_room":
        if current_room:
            await send_to(ws, {"type": "error", "message": "你已在房间中"})
            return
        room_id = None
        for _ in range(1000):
            candidate = str(secrets.randbelow(9000) + 1000)
            if candidate not in rooms:
                room_id = candidate
                break
        if not room_id:
            await send_to(ws, {"type": "error", "message": "房间号已用尽"})
            return
        if len(rooms) >= MAX_ROOMS:
            await send_to(ws, {"type": "error", "message": "服务器房间已满"})
            return
        r = Room(room_id)
        rooms[room_id] = r
        await join_room(ws, username, r)
        return

    if msg_type == "join_room":
        if current_room:
            await send_to(ws, {"type": "error", "message": "你已在房间中"})
            return
        rid = str(message.get("roomId") or "").strip()
        if not rid or len(rid) != 4 or not rid.isdigit():
            await send_to(ws, {"type": "error", "message": "房间号必须是4位数字"})
            return
        r = rooms.get(rid)
        if not r:
            await send_to(ws, {"type": "error", "message": "房间不存在"})
            return
        await join_room(ws, username, r)
        return

    if msg_type == "leave_room":
        if not current_room:
            await send_to(ws, {"type": "error", "message": "你不在任何房间中"})
            return
        await leave_room(ws, reason="主动离开")
        return

    if not current_room:
        await send_to(ws, {"type": "error", "message": "请先加入房间"})
        return

    room = current_room
    client = room.clients.get(ws)
    my_color = client["color"] if client else None

    if msg_type == "move":
        if my_color is None:
            await send_to(ws, {"type": "error", "message": "旁观者不能下棋"})
            return
        if room.game_over:
            await send_to(ws, {"type": "error", "message": "游戏已结束"})
            return
        if my_color != room.current_player:
            await send_to(ws, {"type": "error", "message": "还没轮到你"})
            return
        row = message.get("row")
        col = message.get("col")
        if not isinstance(row, int) or not isinstance(col, int):
            return
        if not (0 <= row < BOARD_SIZE and 0 <= col < BOARD_SIZE):
            return
        if room.board[row][col] != 0:
            await send_to(ws, {"type": "error", "message": "该位置已有棋子"})
            return

        room.board[row][col] = my_color
        room.restart_requested = None
        room.draw_requested = None

        if check_win(room.board, row, col, my_color):
            room.game_over = True
            room.winner = my_color
            winner_name = room.black_player if my_color == 1 else room.white_player
            loser_name = room.white_player if my_color == 1 else room.black_player
            if winner_name and loser_name:
                update_stats(winner_name, loser_name)
            room.swap_on_restart = (my_color == 1)
            await broadcast_room_state(room)
            await broadcast_to_room(room, {"type": "game_over", "winner": my_color,
                                            "winnerName": winner_name})
            return

        if all(room.board[r][c] != 0 for r in range(BOARD_SIZE) for c in range(BOARD_SIZE)):
            room.game_over = True
            room.winner = 0
            room.swap_on_restart = False
            await broadcast_room_state(room)
            await broadcast_to_room(room, {"type": "game_over", "winner": 0})
            return

        room.current_player = 2 if room.current_player == 1 else 1
        await broadcast_room_state(room)
        return

    if msg_type == "request_restart":
        if my_color is None:
            await send_to(ws, {"type": "error", "message": "旁观者不能发起新局"})
            return
        if not room.game_over:
            await send_to(ws, {"type": "error", "message": "游戏进行中，无法开始新一局"})
            return
        if room.restart_requested:
            if room.restart_requested == username:
                await send_to(ws, {"type": "error", "message": "你已发起过申请，等待对方同意"})
            return
        room.restart_requested = username
        await broadcast_room_state(room)
        await broadcast_to_room(room, {
            "type": "notice", "message": f"{username} 申请开始新一局，请对方同意"
        }, exclude=ws)
        return

    if msg_type == "accept_restart":
        if room.restart_requested is None:
            await send_to(ws, {"type": "error", "message": "没有待处理的新局申请"})
            return
        if room.restart_requested == username:
            await send_to(ws, {"type": "error", "message": "不能同意自己的申请"})
            return
        if not room.has_player(username):
            await send_to(ws, {"type": "error", "message": "只有对局玩家可以同意"})
            return

        swapped = False
        if room.swap_on_restart and room.black_player and room.white_player:
            room.swap_colors()
            swapped = True
        room.swap_on_restart = False

        room.reset_board()
        await broadcast_room_state(room)
        notice = "新对局开始，黑棋先行"
        if swapped:
            notice += "（双方已交换黑白）"
        await broadcast_to_room(room, {"type": "notice", "message": notice})
        return

    if msg_type == "reject_restart":
        if room.restart_requested is None:
            await send_to(ws, {"type": "error", "message": "没有待处理的新局申请"})
            return
        requester = room.restart_requested
        room.restart_requested = None
        await broadcast_room_state(room)
        await broadcast_to_room(room, {"type": "notice", "message": f"{requester} 的新局申请被拒绝"})
        return

    if msg_type == "request_draw":
        if my_color is None:
            await send_to(ws, {"type": "error", "message": "旁观者不能发起和棋"})
            return
        if room.game_over:
            await send_to(ws, {"type": "error", "message": "游戏已结束"})
            return
        if room.draw_requested:
            if room.draw_requested == username:
                await send_to(ws, {"type": "error", "message": "你已发起过和棋申请"})
            return
        room.draw_requested = username
        await broadcast_room_state(room)
        await broadcast_to_room(room, {
            "type": "notice", "message": f"{username} 申请和棋，请对方同意"
        }, exclude=ws)
        return

    if msg_type == "accept_draw":
        if room.draw_requested is None:
            await send_to(ws, {"type": "error", "message": "没有待处理的和棋申请"})
            return
        if room.draw_requested == username:
            await send_to(ws, {"type": "error", "message": "不能同意自己的申请"})
            return
        if not room.has_player(username):
            await send_to(ws, {"type": "error", "message": "只有对局玩家可以同意"})
            return
        room.game_over = True
        room.winner = 0
        room.draw_requested = None
        room.swap_on_restart = False
        await broadcast_room_state(room)
        await broadcast_to_room(room, {"type": "game_over", "winner": 0, "draw": True})
        return

    if msg_type == "reject_draw":
        if room.draw_requested is None:
            await send_to(ws, {"type": "error", "message": "没有待处理的和棋申请"})
            return
        requester = room.draw_requested
        room.draw_requested = None
        await broadcast_room_state(room)
        await broadcast_to_room(room, {"type": "notice", "message": f"{requester} 的和棋申请被拒绝"})
        return

    if msg_type == "chat":
        text = (message.get("text") or "").strip()[:200]
        if text:
            await broadcast_to_room(room, {"type": "chat", "username": username, "text": text})
        return

# ==================== 加入/离开 ====================
async def join_room(ws, username, room):
    color, err = room.try_assign_color(username)
    if err:
        await send_to(ws, {"type": "error", "message": err})
        return
    room.clients[ws] = {"username": username, "color": color}
    ws_to_room[ws] = room
    user_to_room[username] = room
    await send_to(ws, {
        "type": "joined_room",
        "roomId": room.room_id,
        "username": username,
        "color": color,
        "stats": get_user_stats(username),
        "state": room.get_public_state(),
    })
    await broadcast_room_state(room)
    if color is not None:
        await broadcast_to_room(room, {"type": "notice", "message": f"{username} 加入了房间"}, exclude=ws)
    else:
        await broadcast_to_room(room, {"type": "notice", "message": f"{username} 开始观战"}, exclude=ws)
    await broadcast_room_list()

async def leave_room(ws, reason=None, silent=False):
    room = ws_to_room.pop(ws, None)
    if not room:
        return
    client = room.clients.pop(ws, None)
    username = client["username"] if client else None
    color = client.get("color") if client else None

    game_was_active = not room.game_over and room.is_full() and room.black_player and room.white_player

    if username:
        # 只有真正参与对局的玩家离开才会判定游戏输赢，旁观者离开不影响
        if game_was_active and color is not None:
            loser_name = username
            winner_name = (room.white_player if username == room.black_player
                           else room.black_player)
            if winner_name and winner_name != loser_name:
                room.game_over = True
                room.winner = (2 if username == room.black_player else 1)
                update_stats(winner_name, loser_name)
                room.swap_on_restart = (room.winner == 1)
                await broadcast_to_room(room, {
                    "type": "game_over",
                    "winner": room.winner,
                    "winnerName": winner_name,
                    "reason": reason or "对方离开，判负"
                })

        if color is not None:
            room.release_color(username)
        if user_to_room.get(username) is room:
            del user_to_room[username]

    if not room.clients and room.black_player is None and room.white_player is None:
        rooms.pop(room.room_id, None)

    await broadcast_room_state(room)
    if username and not silent:
        msg_text = username + (" 离开了房间" if color is not None else " 结束观战")
        if reason and color is not None:
            msg_text += "（" + reason + "）"
        await broadcast_to_room(room, {"type": "notice", "message": msg_text})
    await broadcast_room_list()

# ==================== HTTP 请求拦截（服务 index.html） ====================
async def process_request(connection, request):
    if request.path in ("/", "/index.html"):
        try:
            if os.path.exists("index.html"):
                with open("index.html", "r", encoding="utf-8") as f:
                    html_content = f.read()
                response = connection.respond(HTTPStatus.OK, html_content)
                response.headers["Content-Type"] = "text/html; charset=utf-8"
                return response
        except Exception:
            pass
    return None

# ==================== WebSocket 入口 ====================
async def handler(ws, path=None):
    client_ip = ws.remote_address[0] if ws.remote_address else "127.0.0.1"
    
    all_clients.add(ws)
    ws_global_user[ws] = None
    await send_to(ws, {"type": "hello"})
    await send_to(ws, {"type": "room_list", "data": build_room_list()})
    try:
        async for message_str in ws:
            try:
                message = json.loads(message_str)
            except json.JSONDecodeError:
                continue
            try:
                await handle_message(ws, message, client_ip)
            except Exception as e:
                import traceback
                traceback.print_exc()
                await send_to(ws, {"type": "error", "message": f"服务器错误: {e}"})
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        all_clients.discard(ws)
        if ws in ws_to_room:
            await leave_room(ws, reason="连接断开")
        ws_global_user.pop(ws, None)
        await broadcast_room_list()

async def main():
    init_db()
    host = "0.0.0.0"  # 允许所有外部网络接口访问
    port = 8765
    print(f"==================================================")
    print(f" 五子棋服务已启动！")
    print(f" 本地访问地址: http://localhost:{port}")
    print(f" 局域网访问:   http://<你的本机IP>:{port}")
    print(f" WebSocket:    ws://<你的IP>:{port}")
    print(f" 数据库文件:   {os.path.abspath(DB_FILE)}")
    print(f"==================================================")
    
    async with websockets.serve(
        handler, host, port,
        process_request=process_request,
        ping_interval=15,
        ping_timeout=10,
        close_timeout=5,
    ):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())