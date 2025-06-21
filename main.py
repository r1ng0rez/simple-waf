from flask import Flask, request, abort, jsonify, make_response
import re
import sqlite3
import logging
from functools import lru_cache
import requests
from urllib.parse import urljoin

app = Flask(__name__)

# ======== 配置区域 ========
TARGET_URL = "http://127.0.0.1/pikachu/"  # Pikachu靶场地址
WAF_PORT = 5000
LOG_FILE = "waf.log"
DB_FILE = "waf.db"


# ======== 初始化 ========
def init_db():
    """初始化数据库"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # 删除旧表（如果存在）
    c.execute("DROP TABLE IF EXISTS rules")
    c.execute("DROP TABLE IF EXISTS logs")
    c.execute("DROP TABLE IF EXISTS whitelist")

    # 重新创建规则表（包含name列）
    c.execute('''CREATE TABLE rules
                 (id INTEGER PRIMARY KEY, 
                 name TEXT,
                 pattern TEXT, 
                 method TEXT,
                 path TEXT,
                 action TEXT)''')

    # 日志表
    c.execute('''CREATE TABLE logs
                 (id INTEGER PRIMARY KEY,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 ip TEXT,
                 method TEXT,
                 path TEXT,
                 status INTEGER,
                 payload TEXT,
                 rule_id INTEGER)''')

    # 白名单表
    c.execute('''CREATE TABLE whitelist
                 (id INTEGER PRIMARY KEY,
                 ip TEXT UNIQUE,
                 note TEXT)''')

    conn.commit()
    conn.close()


def load_default_rules():
    """加载默认规则（修正后的版本）"""
    default_rules = [
        ("SQL Injection", r"(select|union|insert|delete|update|drop|alter|--|#|;|/\*|\*/)", None, None, "block"),
        ("XSS", r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)", None, None, "block"),
        ("Path Traversal", r"(\.\./|\./|/etc/passwd|/bin/sh)", None, None, "block"),
        ("RCE", r"(;|\|)(ls|cat|bash|sh|python|perl)\s", None, None, "block"),
        ("Admin Protection", None, "POST", "/admin", "block")
    ]

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.executemany(
        "INSERT INTO rules (name, pattern, method, path, action) VALUES (?, ?, ?, ?, ?)",
        default_rules
    )
    conn.commit()
    conn.close()


# ======== 核心功能 ========
def is_whitelisted(ip):
    """检查IP白名单"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,))
    result = c.fetchone()
    conn.close()
    return result is not None


def detect_attack(method, path, payload):
    """检测攻击"""
    if is_whitelisted(request.remote_addr):
        return None

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, name, pattern, method, path, action FROM rules")

    for rule in c.fetchall():
        rule_id, name, pattern, rule_method, rule_path, action = rule

        # 方法匹配
        if rule_method and rule_method != method:
            continue

        # 路径匹配
        if rule_path and rule_path != path:
            continue

        # 模式匹配
        if pattern:
            if payload and isinstance(payload, str) and re.search(pattern, payload, re.IGNORECASE):
                log_attack(rule_id, method, path, payload)
                return action
            elif payload and isinstance(payload, dict):
                for value in payload.values():
                    if re.search(pattern, str(value), re.IGNORECASE):
                        log_attack(rule_id, method, path, payload)
                        return action
    return None


def log_attack(rule_id, method, path, payload):
    """记录攻击日志"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (ip, method, path, status, payload, rule_id) VALUES (?, ?, ?, ?, ?, ?)",
        (request.remote_addr, method, path, 403, str(payload)[:500], rule_id)
    )
    conn.commit()
    conn.close()
    logging.warning(f"Blocked attack: IP={request.remote_addr} RuleID={rule_id} Path={path}")


# ======== 路由处理 ========
@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def proxy(path):
    """反向代理主路由"""
    # 获取请求数据
    payload = None
    if request.method in ["POST", "PUT"]:
        payload = request.get_json(silent=True) or request.form.to_dict()
    elif request.method == "GET":
        payload = request.query_string.decode()

    # 攻击检测
    action = detect_attack(request.method, path, payload)
    if action == "block":
        abort(403, description="Request blocked by WAF")

    # 转发请求到靶场
    target_url = urljoin(TARGET_URL, path)
    try:
        if request.method == "GET":
            resp = requests.get(target_url, params=request.args, headers=request.headers)
        else:
            resp = requests.request(
                request.method,
                target_url,
                json=request.get_json(silent=True),
                data=request.form,
                headers=request.headers
            )

        # 返回靶场响应
        response = make_response(resp.content)
        response.status_code = resp.status_code
        for key, value in resp.headers.items():
            if key.lower() not in ['content-encoding', 'transfer-encoding']:
                response.headers[key] = value
        return response

    except requests.exceptions.RequestException as e:
        logging.error(f"Proxy error: {str(e)}")
        abort(502, description="Bad Gateway")


# ======== 管理API ========
@app.route('/waf/admin/logs', methods=['GET'])
def get_logs():
    """获取日志"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''SELECT l.id, l.timestamp, l.ip, l.method, l.path, l.status, r.name as rule_name 
                 FROM logs l LEFT JOIN rules r ON l.rule_id = r.id 
                 ORDER BY l.timestamp DESC LIMIT 100''')
    logs = c.fetchall()
    conn.close()
    return jsonify([dict(zip(['id', 'timestamp', 'ip', 'method', 'path', 'status', 'rule_name'], log)) for log in logs])


@app.route('/waf/admin/rules', methods=['GET', 'POST'])
def manage_rules():
    """规则管理"""
    if request.method == 'GET':
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, pattern, method, path, action FROM rules")
        rules = c.fetchall()
        conn.close()
        return jsonify([dict(zip(['id', 'name', 'pattern', 'method', 'path', 'action'], rule)) for rule in rules])

    elif request.method == 'POST':
        data = request.get_json()
        if not data or 'name' not in data or 'action' not in data:
            abort(400, description="Missing required fields")

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            "INSERT INTO rules (name, pattern, method, path, action) VALUES (?, ?, ?, ?, ?)",
            (data['name'], data.get('pattern'), data.get('method'), data.get('path'), data['action'])
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})


# ======== 启动应用 ========
if __name__ == '__main__':
    # 初始化数据库
    init_db()
    load_default_rules()

    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

    logging.info("Starting WAF server...")
    app.run(host='0.0.0.0', port=WAF_PORT, debug=False)