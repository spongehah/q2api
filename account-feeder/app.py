"""
Amazon Q 账号投喂服务
用于让其他人通过 URL 登录投喂账号到主服务
"""
import json
import asyncio
import uuid
import os
from typing import Dict, Optional
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 配置
API_SERVER = os.getenv("API_SERVER", "http://localhost:8000")

# OIDC 端点
OIDC_BASE = "https://oidc.us-east-1.amazonaws.com"
REGISTER_URL = f"{OIDC_BASE}/client/register"
DEVICE_AUTH_URL = f"{OIDC_BASE}/device_authorization"
TOKEN_URL = f"{OIDC_BASE}/token"
START_URL = "https://view.awsapps.com/start"

USER_AGENT = "aws-sdk-rust/1.3.9 os/windows lang/rust/1.87.0"
X_AMZ_USER_AGENT = "aws-sdk-rust/1.3.9 ua/2.1 api/ssooidc/1.88.0 os/windows lang/rust/1.87.0 m/E app/AmazonQ-For-CLI"
AMZ_SDK_REQUEST = "attempt=1; max=3"

# 内存存储授权会话
AUTH_SESSIONS = {}

app = FastAPI(title="Amazon Q 账号投喂服务")


# ============ 数据模型 ============
class AuthStartRequest(BaseModel):
    label: Optional[str] = None
    enabled: bool = True


class AccountCreate(BaseModel):
    label: Optional[str] = None
    clientId: str
    clientSecret: str
    refreshToken: str
    accessToken: Optional[str] = None
    enabled: bool = True


class BatchCreateRequest(BaseModel):
    accounts: list[dict]


# ============ OIDC 授权函数 ============
def _get_proxies() -> Optional[Dict[str, str]]:
    """获取代理配置"""
    proxy = os.getenv("HTTP_PROXY", "").strip()
    if proxy:
        return {"http://": proxy, "https://": proxy}
    return None


def make_headers() -> Dict[str, str]:
    """生成 OIDC 请求头"""
    return {
        "content-type": "application/json",
        "user-agent": USER_AGENT,
        "x-amz-user-agent": X_AMZ_USER_AGENT,
        "amz-sdk-request": AMZ_SDK_REQUEST,
        "amz-sdk-invocation-id": str(uuid.uuid4()),
    }


async def post_json(url: str, payload: Dict) -> httpx.Response:
    """发送 JSON POST 请求"""
    payload_str = json.dumps(payload, ensure_ascii=False)
    headers = make_headers()
    async with httpx.AsyncClient(proxies=_get_proxies(), timeout=60.0) as client:
        resp = await client.post(url, headers=headers, content=payload_str)
        return resp


async def register_client() -> tuple[str, str]:
    """注册 OIDC 客户端"""
    payload = {
        "clientName": "Amazon Q Developer for command line",
        "clientType": "public",
        "scopes": [
            "codewhisperer:completions",
            "codewhisperer:analysis",
            "codewhisperer:conversations",
        ],
    }
    r = await post_json(REGISTER_URL, payload)
    r.raise_for_status()
    data = r.json()
    return data["clientId"], data["clientSecret"]


async def start_device_authorization(client_id: str, client_secret: str) -> Dict:
    """开始设备授权流程"""
    payload = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "startUrl": START_URL,
    }
    r = await post_json(DEVICE_AUTH_URL, payload)
    r.raise_for_status()
    return r.json()


async def poll_for_tokens(
    client_id: str,
    client_secret: str,
    device_code: str,
    interval: int,
    expires_in: int,
    max_timeout_sec: int = 300,
) -> Dict:
    """轮询获取 tokens"""
    payload = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "deviceCode": device_code,
        "grantType": "urn:ietf:params:oauth:grant-type:device_code",
    }

    import time
    now = time.time()
    upstream_deadline = now + max(1, int(expires_in))
    cap_deadline = now + max_timeout_sec if max_timeout_sec > 0 else upstream_deadline
    deadline = min(upstream_deadline, cap_deadline)
    poll_interval = max(1, int(interval or 1))

    while time.time() < deadline:
        r = await post_json(TOKEN_URL, payload)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 400:
            try:
                err = r.json()
            except Exception:
                err = {"error": r.text}
            if str(err.get("error")) == "authorization_pending":
                await asyncio.sleep(poll_interval)
                continue
            r.raise_for_status()
        r.raise_for_status()

    raise TimeoutError("设备授权超时（5分钟内未完成授权）")


# ============ API 端点 ============
@app.get("/", response_class=HTMLResponse)
async def index():
    """返回前端页面"""
    html_path = Path(__file__).parent / "index.html"
    if not html_path.exists():
        return HTMLResponse("<h1>index.html 未找到</h1>", status_code=404)
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.post("/auth/start")
async def auth_start(body: Optional[AuthStartRequest] = None):
    """开始设备授权流程"""
    # 注册客户端
    client_id, client_secret = await register_client()

    # 开始设备授权
    device_data = await start_device_authorization(client_id, client_secret)

    # 生成会话 ID
    auth_id = str(uuid.uuid4())

    # 存储会话信息
    AUTH_SESSIONS[auth_id] = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "deviceCode": device_data["deviceCode"],
        "interval": device_data["interval"],
        "expiresIn": device_data["expiresIn"],
        "label": body.label if body else None,
        "enabled": body.enabled if body else True,
        "status": "pending"
    }

    return {
        "authId": auth_id,
        "verificationUriComplete": device_data["verificationUriComplete"],
        "userCode": device_data["userCode"],
        "expiresIn": device_data["expiresIn"],
        "interval": device_data["interval"]
    }


@app.post("/auth/claim/{auth_id}")
async def auth_claim(auth_id: str):
    """轮询并创建账号（调用原服务）"""
    if auth_id not in AUTH_SESSIONS:
        raise HTTPException(status_code=404, detail="授权会话不存在")

    session = AUTH_SESSIONS[auth_id]

    if session["status"] == "completed":
        raise HTTPException(status_code=400, detail="授权已完成")

    try:
        # 轮询获取 tokens
        tokens = await poll_for_tokens(
            client_id=session["clientId"],
            client_secret=session["clientSecret"],
            device_code=session["deviceCode"],
            interval=session["interval"],
            expires_in=session["expiresIn"],
            max_timeout_sec=300
        )

        # 调用原服务创建账号
        account_data = {
            "label": session.get("label") or f"投喂账号 {auth_id[:8]}",
            "clientId": session["clientId"],
            "clientSecret": session["clientSecret"],
            "refreshToken": tokens.get("refreshToken"),
            "accessToken": tokens.get("accessToken"),
            "enabled": False
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{API_SERVER}/v2/accounts",
                json=account_data,
                headers={"content-type": "application/json"}
            )
            r.raise_for_status()
            account = r.json()

        # 更新会话状态
        session["status"] = "completed"

        return {
            "status": "completed",
            "account": account
        }

    except TimeoutError as e:
        raise HTTPException(status_code=408, detail=str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"创建账号失败: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"未知错误: {str(e)}")


@app.post("/accounts/create")
async def create_account(account: AccountCreate):
    """创建单个账号（调用原服务）"""
    try:
        account_data = {
            "label": account.label or "手动投喂账号",
            "clientId": account.clientId,
            "clientSecret": account.clientSecret,
            "refreshToken": account.refreshToken,
            "accessToken": account.accessToken,
            "enabled": False
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{API_SERVER}/v2/accounts",
                json=account_data,
                headers={"content-type": "application/json"}
            )
            r.raise_for_status()
            return r.json()

    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"创建账号失败: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"未知错误: {str(e)}")


@app.post("/accounts/batch")
async def batch_create_accounts(request: BatchCreateRequest):
    """批量创建账号（调用主服务批量接口）"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(
                f"{API_SERVER}/v2/accounts/batch",
                json={"accounts": request.accounts},
                headers={"content-type": "application/json"}
            )
            r.raise_for_status()
            return r.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"批量创建失败: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"未知错误: {str(e)}")


@app.get("/health")
async def health():
    """健康检查"""
    return {"status": "ok", "service": "amazonq-account-feeder"}


if __name__ == "__main__":
    import sys
    port = 8001
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            break
    print(f"🚀 Amazon Q 账号投喂服务启动中...")
    print(f"📍 监听端口: {port}")
    print(f"🔗 主服务地址: {API_SERVER}")
    print(f"🌐 访问地址: http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
