# ClawVault + OpenClaw 代理配置指南

> 本文档详细说明如何将 ClawVault 配置为透明代理，为本地 OpenClaw 提供安全防护。

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                      OpenClaw (AI Agent)                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ TUI     │  │  Skills  │  │  Files   │  │ LLM Channels  │   │
│  └─────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
└────────┼──────────────┼──────────────┼───────────────┼───────────┘
         │              │              │               │
    HTTP_PROXY env   HTTP_PROXY    HTTP_PROXY     HTTP_PROXY
         │              │              │               │
         └──────────────┴──────────────┴───────────────┘
                              │
                              ▼
         ┌────────────────────────────────────────────┐
         │         ClawVault Proxy (:8765)            │
         │  ┌──────────────────────────────────────┐  │
         │  │        mitmproxy 透明代理             │  │
         │  │   • SSL/TLS 解密 (MITM)               │  │
         │  │   • Host 过滤 (intercept_hosts)       │  │
         │  │   • 请求/响应 拦截                    │  │
         │  └──────────────────────────────────────┘  │
         │                    │                       │
         │                    ▼                       │
         │  ┌──────────────────────────────────────┐  │
         │  │         检测引擎 (Detection Engine)   │  │
         │  │  • 敏感数据检测 (API Keys, 密码, PII)  │  │
         │  │  • 危险命令检测 (rm -rf, curl|bash)   │  │
         │  │  • 提示注入检测 (Prompt Injection)    │  │
         │  └──────────────────────────────────────┘  │
         │                    │                       │
         │                    ▼                       │
         │  ┌──────────────────────────────────────┐  │
         │  │           规则引擎 (Rule Engine)       │  │
         │  │   • allow / block / sanitize / ask   │  │
         │  └──────────────────────────────────────┘  │
         │                    │                       │
         │                    ▼                       │
         │  ┌──────────────────────────────────────┐  │
         │  │           审计日志 (Audit Store)      │  │
         │  │   • SQLite 本地存储                   │  │
         │  │   • 事件记录                           │  │
         │  └──────────────────────────────────────┘  │
         └────────────────────────────────────────────┘
                              │
                              ▼
         ┌────────────────────────────────────────────┐
         │         Dashboard (:8766)                  │
         │   • 实时事件监控                           │
         │   • 规则配置                               │
         │   • 安全报告                               │
         └────────────────────────────────────────────┘
```

## 配置流程

### 步骤 1: 配置 ClawVault 监听所有接口

编辑 `~/.ClawVault/config.yaml`:

```yaml
proxy:
  host: "0.0.0.0"        # 监听所有接口
  port: 8765
  ssl_verify: false      # 关闭 SSL 验证（mitmproxy 解密需要）
  intercept_hosts:
    - "api.openai.com"
    - "api.anthropic.com"
    - "api.siliconflow.cn"
    - "*.openai.azure.com"
    - "generativelanguage.googleapis.com"
    - "api.minimaxi.com"   # MiniMax API

dashboard:
  host: "0.0.0.0"        # 允许外部访问
  port: 8766
```

### 步骤 2: 安装 mitmproxy CA 证书

ClawVault 使用 mitmproxy 进行透明 HTTPS 代理。mitmproxy 需要生成自己的 CA 证书来解密 HTTPS 流量。

#### 2.1 启动 ClawVault 生成 CA 证书

```bash
clawvault start --dashboard-host 0.0.0.0
```

mitmproxy 会在首次启动时在 `~/.mitmproxy/` 目录下生成 CA 证书。

#### 2.2 安装 CA 证书到系统信任存储

**Ubuntu/Debian:**
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
sudo update-ca-certificates
```

**CentOS/RHEL:**
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.crt
sudo update-ca-trust
```

#### 2.3 验证证书安装

```bash
# 检查证书是否存在
ls -la /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt

# 验证系统信任
openssl verify /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
```

### 步骤 3: 配置 OpenClaw Gateway 使用代理

OpenClaw 的 Gateway 服务通过 systemd 运行。需要配置环境变量让所有 OpenClaw 进程使用代理。

#### 3.1 编辑 systemd service 文件

文件位置: `~/.config/systemd/user/openclaw-gateway.service`

```ini
[Unit]
Description=OpenClaw Gateway
After=network.target

[Service]
Type=simple
Environment=HTTP_PROXY=http://127.0.0.1:8765
Environment=HTTPS_PROXY=http://127.0.0.1:8765
Environment=NO_PROXY=localhost,127.0.0.1
Environment=NODE_TLS_REJECT_UNAUTHORIZED=0
ExecStart=/usr/bin/node /usr/lib/node_modules/openclaw/dist/gateway.js
Restart=always
User=ubuntu

[Install]
WantedBy=default.target
```

#### 3.2 重新加载 systemd

```bash
systemctl --user daemon-reload
systemctl --user restart openclaw-gateway
```

### 步骤 4: 启动 ClawVault

```bash
# 方式 1: 使用脚本启动
cd /home/ubuntu/open_source/ClawVault
./scripts/start.sh

# 方式 2: 手动启动
source venv/bin/activate
clawvault start --dashboard-host 0.0.0.0
```

### 步骤 5: 验证配置

#### 5.1 检查服务状态

```bash
# 检查 ClawVault 健康状态
curl -s http://127.0.0.1:8766/api/health | jq

# 检查 OpenClaw Gateway 状态
systemctl --user status openclaw-gateway
```

#### 5.2 访问 Dashboard

打开浏览器访问: `http://<server-ip>:8766`

在 Events 标签页应该能看到拦截的事件。

#### 5.3 测试检测功能

发送包含敏感数据的测试请求:

```bash
curl -x http://127.0.0.1:8765 https://api.openai.com/v1/models \
  -H "Authorization: Bearer sk-proj-test123456789"
```

或者在 OpenClaw TUI 中发送消息，观察 Dashboard 事件计数是否增加。

## 工作原理

### 透明代理 vs 转发代理 vs 反向代理

| 类型 | 原理 | 应用场景 |
|------|------|----------|
| **透明代理** | 网络层拦截，客户端无感知 | 企业网关、内容过滤 |
| **转发代理** | 客户端主动设置 HTTP_PROXY | 科学上网、开发调试 |
| **反向代理** | 服务端前置代理，负载均衡 | CDN、API 网关 |

ClawVault 使用的是**透明代理模式**，但实现上结合了转发代理的机制：

1. OpenClaw 通过 `HTTP_PROXY` 环境变量主动将请求发送到 ClawVault
2. ClawVault 使用 mitmproxy 作为底层代理
3. mitmproxy 对 HTTPS 请求进行 MITM (中间人) 解密

### HTTPS 拦截原理

#### 为什么需要解密切尔?

正常 HTTPS 通信:
```
Client ←───────────────→ Server
      (加密通道，代理无法查看内容)
```

使用 mitmproxy 进行 HTTPS 拦截:
```
Client ←───────→ mitmproxy ←───────→ Server
          (1)          (2)

(1) Client 与 mitmproxy 之间的加密通道 (mitmproxy 生成证书)
(2) mitmproxy 与 Server 之间的加密通道 (原始证书)
```

mitmproxy 会:
1. 与客户端建立 TLS 连接，使用自签名 CA 证书
2. 与目标服务器建立 TLS 连接，使用原始服务器证书
3. 解密客户端请求，重新加密发送到服务器
4. 解密服务器响应，重新加密返回给客户端

#### 证书信任链

```
根证书颁发机构 (系统信任)
    └── mitmproxy CA (自签名)
         └── mitmproxy 生成的服务证书
              └── api.openai.com (伪造)
```

## 拦截的主机列表

ClawVault 默认拦截以下主机:

| 主机 | 说明 |
|------|------|
| `api.openai.com` | OpenAI API |
| `api.anthropic.com` | Anthropic API |
| `api.siliconflow.cn` | SiliconFlow API |
| `*.openai.azure.com` | Azure OpenAI |
| `generativelanguage.googleapis.com` | Google Gemini |
| `api.minimaxi.com` | MiniMax API |

可以在 `config.yaml` 中添加更多主机:

```yaml
proxy:
  intercept_hosts:
    - "api.openai.com"
    - "api.anthropic.com"
    - "custom-api.example.com"
```

## 故障排查

### Dashboard 显示 0 事件

**原因**: OpenClaw 的请求没有经过 ClawVault 代理

**排查步骤**:

1. 确认 ClawVault 正在运行:
   ```bash
   curl -s http://127.0.0.1:8766/api/health
   ```

2. 确认代理端口可访问:
   ```bash
   curl -s http://127.0.0.1:8765
   ```

3. 检查 OpenClaw Gateway 环境变量:
   ```bash
   systemctl --user show openclaw-gateway | grep PROXY
   ```

4. 检查 OpenClaw 使用的 API 主机是否在 intercept_hosts 中

### TLS 握手失败

**错误**: `client does not trust proxy certificate`

**解决**:

1. 确认 CA 证书已安装到系统信任存储
2. 确认 `ssl_verify: false` 在 config.yaml 中
3. 确认 `NODE_TLS_REJECT_UNAUTHORIZED=0` 在 systemd 服务中

### OpenClaw TUI 无法启动

**排查**:

1. 检查端口冲突:
   ```bash
   ps aux | grep openclaw
   lsof -i :18789
   ```

2. 确认配置文件端口正确:
   ```bash
   cat ~/.openclaw/openclaw.json | grep port
   ```

3. 检查 node 模块路径:
   ```bash
   ls -la /usr/lib/node_modules/openclaw/node_modules/@larksuiteoapi
   ```

## 安全说明

### 为什么需要关闭 SSL 验证?

`ssl_verify: false` 和 `NODE_TLS_REJECT_UNAUTHORIZED=0` 是必要的，因为:

1. mitmproxy 需要解密的 HTTPS 流量才能进行安全检测
2. 自签名证书不被默认信任
3. 这是透明代理的必要条件

### 安全边界

- ClawVault 只拦截配置在 `intercept_hosts` 中的主机
- 所有检测都在本地进行，不会发送数据到外部
- 敏感信息可以自动脱敏或拦截
- 完整的行为日志存储在本地 SQLite 数据库

## 相关文档

- [OpenClaw 集成](./OPENCLAW_INTEGRATION.md) - 详细的 OpenClaw 集成指南
- [架构文档](./architecture.md) - 系统架构详解
- [部署指南](./INSTALL_PRODUCTION.md) - 生产环境部署