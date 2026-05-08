# ClawVault 意图检测（Intent Guard）完整流程文档

## 架构概览

ClawVault 意图检测采用**两层过滤**架构：

```
AI 响应到达 interceptor
    ↓
第一层：规则评分（快速，本地执行）
    ├── 无 ToolCall → 跳过
    ├── 规则判定 ALLOW → 放行
    └── 规则判定 CONFIRM/BLOCK → 进入第二层
    ↓
第二层：LLM 二次判别（精准，远程调用）
    ├── LLM 判定 ALLOW（置信度≥0.7）→ 降级放行（规则误报）
    └── LLM 判定 CONFIRM/BLOCK → 维持拦截，补充理由
    ↓
最终决策 → interceptor 按 guard_mode 执行
```

---

## 完整数据流

### 阶段 0：请求拦截与元数据保存

**文件**：`src/claw_vault/proxy/interceptor.py` — `request()` 方法

当 AI 请求经过代理时，interceptor 从请求体中提取并保存用户消息：

```
用户发送 AI 请求
    ↓
interceptor.request() 保存：
    - user_text: 用户最后一条消息文本
    - agent_config: Agent 配置信息
    - original_body: 原始请求体
```

### 阶段 1：响应拦截与触发判断

**文件**：`src/claw_vault/proxy/interceptor.py` — `response()` 方法

AI 响应返回时：

```python
# 触发条件
if user_text and self.intent_enabled:
    # 解析响应体（JSON 或 SSE 流式）
    if isinstance(body, str):
        response_data = json.loads(body)       # 标准 JSON
        response_data = _aggregate_sse(body)   # SSE 流式聚合
    else:
        response_data = body

    # 调用检测引擎
    intent_violations = engine.scan_response_intent(response_data, user_text)
```

### 阶段 2：ToolCall 解析

**文件**：`src/claw_vault/detector/intent.py` — `parse_response_tool_calls()`

从 AI 响应中提取所有 ToolCall，兼容多种格式：

| 格式 | 解析路径 |
|------|---------|
| OpenAI | `choices[].message.tool_calls[].function.{name, arguments}` |
| Anthropic | `content[].type=tool_use` → `{name, input}` |
| SSE 聚合 | interceptor 预处理后的合并结构 |

返回 `ToolCallInfo(tool_name, arguments, call_id)` 列表。

### 阶段 3：用户意图推断

**文件**：`src/claw_vault/detector/intent.py` — `infer_user_intent()`

基于关键词评分推断用户意图类型：

```python
_USER_INTENT_KEYWORDS = {
    "FILE_READ":    ["查看", "读取", "cat", "read", "show", ...],
    "FILE_WRITE":   ["创建", "修改", "write", "edit", ...],
    "FILE_DELETE":  ["删除", "remove", "delete", ...],
    "CODE_BUILD":   ["编译", "构建", "build", "compile", ...],
    "INSTALL":      ["安装", "install", "setup", ...],
    "DEBUG":        ["调试", "debug", "diagnose", ...],
    "QUERY":        ["查询", "search", "find", ...],
    "EXECUTE":      ["运行", "执行", "run", "execute", ...],
    "CONFIG":       ["配置", "config", "设置", ...],
    "NETWORK":      ["下载", "上传", "download", "upload", ...],
}

# 对每种意图统计关键词命中数，取最高分
# 无匹配时返回 "UNKNOWN"
```

### 阶段 4：工具意图分类

**文件**：`src/claw_vault/detector/intent.py` — `classify_tool()`

对每个 ToolCall 分类其执行意图：

**匹配优先级：**

1. **exec/bash/shell 工具** → 解析 `command` 参数，用正则规则推断真实意图
2. **工具名精确匹配** → `_TOOL_INTENT_MAP` 字典
3. **工具名前缀/后缀匹配** → 模糊匹配
4. **兜底** → `UNKNOWN`

**Shell 命令意图推断规则（按优先级）：**

```
数据外泄（curl | wget + POST + 敏感路径）   → NETWORK_WRITE   (最高优先级)
安装类（apt/yum/pip install）               → INSTALL
下载类（wget/curl -O）                      → NETWORK_READ
文件写入（echo/tee/redirect）                → WRITE
文件删除（rm/del）                           → DELETE
文件读取（cat/head/tail/less）               → READ
系统查询（ps/lsof/netstat/whoami）           → QUERY
```

### 阶段 5：兼容矩阵检查

**文件**：`src/claw_vault/detector/intent.py` — `correlate()`

检查工具意图是否在用户意图的允许范围内：

```python
_COMPATIBILITY_MATRIX = {
    "FILE_READ":   {READ, QUERY, INSPECT, NETWORK_READ},
    "FILE_WRITE":  {READ, QUERY, INSPECT, WRITE, MODIFY, CREATE},
    "CODE_BUILD":  {READ, QUERY, INSPECT, WRITE, MODIFY, CREATE, EXECUTE, BUILD, INSTALL, NETWORK_READ},
    "INSTALL":     {READ, QUERY, EXECUTE, INSTALL, NETWORK_READ},
    "DEBUG":       {READ, QUERY, INSPECT, EXECUTE, NETWORK_READ},
    "UNKNOWN":     {READ, QUERY},   # 未知意图只允许低风险操作
    ...
}
```

**漂移值计算：**

```
基础漂移 = _BASE_DRIFT[工具意图]     # 不同意图的基础漂移值
不兼容   → 基础漂移 += 0.4
未知意图 → 基础漂移 *= 0.5
最终漂移 = min(漂移值, 1.0)
```

**初始决策：**
- 兼容 → `ALLOW`
- 不兼容且漂移 ≥ 0.6 → `BLOCK`
- 不兼容且漂移 < 0.6 → `CONFIRM`

### 阶段 6：五维风险评分

**文件**：`src/claw_vault/detector/intent.py` — `score_toolcall_risk()`

对每个 ToolCall 进行五个维度的风险评估：

| 维度 | 权重 | 检测内容 |
|------|------|---------|
| **参数风险** `param_risk` | 0.20 | `--force`, `-f`, `777`, `--yes`, 通配符数量 |
| **路径风险** `path_risk` | 0.20 | `/etc/`, `/root/`, `/.ssh/`, `/.env`, `/var/log/` |
| **意图基础风险** `intent_risk` | 0.15 | 工具意图类型的固有风险（如 DELETE > READ） |
| **上下文风险** `context_risk` | 0.20 | 外部 URL、IP 地址、环境变量引用、数据+URL组合 |
| **模式风险** `pattern_risk` | 0.25 | curl POST + 敏感文件、管道发送到网络、bash + curl + 敏感路径 |

```
总分 = Σ(维度分 × 权重)

风险等级：
    CRITICAL:  总分 ≥ 0.8
    HIGH:      总分 ≥ 0.6
    MEDIUM:    总分 ≥ 0.3
    LOW:       总分 < 0.3
```

### 阶段 7：决策升级

即使兼容矩阵判定 ALLOW，仍检查高风险模式：

```python
if decision == "ALLOW":
    pattern_risk = dimensions.get("pattern_risk", 0.0)
    context_risk = dimensions.get("context_risk", 0.0)
    path_risk    = dimensions.get("path_risk", 0.0)

    # 数据外泄组合：高危模式 + 敏感路径 → 强制 BLOCK
    if pattern_risk >= 0.95 and path_risk >= 0.5:
        decision = "BLOCK"

    # 高风险操作：升级为 CONFIRM
    elif pattern_risk >= 0.8 or context_risk >= 0.9:
        decision = "CONFIRM"
```

只有决策为 `CONFIRM` 或 `BLOCK` 的 ToolCall 才会生成 `IntentViolation` 记录。

### 阶段 8：LLM 二次判别

**文件**：`src/claw_vault/detector/intent.py` — `_llm_review_violations()`

对规则评分产生的违规，调用 LLM 进行语义级判断：

```
遍历每个 IntentViolation:
    ↓
检查风险等级是否达到触发阈值
    should_trigger_llm(v.risk_level, config.min_risk_for_llm)
    LOW < MEDIUM（默认）→ 不触发，保留违规
    HIGH/CRITICAL → 触发 LLM
    ↓
调用 judge_toolcall_sync()
    组装 prompt（用户指令 + 工具调用 + 规则评分参考）
    发送 OpenAI 兼容格式请求
    ↓
解析 LLM 响应（_parse_verdict）:
    1. 去除 markdown 代码块
    2. 优先从 Ⴆ... Ethiopian 块提取 JSON（MiniMax 等模型）
    3. 从正文提取 JSON
    4. 兜底：关键词匹配提取决策
    ↓
处理 LLM 判定结果:
    ├── ALLOW 且置信度 ≥ 0.7 → 移除违规（规则误报纠正）
    ├── ALLOW 但置信度 < 0.7 → 维持违规
    ├── CONFIRM → 维持违规，补充理由
    └── BLOCK → 维持违规，补充理由
    ↓
写入 LLM 字段到 IntentViolation:
    - llm_verdict: LLM 判定
    - llm_reason: LLM 理由
    - llm_confidence: 置信度
    - llm_raw_response: 原始输出（截断1000字符）
    - reason: 追加 "| [LLM确认] ..." 或 "| [LLM纠正] ..."
```

### 阶段 9：LLM API 调用详情

**文件**：`src/claw_vault/detector/intent_llm.py`

**请求格式（OpenAI 兼容）：**

```json
{
    "model": "MiniMax-M2.5",
    "messages": [
        {
            "role": "system",
            "content": "你是 AI Agent 安全助手...【输出JSON】..."
        },
        {
            "role": "user",
            "content": "【用户原始指令】\n按教程安装 nginx\n\n【Agent 执行的工具调用】\ntool_name: exec\narguments: {...}\n实际命令: curl -X POST...\n\n【规则评分参考】\n规则决策: BLOCK\n规则原因: ...\n风险评分: 0.85"
        }
    ],
    "temperature": 0.1,
    "max_tokens": 4096
}
```

**响应解析策略：**

```
LLM 原始响应
    ↓
去除 markdown 代码块（```json ... ```）
    ↓
优先从 ->___ 块提取:
    ├── 直接 json.loads(block)
    └── 从 block 中提取花括号内的 JSON（支持嵌套）
    ↓
从正文提取 JSON:
    ├── 直接 json.loads(text)
    └── 正则提取 JSON 对象
    ↓
兜底：关键词匹配:
    block_kw  = ["超出授权", "违背指令", "恶意", "unauthorized", ...]
    allow_kw  = ["符合意图", "在授权范围内", "安全", "authorized", ...]
    confirm_kw = ["不确定", "需要确认", "uncertain", ...]
    → 按命中数最高者返回
```

**响应格式兼容：**
- OpenAI 格式：`choices[].message.content`
- Anthropic 格式：`content[].type=text → .text`

### 阶段 10：拦截决策与执行

**文件**：`src/claw_vault/proxy/interceptor.py` — `response()` 方法

根据 `guard_mode` 配置处理违规：

| guard_mode | 行为 |
|------------|------|
| **strict** | 拦截所有 CONFIRM/BLOCK 违规，返回伪造 LLM 响应阻止执行 |
| **interactive** | 拦截 HIGH/CRITICAL 违规，MEDIUM 仅警告 |
| **permissive** | 所有违规标记为 LOGGED，仅记录不拦截 |

拦截时生成伪造响应，让 AI Agent 认为工具调用失败：

```python
flow.response = self._make_llm_response(orig_body, block_msg)
# block_msg: "Tool call blocked by ClawVault Intent Guard: ..."
```

### 阶段 11：事件记录

**文件**：`src/claw_vault/dashboard/api.py` — `push_intent_event()`

违规事件写入内存事件列表，供 Dashboard API 查询：

```json
{
    "id": "uuid",
    "ts": "2026-05-08T10:59:25Z",
    "source": "proxy",
    "user_intent": "INSTALL",
    "guard_mode": "strict",
    "violation_count": 1,
    "violations": [{
        "tool_name": "exec",
        "tool_intent": "NETWORK_WRITE",
        "user_intent": "INSTALL",
        "is_compatible": false,
        "risk_score": 0.85,
        "risk_level": "CRITICAL",
        "drift_indicator": 0.9,
        "decision": "BLOCK",
        "reason": "规则原因 | [LLM确认] LLM原因",
        "tool_cmd": "curl -X POST ...",
        "tool_arguments": {"command": "..."},
        "llm_verdict": "BLOCK",
        "llm_reason": "详细理由...",
        "llm_confidence": 0.95,
        "llm_raw_response": "{\"decision\":\"BLOCK\",...}"
    }]
}
```

---

## 配置参考

**文件**：`src/claw_vault/config.py`

```yaml
intent:
  enabled: true                    # 是否启用意图检测
  guard_mode: strict               # permissive | interactive | strict
  llm:
    enabled: true                  # 是否启用 LLM 二次判别
    api_url: "https://api.edgefn.net/v1/chat/completions"
    api_key: "sk-xxx"
    model: "MiniMax-M2.5"
    timeout: 10.0                  # LLM 请求超时（秒）
    min_risk_for_llm: "MEDIUM"     # 触发 LLM 的最低风险等级
```

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `intent.enabled` | `true` | 总开关，关闭后跳过所有意图检测 |
| `intent.guard_mode` | `permissive` | 违规处理策略 |
| `intent.llm.enabled` | `false` | LLM 二次判别开关 |
| `intent.llm.api_url` | `""` | OpenAI 兼容 API 地址 |
| `intent.llm.api_key` | `""` | API 密钥 |
| `intent.llm.model` | `gpt-4o-mini` | 模型名称 |
| `intent.llm.timeout` | `10.0` | 请求超时秒数 |
| `intent.llm.min_risk_for_llm` | `MEDIUM` | LLM 触发的最低风险等级 |

---

## 关键决策点

| 决策点 | 位置 | 决策依据 | 可能结果 |
|--------|------|----------|----------|
| 是否启用意图检测 | `interceptor.py` | `intent.enabled` 配置 | 跳过 / 执行 |
| 用户意图类型 | `intent.py` | 关键词命中评分 | FILE_READ / INSTALL / UNKNOWN ... |
| 工具意图类型 | `intent.py` | 工具名 + shell 命令正则 | READ / NETWORK_WRITE / DELETE ... |
| 意图兼容性 | `intent.py` | 兼容矩阵查询 | 兼容 / 不兼容 |
| 初始决策 | `intent.py` | 漂移值阈值 | ALLOW / CONFIRM / BLOCK |
| 风险等级 | `intent.py` | 五维加权评分 | LOW / MEDIUM / HIGH / CRITICAL |
| 决策升级 | `intent.py` | 模式风险 + 上下文风险 | ALLOW → CONFIRM / BLOCK |
| LLM 触发 | `intent.py` | `min_risk_for_llm` 配置 | 触发 / 跳过 |
| LLM 判定 | `intent_llm.py` | JSON 解析 / 关键词兜底 | ALLOW / CONFIRM / BLOCK |
| 误报纠正 | `intent.py` | LLM 置信度 ≥ 0.7 | 移除违规 / 维持违规 |
| 最终拦截 | `interceptor.py` | `guard_mode` 配置 | 拦截 / 警告 / 记录 |

---

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/intent/status` | 获取意图防护状态和配置 |
| POST | `/api/intent/config` | 更新意图防护配置 |
| GET | `/api/intent/events` | 获取违规事件列表 |
| POST | `/api/intent/test` | 模拟测试（接收 user_text + response，返回检测结果） |

---

## 文件清单

| 文件 | 职责 |
|------|------|
| `src/claw_vault/proxy/interceptor.py` | 请求/响应拦截、guard_mode 执行 |
| `src/claw_vault/detector/engine.py` | 检测引擎，透传 intent.py 结果 |
| `src/claw_vault/detector/intent.py` | 核心检测逻辑（6 阶段规则评分 + LLM 二次判别编排） |
| `src/claw_vault/detector/intent_llm.py` | LLM 二次判别模块（API 调用、响应解析、兜底提取） |
| `src/claw_vault/config.py` | 配置定义（IntentConfig + IntentLLMConfig） |
| `src/claw_vault/dashboard/api.py` | Dashboard API 端点、事件记录序列化 |
| `src/claw_vault/dashboard/static/index.html` | 前端 UI（配置面板 + 测试面板 + 事件列表） |
