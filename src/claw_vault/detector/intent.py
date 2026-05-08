"""意图识别引擎 — 从 LCIR 适配，用于 AI 响应方向的 ToolCall 越界检测。

核心流程：
1. 用户意图推断：从用户自然语言推断意图类型
2. ToolCall 解析：从 AI 响应中提取 ToolCall
3. 工具意图分类：将 ToolCall 映射到 CommandIntent
4. 上下文关联：检查 ToolCall 意图是否与用户意图兼容
5. 风险评分：评估 ToolCall 的综合风险
6. 综合决策：生成违规列表
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

class CommandIntent(Enum):
    """工具调用的意图类型（从 LCIR 复用，覆盖 AI ToolCall 场景）。"""
    READ = "READ"
    QUERY = "QUERY"
    INSPECT = "INSPECT"
    WRITE = "WRITE"
    APPEND = "APPEND"
    MODIFY = "MODIFY"
    CREATE = "CREATE"
    DELETE = "DELETE"
    CLEAN = "CLEAN"
    EXECUTE = "EXECUTE"
    INSTALL = "INSTALL"
    BUILD = "BUILD"
    SERVICE = "SERVICE"
    NETWORK_READ = "NETWORK_READ"
    NETWORK_WRITE = "NETWORK_WRITE"
    NETWORK_LISTEN = "NETWORK_LISTEN"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    AUTH = "AUTH"
    PERMISSION = "PERMISSION"
    UNKNOWN = "UNKNOWN"


@dataclass
class ToolCallInfo:
    """从 AI 响应中解析出的工具调用。"""
    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""


@dataclass
class IntentViolation:
    """意图违规记录。"""
    tool_name: str
    tool_intent: CommandIntent
    user_intent: str
    is_compatible: bool
    risk_score: float
    risk_level: str  # LOW / MEDIUM / HIGH / CRITICAL
    drift_indicator: float
    decision: str  # ALLOW / CONFIRM / BLOCK / LOGGED
    reason: str
    tool_arguments: dict[str, Any] = field(default_factory=dict)
    tool_cmd: str = ""  # exec/bash 类工具的实际命令
    user_prompt: str = ""  # 用户的原始指令文本
    llm_verdict: str = ""        # LLM 判定结果 (ALLOW/CONFIRM/BLOCK)
    llm_reason: str = ""         # LLM 判断理由
    llm_confidence: float = 0.0  # LLM 置信度
    llm_raw_response: str = ""   # LLM 原始输出


# ---------------------------------------------------------------------------
# 1. 用户意图推断（LCIR 没有，新建）
# ---------------------------------------------------------------------------

# 用户自然语言关键词 → ContextCorrelator._COMPATIBILITY_MATRIX 的 key
_USER_INTENT_KEYWORDS: dict[str, list[str]] = {
    "FILE_READ": [
        "查看", "显示", "读取", "检查", "搜索", "看", "列出", "浏览",
        "cat", "read", "show", "display", "view", "list", "check", "inspect",
        "find", "grep", "head", "tail", "less", "more",
    ],
    "FILE_WRITE": [
        "创建", "修改", "编辑", "保存", "写入", "更新", "改", "写",
        "create", "write", "edit", "modify", "update", "save", "change",
    ],
    "FILE_DELETE": [
        "删除", "清除", "移除", "清空", "删", "去掉",
        "delete", "remove", "clean", "clear", "erase", "drop",
    ],
    "CODE_BUILD": [
        "编译", "构建", "打包", "测试", "运行项目", "启动",
        "build", "compile", "test", "run", "start", "make",
    ],
    "INSTALL": [
        "安装", "部署", "配置", "设置", "初始化",
        "install", "setup", "deploy", "configure", "init",
    ],
    "DEPLOY": [
        "发布", "上线", "推送", "部署到", "生产",
        "deploy", "release", "publish", "push", "production",
    ],
    "DEBUG": [
        "调试", "排查", "诊断", "排错", "定位问题",
        "debug", "troubleshoot", "diagnose", "investigate",
    ],
    "NETWORK_ACCESS": [
        "下载", "上传", "请求", "访问", "发送", "网络",
        "download", "upload", "request", "fetch", "send", "network",
    ],
    "SYSTEM_ADMIN": [
        "管理", "监控", "运维", "系统", "服务器",
        "admin", "manage", "monitor", "system", "server",
    ],
}


def infer_user_intent(user_text: str) -> str:
    """从用户自然语言推断意图类型（关键词规则评分）。

    返回 ContextCorrelator._COMPATIBILITY_MATRIX 的 key，
    找不到时返回 "UNKNOWN"。
    """
    if not user_text:
        return "UNKNOWN"

    text_lower = user_text.lower()
    scores: dict[str, int] = {}

    for intent_key, keywords in _USER_INTENT_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > 0:
            scores[intent_key] = score

    if not scores:
        return "UNKNOWN"

    return max(scores, key=scores.get)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. ToolCall 解析器（复用 dashboard/api.py 的解析模式，扩展到响应体）
# ---------------------------------------------------------------------------

def parse_response_tool_calls(response_body: dict | list) -> list[ToolCallInfo]:
    """从 AI 响应体中解析 ToolCall。

    支持格式：
    - OpenAI 响应: choices[].message.tool_calls[].function
    - Anthropic 响应: content[].type=tool_use
    - SSE 聚合后的 body: 同上
    """
    tool_calls: list[ToolCallInfo] = []

    if isinstance(response_body, list):
        # 可能是 SSE 聚合的结果列表
        for item in response_body:
            if isinstance(item, dict):
                tool_calls.extend(_parse_single_response(item))
        return tool_calls

    if isinstance(response_body, dict):
        tool_calls.extend(_parse_single_response(response_body))

    return tool_calls


def _parse_single_response(data: dict) -> list[ToolCallInfo]:
    """解析单个响应对象中的 ToolCall。"""
    tool_calls: list[ToolCallInfo] = []

    # OpenAI 格式: choices[].message.tool_calls[]
    choices = data.get("choices", [])
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message", {})
            if not isinstance(message, dict):
                continue
            tc_list = message.get("tool_calls", [])
            if not isinstance(tc_list, list):
                continue
            for tc in tc_list:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function", {})
                name = fn.get("name", tc.get("name", "unknown"))
                params_raw = fn.get("arguments", "{}")
                try:
                    params = json.loads(params_raw) if isinstance(params_raw, str) else params_raw
                except (ValueError, TypeError):
                    params = params_raw if isinstance(params_raw, dict) else {}
                tool_calls.append(ToolCallInfo(
                    tool_name=name,
                    arguments=params if isinstance(params, dict) else {},
                    call_id=tc.get("id", ""),
                ))

    # Anthropic 格式: content[].type=tool_use
    content = data.get("content", [])
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name", "unknown")
                inp = block.get("input", {})
                tool_calls.append(ToolCallInfo(
                    tool_name=name,
                    arguments=inp if isinstance(inp, dict) else {},
                    call_id=block.get("id", ""),
                ))

    return tool_calls


# ---------------------------------------------------------------------------
# 3. 工具名 → 意图映射（替代 LCIR 的命令映射）
# ---------------------------------------------------------------------------

_TOOL_INTENT_MAP: dict[str, CommandIntent] = {
    # 通用执行类
    "bash": CommandIntent.EXECUTE,
    "exec": CommandIntent.EXECUTE,
    "execute": CommandIntent.EXECUTE,
    "shell": CommandIntent.EXECUTE,
    "run_command": CommandIntent.EXECUTE,
    "run": CommandIntent.EXECUTE,
    "command": CommandIntent.EXECUTE,
    "terminal": CommandIntent.EXECUTE,
    "subprocess": CommandIntent.EXECUTE,
    "cmd": CommandIntent.EXECUTE,
    "powershell": CommandIntent.EXECUTE,

    # 文件读取类
    "read_file": CommandIntent.READ,
    "get_file": CommandIntent.READ,
    "cat": CommandIntent.READ,
    "head": CommandIntent.READ,
    "tail": CommandIntent.READ,
    "less": CommandIntent.READ,
    "view_file": CommandIntent.READ,
    "show_file": CommandIntent.READ,
    "file_read": CommandIntent.READ,
    "open_file": CommandIntent.READ,

    # 文件写入/创建类
    "write_file": CommandIntent.WRITE,
    "create_file": CommandIntent.CREATE,
    "save_file": CommandIntent.WRITE,
    "edit_file": CommandIntent.MODIFY,
    "update_file": CommandIntent.MODIFY,
    "append_file": CommandIntent.APPEND,
    "patch_file": CommandIntent.MODIFY,
    "file_write": CommandIntent.WRITE,
    "file_edit": CommandIntent.MODIFY,

    # 文件删除类
    "delete_file": CommandIntent.DELETE,
    "remove_file": CommandIntent.DELETE,
    "rm": CommandIntent.DELETE,
    "unlink": CommandIntent.DELETE,
    "file_delete": CommandIntent.DELETE,

    # 网络 - 读
    "http_get": CommandIntent.NETWORK_READ,
    "fetch": CommandIntent.NETWORK_READ,
    "get": CommandIntent.NETWORK_READ,
    "web_search": CommandIntent.NETWORK_READ,
    "web_fetch": CommandIntent.NETWORK_READ,
    "download": CommandIntent.NETWORK_READ,
    "curl": CommandIntent.NETWORK_READ,
    "wget": CommandIntent.NETWORK_READ,
    "request": CommandIntent.NETWORK_READ,

    # 网络 - 写
    "http_post": CommandIntent.NETWORK_WRITE,
    "http_put": CommandIntent.NETWORK_WRITE,
    "http_patch": CommandIntent.NETWORK_WRITE,
    "post": CommandIntent.NETWORK_WRITE,
    "put": CommandIntent.NETWORK_WRITE,
    "send_data": CommandIntent.NETWORK_WRITE,
    "upload": CommandIntent.NETWORK_WRITE,
    "send": CommandIntent.NETWORK_WRITE,
    "submit": CommandIntent.NETWORK_WRITE,
    "notify": CommandIntent.NETWORK_WRITE,
    "webhook": CommandIntent.NETWORK_WRITE,
    "emit": CommandIntent.NETWORK_WRITE,

    # 网络 - 连接/监听
    "connect": CommandIntent.NETWORK_CONNECT,
    "listen": CommandIntent.NETWORK_LISTEN,
    "ssh": CommandIntent.NETWORK_CONNECT,
    "scp": CommandIntent.NETWORK_WRITE,
    "rsync": CommandIntent.NETWORK_WRITE,

    # 安装/构建类
    "install": CommandIntent.INSTALL,
    "pip_install": CommandIntent.INSTALL,
    "npm_install": CommandIntent.INSTALL,
    "build": CommandIntent.BUILD,
    "make": CommandIntent.BUILD,
    "compile": CommandIntent.BUILD,

    # 服务管理
    "systemctl": CommandIntent.SERVICE,
    "service": CommandIntent.SERVICE,
    "docker": CommandIntent.SERVICE,
    "kubectl": CommandIntent.SERVICE,

    # 查询/检查类
    "list": CommandIntent.QUERY,
    "search": CommandIntent.QUERY,
    "find": CommandIntent.QUERY,
    "grep": CommandIntent.QUERY,
    "which": CommandIntent.QUERY,
    "env": CommandIntent.QUERY,
    "printenv": CommandIntent.QUERY,
    "whoami": CommandIntent.QUERY,
    "ls": CommandIntent.QUERY,
    "stat": CommandIntent.INSPECT,
    "ps": CommandIntent.INSPECT,
    "inspect": CommandIntent.INSPECT,

    # 权限/认证类
    "sudo": CommandIntent.AUTH,
    "chmod": CommandIntent.PERMISSION,
    "chown": CommandIntent.PERMISSION,
}

# 前缀/后缀模糊匹配映射
_TOOL_PREFIX_MAP: dict[str, CommandIntent] = {
    "read_": CommandIntent.READ,
    "get_": CommandIntent.READ,
    "list_": CommandIntent.QUERY,
    "search_": CommandIntent.QUERY,
    "find_": CommandIntent.QUERY,
    "write_": CommandIntent.WRITE,
    "create_": CommandIntent.CREATE,
    "update_": CommandIntent.MODIFY,
    "edit_": CommandIntent.MODIFY,
    "delete_": CommandIntent.DELETE,
    "remove_": CommandIntent.DELETE,
    "install_": CommandIntent.INSTALL,
    "send_": CommandIntent.NETWORK_WRITE,
    "fetch_": CommandIntent.NETWORK_READ,
    "download_": CommandIntent.NETWORK_READ,
    "upload_": CommandIntent.NETWORK_WRITE,
    "exec_": CommandIntent.EXECUTE,
    "run_": CommandIntent.EXECUTE,
}

_TOOL_SUFFIX_MAP: dict[str, CommandIntent] = {
    "_read": CommandIntent.READ,
    "_get": CommandIntent.READ,
    "_list": CommandIntent.QUERY,
    "_search": CommandIntent.QUERY,
    "_write": CommandIntent.WRITE,
    "_create": CommandIntent.CREATE,
    "_update": CommandIntent.MODIFY,
    "_edit": CommandIntent.MODIFY,
    "_delete": CommandIntent.DELETE,
    "_remove": CommandIntent.DELETE,
    "_install": CommandIntent.INSTALL,
    "_send": CommandIntent.NETWORK_WRITE,
    "_fetch": CommandIntent.NETWORK_READ,
    "_download": CommandIntent.NETWORK_READ,
    "_upload": CommandIntent.NETWORK_WRITE,
    "_exec": CommandIntent.EXECUTE,
    "_run": CommandIntent.EXECUTE,
}


def classify_tool(tool_call: ToolCallInfo) -> CommandIntent:
    """将 ToolCall 分类为意图类型。

    匹配优先级：
    1. 解析 exec/bash/shell 的 command 参数，推断真实意图
    2. 工具名精确匹配
    3. 前缀/后缀模糊匹配
    4. UNKNOWN
    """
    name_lower = tool_call.tool_name.lower()

    # 对于 shell/exec 类工具，解析 command 参数推断真实意图
    if name_lower in ("exec", "bash", "shell", "execute", "run_command", "run", "command", "terminal", "subprocess", "cmd", "powershell"):
        command_arg = tool_call.arguments.get("command", "")
        if isinstance(command_arg, str) and command_arg.strip():
            real_intent = _classify_shell_command(command_arg)
            if real_intent is not None:
                return real_intent

    # 精确匹配
    if name_lower in _TOOL_INTENT_MAP:
        return _TOOL_INTENT_MAP[name_lower]

    # 前缀匹配
    for prefix, intent in _TOOL_PREFIX_MAP.items():
        if name_lower.startswith(prefix):
            return intent

    # 后缀匹配
    for suffix, intent in _TOOL_SUFFIX_MAP.items():
        if name_lower.endswith(suffix):
            return intent

    return CommandIntent.UNKNOWN


# shell 命令 → 意图映射的关键词规则
_SHELL_INTENT_RULES: list[tuple[re.Pattern[str], CommandIntent]] = [
    # === 数据外泄（最高优先级）===
    # curl POST/发送数据（含变量引用）
    (re.compile(r"(curl|wget)\s+.*(-X\s+POST|--data\b|-d\s|-F\s|--form\b)", re.I), CommandIntent.NETWORK_WRITE),
    # 管道发送到网络
    (re.compile(r"\|\s*(curl|wget|nc|ncat)\s+", re.I), CommandIntent.NETWORK_WRITE),
    # 重定向到 /dev/tcp
    (re.compile(r">\s*/dev/(tcp|udp)/", re.I), CommandIntent.NETWORK_WRITE),
    # === 安装类 ===
    (re.compile(r"\b(apt|yum|brew|pip|npm|gem|cargo|go)\s+install\b", re.I), CommandIntent.INSTALL),
    (re.compile(r"\b(dpkg|rpm)\s+-i\b", re.I), CommandIntent.INSTALL),
    (re.compile(r"\bmake\s+(install|all)\b", re.I), CommandIntent.INSTALL),
    # python/perl/ruby 执行安装脚本（非贪婪，避免跨链匹配）
    (re.compile(r"\bpython3?\s+[^\s;&|]+(Setup\.py|setup\.py|install\b)", re.I), CommandIntent.INSTALL),
    # curl/wget 下载安装脚本（仅限单独一条下载命令）
    (re.compile(r"^\s*(curl|wget)\s+[^;&|]+?\.(sh|py|pl|rb)\b", re.I), CommandIntent.INSTALL),
    # === 下载类（纯下载）===
    (re.compile(r"\bcurl\s+-s[Oo]\b", re.I), CommandIntent.NETWORK_READ),
    (re.compile(r"\b(curl|wget)\s+.*(-[Oo]|--output)\b", re.I), CommandIntent.NETWORK_READ),
    (re.compile(r"\b(curl|wget|fetch)\s+", re.I), CommandIntent.NETWORK_READ),
    # === 下载类 ===
    (re.compile(r"\b(curl|wget)\s+.*(-[Oo]|--output)\b", re.I), CommandIntent.NETWORK_READ),
    (re.compile(r"\bcurl\s+-s[Oo]\b", re.I), CommandIntent.NETWORK_READ),
    (re.compile(r"\b(curl|wget|fetch)\s+", re.I), CommandIntent.NETWORK_READ),
    # 数据外泄：curl/wget POST + 敏感文件
    (re.compile(r"(curl|wget).*(-d\s|--data|-F\s|--form|POST).*\b(cat|<)\s", re.I), CommandIntent.NETWORK_WRITE),
    (re.compile(r"(curl|wget).*\b(-d\s|--data\b|-F\s|--form\b)\b", re.I), CommandIntent.NETWORK_WRITE),
    # 文件读取
    (re.compile(r"\b(cat|head|tail|less|more|view)\s+", re.I), CommandIntent.READ),
    (re.compile(r"\b(read|view|show|display|print)\s+", re.I), CommandIntent.READ),
    # 文件写入
    (re.compile(r"\b(tee|write|echo\s+.*>\s*)", re.I), CommandIntent.WRITE),
    (re.compile(r"\bsed\s+(-i|--in-place)", re.I), CommandIntent.MODIFY),
    # 文件删除
    (re.compile(r"\b(rm|del|remove|unlink|rmdir)\s+", re.I), CommandIntent.DELETE),
    # 查询/检查
    (re.compile(r"\b(ls|list|find|which|whereis|locate|stat|file|du|df)\b", re.I), CommandIntent.QUERY),
    (re.compile(r"\b(ps|top|htop|whoami|id|uname|env|printenv)\b", re.I), CommandIntent.INSPECT),
    (re.compile(r"\bgrep|awk|sed\b", re.I), CommandIntent.QUERY),
    # 服务管理
    (re.compile(r"\b(systemctl|service|docker|kubectl)\s+", re.I), CommandIntent.SERVICE),
    # 网络连接
    (re.compile(r"\b(ssh|scp|rsync|nc|ncat|telnet)\s+", re.I), CommandIntent.NETWORK_CONNECT),
    # 网络监听
    (re.compile(r"\b(nc|ncat|socat)\s+.*(-l|--listen)\b", re.I), CommandIntent.NETWORK_LISTEN),
    # 构建编译
    (re.compile(r"\b(make|gcc|g\+\+|cmake|cargo|go\s+build)\b", re.I), CommandIntent.BUILD),
    # 权限修改
    (re.compile(r"\b(chmod|chown|chgrp)\s+", re.I), CommandIntent.PERMISSION),
    # 认证
    (re.compile(r"\b(sudo|su|passwd)\b", re.I), CommandIntent.AUTH),
]


def _classify_shell_command(command: str) -> CommandIntent | None:
    """从 shell 命令内容推断真实意图。

    返回匹配到的第一个意图，按规则列表顺序优先级决定。
    如果命令中包含管道/链式操作，取最敏感（最危险）的意图。
    """
    # 按优先级匹配：安装 > 外泄 > 写入 > 删除 > 读取 > 查询
    for pattern, intent in _SHELL_INTENT_RULES:
        if pattern.search(command):
            return intent
    return None


# ---------------------------------------------------------------------------
# 4. 上下文关联（从 LCIR ContextCorrelator 直接复用）
# ---------------------------------------------------------------------------

# 意图兼容矩阵：用户意图 -> 兼容的工具意图集合
_COMPATIBILITY_MATRIX: dict[str, set[str]] = {
    "FILE_READ": {
        "READ", "QUERY", "INSPECT", "NETWORK_READ",
    },
    "FILE_WRITE": {
        "READ", "QUERY", "INSPECT",
        "WRITE", "APPEND", "MODIFY", "CREATE",
    },
    "FILE_DELETE": {
        "READ", "QUERY", "INSPECT", "DELETE", "CLEAN",
    },
    "CODE_BUILD": {
        "READ", "QUERY", "INSPECT",
        "WRITE", "APPEND", "MODIFY", "CREATE",
        "EXECUTE", "BUILD", "INSTALL",
        "NETWORK_READ",
    },
    "DEPLOY": {
        "READ", "QUERY", "INSPECT",
        "WRITE", "MODIFY", "CREATE",
        "EXECUTE", "BUILD", "INSTALL", "SERVICE",
        "NETWORK_READ", "NETWORK_CONNECT",
        "AUTH",
    },
    "SYSTEM_ADMIN": {
        "READ", "QUERY", "INSPECT",
        "WRITE", "APPEND", "MODIFY", "CREATE",
        "DELETE", "CLEAN",
        "EXECUTE", "BUILD", "INSTALL", "SERVICE",
        "NETWORK_READ", "NETWORK_WRITE",
        "NETWORK_LISTEN", "NETWORK_CONNECT",
        "AUTH", "PERMISSION",
    },
    "DEBUG": {
        "READ", "QUERY", "INSPECT",
        "EXECUTE", "NETWORK_READ",
    },
    "INSTALL": {
        "READ", "QUERY",
        "EXECUTE", "INSTALL", "BUILD",
        "NETWORK_READ", "NETWORK_CONNECT",
        "WRITE", "MODIFY", "CREATE",
    },
    "NETWORK_ACCESS": {
        "NETWORK_READ", "NETWORK_WRITE",
        "NETWORK_CONNECT", "NETWORK_LISTEN",
        "READ", "QUERY",
    },
    "UNKNOWN": {
        # 未知意图时，允许所有低风险操作
        "READ", "QUERY", "INSPECT",
    },
}

# 命令意图的基础漂移值
_BASE_DRIFT: dict[str, float] = {
    "READ": 0.0,
    "QUERY": 0.0,
    "INSPECT": 0.05,
    "CREATE": 0.1,
    "APPEND": 0.1,
    "WRITE": 0.2,
    "MODIFY": 0.2,
    "EXECUTE": 0.15,
    "BUILD": 0.1,
    "SERVICE": 0.25,
    "INSTALL": 0.3,
    "CLEAN": 0.35,
    "DELETE": 0.4,
    "NETWORK_READ": 0.1,
    "NETWORK_CONNECT": 0.2,
    "NETWORK_WRITE": 0.5,
    "NETWORK_LISTEN": 0.6,
    "AUTH": 0.5,
    "PERMISSION": 0.6,
    "UNKNOWN": 0.3,
}

# 意图基础风险值（从 LCIR risk_weights.json 复用）
_INTENT_BASE_RISK: dict[str, float] = {
    "READ": 0.0,
    "QUERY": 0.0,
    "INSPECT": 0.0,
    "CREATE": 0.2,
    "APPEND": 0.2,
    "WRITE": 0.4,
    "MODIFY": 0.4,
    "EXECUTE": 0.3,
    "BUILD": 0.3,
    "SERVICE": 0.4,
    "INSTALL": 0.5,
    "NETWORK_READ": 0.2,
    "NETWORK_CONNECT": 0.3,
    "NETWORK_WRITE": 0.7,
    "NETWORK_LISTEN": 0.8,
    "DELETE": 0.8,
    "CLEAN": 0.7,
    "AUTH": 0.9,
    "PERMISSION": 0.9,
    "UNKNOWN": 0.5,
}


def correlate(
    user_intent: str,
    tool_intent: CommandIntent,
) -> tuple[bool, float, str, str]:
    """检查工具意图是否与用户意图兼容（从 LCIR ContextCorrelator 适配）。

    返回：(是否兼容, 漂移指标, 决策(ALLOW/CONFIRM/BLOCK), 原因)
    """
    cmd_value = tool_intent.value

    # 检查兼容性
    compatible_set = _COMPATIBILITY_MATRIX.get(user_intent, set())
    is_compatible = cmd_value in compatible_set

    # 计算匹配分数
    match_score = 1.0 - _BASE_DRIFT.get(cmd_value, 0.2) if is_compatible else 0.0

    # 计算漂移指标
    base = _BASE_DRIFT.get(cmd_value, 0.2)
    if not is_compatible:
        base += 0.4
    if user_intent == "UNKNOWN":
        base *= 0.5
    drift = min(base, 1.0)

    # 决策
    if is_compatible:
        decision = "ALLOW"
        reason = f"工具意图 {cmd_value} 与用户意图 {user_intent} 兼容"
    elif drift >= 0.6:
        decision = "BLOCK"
        reason = f"工具意图 {cmd_value} 与用户意图 {user_intent} 不兼容且漂移={drift:.2f}"
    else:
        decision = "CONFIRM"
        reason = f"意图偏离: 工具={cmd_value}, 用户={user_intent}, 漂移={drift:.2f}"

    return is_compatible, drift, decision, reason


# ---------------------------------------------------------------------------
# 5. ToolCall 风险评分（从 LCIR RiskScorer 适配）
# ---------------------------------------------------------------------------

# 敏感路径模式
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    (re.compile(re.escape(p), re.IGNORECASE), score)
    for p, score in [
        ("/etc/", 0.8),
        ("/root/", 0.9),
        ("/.ssh/", 0.9),
        ("/.aws/", 0.9),
        ("/.env", 0.8),
        ("/.kube/", 0.7),
        ("/.gnupg/", 0.9),
        ("/.bashrc", 0.6),
        ("/.zshrc", 0.6),
        ("/.profile", 0.6),
        ("/.gitconfig", 0.5),
        ("/.npmrc", 0.7),
        ("/.pypirc", 0.7),
        ("/.config/", 0.4),
    ]
]

# 已知危险工具调用模式
_DANGEROUS_TOOL_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"curl\b.*\|\s*(bash|sh|python|perl)", re.IGNORECASE), 0.95, "下载并执行远程脚本"),
    (re.compile(r"wget\b.*\|\s*(bash|sh|python|perl)", re.IGNORECASE), 0.95, "下载并执行远程脚本"),
    (re.compile(r"(eval|exec)\s+\$", re.IGNORECASE), 0.7, "动态执行变量内容"),
]


def score_toolcall_risk(
    tool_call: ToolCallInfo,
    tool_intent: CommandIntent,
    user_intent: str = "UNKNOWN",
) -> tuple[float, str, dict[str, float]]:
    """评估 ToolCall 的综合风险（从 LCIR RiskScorer 五维框架适配）。

    返回：(综合评分 0~1, 风险等级, 各维度评分)
    """
    dimensions: dict[str, float] = {}

    # 维度1: 参数风险 — 检查参数中的危险标志
    dimensions["param_risk"] = _score_param_risk(tool_call)

    # 维度2: 路径风险 — 检查参数中的敏感路径
    dimensions["path_risk"] = _score_path_risk(tool_call)

    # 维度3: 意图风险 — 意图类型基础风险
    dimensions["intent_risk"] = _score_intent_risk(tool_intent)

    # 维度4: 上下文风险 — 外部 URL/IP、数据外泄指标
    dimensions["context_risk"] = _score_context_risk(tool_call, user_intent)

    # 维度5: 模式风险 — 已知危险工具调用模式
    dimensions["pattern_risk"] = _score_pattern_risk(tool_call)

    # 加权求和
    weights = {
        "param_risk": 0.20,
        "path_risk": 0.20,
        "intent_risk": 0.15,
        "context_risk": 0.20,
        "pattern_risk": 0.25,  # 数据外泄模式权重提高
    }
    overall = sum(
        dimensions[dim] * weights.get(dim, 0.2) for dim in dimensions
    )

    # 极高风险模式直接提升到 CRITICAL
    if dimensions.get("pattern_risk", 0) >= 0.9 and dimensions.get("path_risk", 0) >= 0.5:
        overall = max(overall, 0.85)
    elif dimensions.get("pattern_risk", 0) >= 0.9:
        overall = max(overall, 0.7)

    overall = min(max(overall, 0.0), 1.0)

    # 确定风险等级
    if overall >= 0.8:
        risk_level = "CRITICAL"
    elif overall >= 0.6:
        risk_level = "HIGH"
    elif overall >= 0.3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return overall, risk_level, dimensions


def _score_param_risk(tool_call: ToolCallInfo) -> float:
    """参数风险：检查 ToolCall 参数中的危险标志。"""
    args_str = json.dumps(tool_call.arguments, ensure_ascii=False).lower()
    score = 0.0

    # 危险标志
    dangerous_flags = ["--force", "-f ", "--no-confirm", "777", "666", "--yes", "-y "]
    for flag in dangerous_flags:
        if flag in args_str:
            score += 0.4

    # 通配符
    glob_count = args_str.count("*") + args_str.count("?")
    score += min(glob_count / 10.0, 0.3)

    return min(score, 1.0)


def _score_path_risk(tool_call: ToolCallInfo) -> float:
    """路径风险：检查参数中的敏感路径。"""
    all_text = json.dumps(tool_call.arguments, ensure_ascii=False)
    max_score = 0.0

    for pattern, score in _SENSITIVE_PATH_PATTERNS:
        if pattern.search(all_text):
            max_score = max(max_score, score)

    return max_score


def _score_intent_risk(tool_intent: CommandIntent) -> float:
    """意图风险：意图类型基础风险。"""
    return _INTENT_BASE_RISK.get(tool_intent.value, 0.3)


def _score_context_risk(tool_call: ToolCallInfo, user_intent: str) -> float:
    """上下文风险：外部 URL/IP、数据外泄指标。"""
    args_str = json.dumps(tool_call.arguments, ensure_ascii=False)
    score = 0.0

    # 外部 URL 出现（数据可能外泄）
    if re.search(r"https?://", args_str):
        score += 0.3
        # 非常见域名进一步增加风险
        if not re.search(r"https?://(github\.com|pypi\.org|npmjs\.com|docs\.)", args_str):
            score += 0.2

    # IP 地址出现
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", args_str):
        score += 0.2

    # 环境变量引用
    if re.search(r"\$[{(]?[A-Z_]+", args_str):
        score += 0.2

    # 数据传输类参数（content, data, body, payload + 外部URL）
    has_data_keys = any(
        k in tool_call.arguments for k in ("data", "content", "body", "payload", "message")
    )
    has_external_url = bool(re.search(r"https?://", args_str))
    if has_data_keys and has_external_url:
        score += 0.3  # 数据外泄高风险

    # 文件读取 + 网络发送的组合风险
    file_paths = tool_call.arguments.get("file_path", tool_call.arguments.get("path", ""))
    if isinstance(file_paths, str) and has_external_url:
        score += 0.2

    return min(score, 1.0)


def _score_pattern_risk(tool_call: ToolCallInfo) -> float:
    """模式风险：已知危险工具调用模式。"""
    # 检查 bash/shell 命令参数中的危险模式
    command_arg = tool_call.arguments.get("command", "")
    if isinstance(command_arg, str):
        for pattern, score, _ in _DANGEROUS_TOOL_PATTERNS:
            if pattern.search(command_arg):
                return score

    # 检查工具名+参数组合的高危模式
    name_lower = tool_call.tool_name.lower()
    args_str = json.dumps(tool_call.arguments, ensure_ascii=False).lower()

    # 网络发送工具 + 敏感路径
    if name_lower in ("http_post", "send_data", "send", "upload", "post", "webhook"):
        for pat, _ in _SENSITIVE_PATH_PATTERNS:
            if pat.search(args_str):
                return 0.9  # 发送敏感文件，极高风险

    # 读取 + 发送的链式风险（exec/bash 类工具）
    if name_lower in ("bash", "exec", "execute", "shell", "run_command"):
        if re.search(r"curl|wget|send|post|upload", args_str):
            # 排除纯下载场景：curl -sO / wget -O 只有下载没有发送
            command_arg = tool_call.arguments.get("command", "")
            if isinstance(command_arg, str):
                has_upload = bool(re.search(r"curl\s+.*(-d\s|--data\b|-F\s|--form\b|-T\s|--upload-file\b|POST\b)", command_arg, re.I))
                has_pipe_send = bool(re.search(r"\|\s*(curl|wget|nc|ncat)", command_arg, re.I))
                has_redirect_send = bool(re.search(r">\s*/dev/(tcp|udp)", command_arg, re.I))
                has_sensitive_data = bool(re.search(r"\.bashrc|\.ssh|\.env|\.aws|credential|secret|key|token|password", args_str, re.I))

                if (has_upload or has_pipe_send or has_redirect_send) and has_sensitive_data:
                    return 0.95  # 读取敏感文件并发送到外部
                elif has_upload or has_pipe_send or has_redirect_send:
                    return 0.5  # 有网络发送但无敏感数据
                # 纯下载（curl -sO）不算数据外泄风险
                elif re.search(r"\.bashrc|\.ssh|\.env|\.aws|credential|secret|key", args_str):
                    return 0.3  # 涉及敏感路径但仅下载，低风险

    return 0.0


# ---------------------------------------------------------------------------
# 6. 编排函数
# ---------------------------------------------------------------------------

def analyze_response(
    response_body: dict | list | str,
    user_text: str,
) -> list[IntentViolation]:
    """完整的响应意图分析流水线。

    Args:
        response_body: AI 响应体（dict/list/str）
        user_text: 用户最后一条消息文本

    Returns:
        违规列表（仅包含需要 CONFIRM/BLOCK 的 ToolCall，ALLOW 的不返回）
    """
    # 解析响应体
    body = response_body
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (ValueError, TypeError):
            return []

    # 解析 ToolCall
    tool_calls = parse_response_tool_calls(body)
    if not tool_calls:
        return []

    # 推断用户意图
    user_intent = infer_user_intent(user_text)

    violations: list[IntentViolation] = []
    # 追踪规则判定 ALLOW 的 ToolCall，稍后决定是否需要 LLM 审查
    allow_candidates: list[tuple[ToolCallInfo, CommandIntent, bool, float, float, str, str, dict[str, float]]] = []

    for tc in tool_calls:
        # 分类工具意图
        tool_intent = classify_tool(tc)

        # 上下文关联
        is_compatible, drift, decision, reason = correlate(user_intent, tool_intent)

        # 风险评分
        risk_score, risk_level, dimensions = score_toolcall_risk(tc, tool_intent, user_intent)

        # 即使意图兼容，高风险数据外泄行为也应拦截
        # 升级决策：基于风险维度强化
        if decision == "ALLOW":
            pattern_risk = dimensions.get("pattern_risk", 0.0)
            context_risk = dimensions.get("context_risk", 0.0)
            path_risk = dimensions.get("path_risk", 0.0)

            # 数据外泄组合：外部 URL + 敏感路径窃取 → BLOCK
            if pattern_risk >= 0.95 and path_risk >= 0.5:
                decision = "BLOCK"
                reason = f"数据外泄高风险：pattern_risk={pattern_risk:.2f}, path_risk={path_risk:.2f}"
            elif pattern_risk >= 0.8 or context_risk >= 0.9:
                decision = "CONFIRM"
                reason = f"高风险操作：pattern_risk={pattern_risk:.2f}, context_risk={context_risk:.2f}"

        # 只记录需要确认或拦截的违规
        if decision in ("CONFIRM", "BLOCK"):
            # 提取 exec/bash 类工具的实际命令
            tool_cmd = ""
            cmd_arg = tc.arguments.get("command", "")
            if isinstance(cmd_arg, str) and cmd_arg.strip():
                tool_cmd = cmd_arg[:500]

            violations.append(IntentViolation(
                tool_name=tc.tool_name,
                tool_intent=tool_intent,
                user_intent=user_intent,
                is_compatible=is_compatible,
                risk_score=risk_score,
                risk_level=risk_level,
                drift_indicator=drift,
                decision=decision,
                reason=reason,
                tool_arguments=tc.arguments,
                tool_cmd=tool_cmd,
                user_prompt=user_text[:500],
            ))
        elif decision == "ALLOW":
            # 记录 ALLOW 结果，稍后可能需要 LLM 审查
            allow_candidates.append((tc, tool_intent, is_compatible, drift, risk_score, risk_level, reason, dimensions))

    # --- LLM 二次判别（已有：减少误报） ---
    if violations:
        violations = _llm_review_violations(violations, user_text)

    # --- LLM 漏报审查（新增：减少漏报） ---
    if allow_candidates:
        new_violations = _llm_review_allowed(allow_candidates, user_text, user_intent)
        if new_violations:
            violations.extend(new_violations)

    if violations:
        logger.info(
            "intent_violations_detected",
            user_intent=user_intent,
            violation_count=len(violations),
            max_risk=max(v.risk_score for v in violations) if violations else 0,
        )

    return violations


# ---------------------------------------------------------------------------
# 7. LLM 漏报审查 — 对规则判定 ALLOW 的可疑 ToolCall 进行 LLM 审查
# ---------------------------------------------------------------------------

# 高危工具类型：即使规则判定 ALLOW，也需要 LLM 审查
_HIGH_RISK_TOOLS = frozenset({
    "exec", "bash", "shell", "execute", "run_command", "run",
    "command", "terminal", "subprocess", "cmd", "powershell",
})

# 灰区风险分数范围：接近阈值但未触发规则
_GRAY_ZONE_MIN = 0.15
_GRAY_ZONE_MAX = 0.30


def _should_llm_review_allow(
    tc: ToolCallInfo,
    tool_intent: CommandIntent,
    risk_score: float,
    user_intent: str,
) -> bool:
    """判断规则判定 ALLOW 的 ToolCall 是否需要 LLM 审查（减少漏报）。

    触发条件（任一满足）：
    1. 高危工具类型（exec/bash/shell 等）
    2. 灰区风险分数（接近阈值但未触发）
    3. 用户意图 UNKNOWN（兼容矩阵过于宽松）
    4. 工具意图 UNKNOWN（未能分类，可能是新型攻击）
    """
    # 1. 高危工具类型 → 必须审查
    if tc.tool_name.lower() in _HIGH_RISK_TOOLS:
        return True
    # 2. 灰区风险分数
    if _GRAY_ZONE_MIN <= risk_score < _GRAY_ZONE_MAX:
        return True
    # 3. 用户意图 UNKNOWN
    if user_intent == "UNKNOWN":
        return True
    # 4. 工具意图 UNKNOWN
    if tool_intent == CommandIntent.UNKNOWN:
        return True
    return False


def _llm_review_allowed(
    candidates: list[tuple[ToolCallInfo, CommandIntent, bool, float, float, str, str, dict[str, float]]],
    user_text: str,
    user_intent: str,
) -> list[IntentViolation]:
    """对规则判定 ALLOW 但可疑的 ToolCall 调用 LLM 审查，捕获漏报。"""
    # 读取配置
    try:
        from claw_vault.config import load_settings
        live_settings = load_settings()
        llm_cfg = live_settings.intent.llm
    except Exception:
        return []

    if not llm_cfg.enabled or not llm_cfg.review_allow or not llm_cfg.api_url or not llm_cfg.api_key:
        return []

    from claw_vault.detector.intent_llm import judge_toolcall_sync

    new_violations: list[IntentViolation] = []

    for (tc, tool_intent, is_compatible, drift, risk_score, risk_level, reason, dimensions) in candidates:
        if not _should_llm_review_allow(tc, tool_intent, risk_score, user_intent):
            continue

        # 提取 exec/bash 类工具的实际命令
        tool_cmd = ""
        cmd_arg = tc.arguments.get("command", "")
        if isinstance(cmd_arg, str) and cmd_arg.strip():
            tool_cmd = cmd_arg[:500]

        logger.warning(
            "llm_review_allow_start",
            tool_name=tc.tool_name,
            user_intent=user_intent,
            tool_intent=tool_intent.value,
            risk_score=risk_score,
        )

        verdict = judge_toolcall_sync(
            user_text=user_text,
            tool_name=tc.tool_name,
            tool_args=tc.arguments,
            tool_cmd=tool_cmd,
            rule_decision="ALLOW",
            rule_reason=reason,
            risk_score=risk_score,
            api_url=llm_cfg.api_url,
            api_key=llm_cfg.api_key,
            model=llm_cfg.model,
            timeout=llm_cfg.timeout,
        )

        if verdict is None:
            # LLM 调用失败，维持 ALLOW
            continue

        if verdict.decision in ("CONFIRM", "BLOCK") and verdict.confidence >= 0.6:
            # LLM 发现漏报，升级为违规
            violation = IntentViolation(
                tool_name=tc.tool_name,
                tool_intent=tool_intent,
                user_intent=user_intent,
                is_compatible=is_compatible,
                risk_score=risk_score,
                risk_level=risk_level,
                drift_indicator=drift,
                decision=verdict.decision,
                reason=f"{reason} | [LLM漏报捕获] {verdict.reason}",
                tool_arguments=tc.arguments,
                tool_cmd=tool_cmd,
                user_prompt=user_text[:500],
                llm_verdict=verdict.decision,
                llm_reason=verdict.reason,
                llm_confidence=verdict.confidence,
                llm_raw_response=verdict.raw_response[:1000],
            )
            new_violations.append(violation)
            logger.warning(
                "llm_catch_missed_threat",
                tool_name=tc.tool_name,
                llm_decision=verdict.decision,
                confidence=verdict.confidence,
                reason=verdict.reason[:100],
            )

    return new_violations


def _llm_review_violations(
    violations: list[IntentViolation],
    user_text: str,
) -> list[IntentViolation]:
    """对规则评分产生的违规进行 LLM 二次判别。

    仅在 LLM 配置启用且有可用 API 时触发。
    LLM 判定 ALLOW 且置信度 >= 0.7 时，降级为放行（纠正规则误报）。
    """
    # 实时读取配置文件（API 保存后会刷新生效）
    try:
        from claw_vault.config import load_settings
        live_settings = load_settings()
        llm_cfg = live_settings.intent.llm
    except Exception:
        return violations

    if not llm_cfg.enabled or not llm_cfg.api_url or not llm_cfg.api_key:
        return violations

    from claw_vault.detector.intent_llm import judge_toolcall_sync, should_trigger_llm

    remaining: list[IntentViolation] = []
    for v in violations:
        # 检查风险等级是否达到 LLM 触发阈值
        if not should_trigger_llm(v.risk_level, llm_cfg.min_risk_for_llm):
            remaining.append(v)
            continue

        verdict = judge_toolcall_sync(
            user_text=user_text,
            tool_name=v.tool_name,
            tool_args=v.tool_arguments,
            tool_cmd=v.tool_cmd,
            rule_decision=v.decision,
            rule_reason=v.reason,
            risk_score=v.risk_score,
            api_url=llm_cfg.api_url,
            api_key=llm_cfg.api_key,
            model=llm_cfg.model,
            timeout=llm_cfg.timeout,
        )

        if verdict is None:
            # LLM 调用失败，维持规则评分结果
            remaining.append(v)
            continue

        # 记录 LLM 判定结果
        v.llm_verdict = verdict.decision
        v.llm_reason = verdict.reason
        v.llm_confidence = verdict.confidence
        v.llm_raw_response = verdict.raw_response[:1000]  # 保留原始输出（截断）

        if verdict.decision == "ALLOW" and verdict.confidence >= 0.7:
            # LLM 纠正：规则误报，降级为放行
            logger.warning(
                "llm_judge_overridden",
                tool_name=v.tool_name,
                rule_decision=v.decision,
                llm_decision="ALLOW",
                confidence=verdict.confidence,
            )
            # 不加入 remaining → 该违规被移除
        else:
            # LLM 维持或加重，补充理由
            v.reason = f"{v.reason} | [LLM确认] {verdict.reason}"
            remaining.append(v)

    return remaining
