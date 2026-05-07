"""意图防护 LLM 二次判别模块。

在规则评分检测到高危 ToolCall 后，调用 LLM 进行语义级判断，
纠正规则评分的误报，提升意图识别准确度。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import httpx
import structlog

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class LLMVerdict:
    """LLM 判别结果。"""
    decision: str       # ALLOW / CONFIRM / BLOCK
    reason: str         # 判断理由
    confidence: float   # 置信度 0-1
    raw_response: str = ""  # LLM 原始输出


# ---------------------------------------------------------------------------
# Prompt 组装
# ---------------------------------------------------------------------------

_JUDGE_SYSTEM_PROMPT = (
    "你是 AI Agent 安全助手，负责判断 Agent 的 ToolCall 是否超出了用户授权范围。\n"
    "\n"
    "【判断标准】\n"
    "- 如果 ToolCall 完全符合用户指令意图 → ALLOW\n"
    "- 如果 ToolCall 部分超出或不确定 → CONFIRM\n"
    "- 如果 ToolCall 明显违背用户指令或存在安全风险 → BLOCK\n"
    "\n"
    "【重要】直接输出 JSON 对象，不要任何其他文字：\n"
    '{"decision": "ALLOW", "reason": "理由", "confidence": 0.85}\n"'
)

_RISK_LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def build_judge_prompt(
    user_text: str,
    tool_name: str,
    tool_args: dict,
    tool_cmd: str,
    rule_decision: str,
    rule_reason: str,
    risk_score: float,
) -> str:
    """组装判别 prompt，包含规则评分的中间结果供 LLM 参考。"""
    prompt = (
        f"【用户原始指令】\n{user_text}\n\n"
        f"【Agent 执行的工具调用】\n"
        f"tool_name: {tool_name}\n"
        f"arguments: {json.dumps(tool_args, ensure_ascii=False, indent=2)}"
    )
    if tool_cmd:
        prompt += f"\n实际命令: {tool_cmd}"
    prompt += (
        f"\n\n【规则评分参考】\n"
        f"规则决策: {rule_decision}\n"
        f"规则原因: {rule_reason}\n"
        f"风险评分: {risk_score:.2f}\n\n"
        "请判断此 ToolCall 是否超出用户授权范围。"
    )
    return prompt


# ---------------------------------------------------------------------------
# LLM 调用
# ---------------------------------------------------------------------------
def _build_verdict(data: dict) -> LLMVerdict:
    """从解析出的 JSON dict 构建 LLMVerdict。"""
    decision = data.get("decision", "CONFIRM").upper()
    if decision not in ("ALLOW", "CONFIRM", "BLOCK"):
        decision = "CONFIRM"
    confidence = float(data.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))
    return LLMVerdict(
        decision=decision,
        reason=str(data.get("reason", ""))[:500],
        confidence=confidence,
    )


def _parse_verdict(raw: str) -> LLMVerdict | None:
    """从 LLM 原始输出中解析 JSON 判决结果。

    兼容带有<think>...</think>思考标签的模型（如 MiniMax）。
    策略：优先从<think>...</think>块内提取 JSON，其次从正文提取。
    """
    text = raw.strip()

    # 去掉 markdown 代码块包裹
    if text.startswith("```"):
        text = re.sub(r"^```\w*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
        text = text.strip()

    # 优先从<think>...</think>块内提取 JSON（处理带思考标签的模型）
    think_blocks = re.findall(r"<think>(.*?)</think>", text, flags=re.DOTALL)
    for block in think_blocks:
        block = block.strip()
        # 先尝试直接解析
        try:
            data = json.loads(block)
            return _build_verdict(data)
        except (json.JSONDecodeError, ValueError):
            pass
        # 尝试提取 JSON 对象（处理嵌套花括号）
        idx = block.find("{")
        if idx >= 0:
            for fend in range(len(block), idx - 1, -1):
                try:
                    data = json.loads(block[idx:fend])
                    return _build_verdict(data)
                except (json.JSONDecodeError, ValueError):
                    pass

    # 从正文（去掉思考标签后）提取 JSON
    plain = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    def _try_parse(s: str) -> dict | None:
        s = s.strip()
        # 直接解析
        try:
            return json.loads(s)
        except (json.JSONDecodeError, ValueError):
            pass
        # 提取 JSON 对象
        m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", s, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    data = _try_parse(plain)
    if data is None:
        data = _try_parse(text)  # 兜底用原文
    if data is None:
        # 兜底：从文本中提取关键词决策
        verdict = _parse_verdict_fallback(text)
        if verdict is not None:
            return verdict
        logger.warning("llm_judge_parse_failed", raw=text[:200])
        return None

    return _build_verdict(data)



def judge_toolcall_sync(
    user_text: str,
    tool_name: str,
    tool_args: dict,
    tool_cmd: str,
    rule_decision: str,
    rule_reason: str,
    risk_score: float,
    api_url: str,
    api_key: str,
    model: str = "gpt-4o-mini",
    timeout: float = 10.0,
) -> LLMVerdict | None:
    """同步调用 LLM 判断 ToolCall 是否越界。

    Args:
        user_text: 用户原始输入
        tool_name: 工具名
        tool_args: 工具参数
        tool_cmd: exec/bash 类工具的实际命令
        rule_decision: 规则评分的决策（CONFIRM/BLOCK）
        rule_reason: 规则评分的原因
        risk_score: 规则评分的风险分值
        api_url: LLM API 地址（OpenAI 兼容格式）
        api_key: API Key
        model: 模型名
        timeout: 超时秒数

    Returns:
        LLMVerdict 或 None（调用失败时降级到规则评分结果）
    """
    prompt = build_judge_prompt(
        user_text=user_text,
        tool_name=tool_name,
        tool_args=tool_args,
        tool_cmd=tool_cmd,
        rule_decision=rule_decision,
        rule_reason=rule_reason,
        risk_score=risk_score,
    )

    # 构造 OpenAI 兼容请求体
    request_body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _JUDGE_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 300,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    logger.warning(
        "llm_judge_start",
        tool_name=tool_name,
        model=model,
        rule_decision=rule_decision,
    )

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(api_url, json=request_body, headers=headers)

        if resp.status_code != 200:
            logger.warning(
                "llm_judge_api_error",
                status=resp.status_code,
                body=resp.text[:200],
            )
            return None

        resp_data = resp.json()

        # 提取响应文本（兼容 OpenAI + Anthropic 格式）
        content = ""
        # OpenAI 格式: choices[].message.content
        choices = resp_data.get("choices", [])
        if isinstance(choices, list) and choices:
            msg = choices[0].get("message", {})
            content = msg.get("content", "")
        # Anthropic 格式: content[].text
        elif isinstance(resp_data.get("content"), list):
            for block in resp_data["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    content += block.get("text", "")

        if not content:
            logger.warning("llm_judge_empty_response")
            return None

        verdict = _parse_verdict(content)
        if verdict:
            verdict.raw_response = content  # 保留原始输出
            logger.warning(
                "llm_judge_result",
                decision=verdict.decision,
                confidence=verdict.confidence,
                reason=verdict.reason[:100],
                raw_response=content[:200],
            )
        return verdict

    except httpx.TimeoutException:
        logger.warning("llm_judge_timeout", timeout=timeout)
        return None
    except Exception as exc:
        logger.warning("llm_judge_failed", error=str(exc))
        return None


def _parse_verdict_fallback(text: str) -> LLMVerdict | None:
    """从非 JSON 文本中兜底提取决策。

    用于模型未按要求返回 JSON 时的补救。
    通过关键词匹配判断 ALLOW/CONFIRM/BLOCK。
    """
    text_lower = text.lower()

    # BLOCK 关键词（高风险词）
    block_kw = ["超出授权", "超出范围", "违背指令", "明显违规", "恶意", "危险操作",
                "数据泄露", "窃取", "钓鱼", "未经授权", "security risk", "unauthorized",
                "beyond scope", "violates", "malicious"]
    # ALLOW 关键词（安全词）
    allow_kw = ["符合意图", "完全符合", "在授权范围内", "合理", "安全",
                "authorized", "within scope", "legitimate", "appropriate"]
    # CONFIRM 关键词（中等风险）
    confirm_kw = ["不确定", "需要确认", "建议确认", "部分超出", " ambiguous",
                  "uncertain", "confirm", "verify"]

    block_score = sum(1 for kw in block_kw if kw in text_lower)
    allow_score = sum(1 for kw in allow_kw if kw in text_lower)
    confirm_score = sum(1 for kw in confirm_kw if kw in text_lower)

    if block_score > allow_score and block_score > confirm_score:
        reason = "文本兜底提取: 检测到风险关键词"
        confidence = min(0.95, 0.5 + block_score * 0.1)
        return LLMVerdict(decision="BLOCK", reason=reason, confidence=confidence)
    elif allow_score > block_score:
        reason = "文本兜底提取: 检测到安全关键词"
        confidence = min(0.9, 0.5 + allow_score * 0.1)
        return LLMVerdict(decision="ALLOW", reason=reason, confidence=confidence)
    elif confirm_score > 0:
        reason = "文本兜底提取: 检测到不确定关键词"
        confidence = 0.5 + confirm_score * 0.05
        return LLMVerdict(decision="CONFIRM", reason=reason, confidence=confidence)

    return None



def should_trigger_llm(
    risk_level: str,
    min_risk: str = "MEDIUM",
) -> bool:
    """判断风险等级是否达到触发 LLM 判别的阈值。"""
    return _RISK_LEVEL_ORDER.get(risk_level, 0) >= _RISK_LEVEL_ORDER.get(min_risk, 1)
