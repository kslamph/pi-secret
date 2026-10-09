/**
 * secret-redactor — pi 扩展：在用户输入送往 LLM 之前，自动检测并脱敏密码 / API Key 等敏感信息。
 *
 * 安装：
 *   mkdir -p ~/.pi/agent/extensions/secret-redactor
 *   cp index.ts detect.ts ~/.pi/agent/extensions/secret-redactor/
 *   # 然后在 pi 里 /reload；或开发时：pi -e ./index.ts
 *
 * 三道防线：
 *   input        用户输入 —— 改写成带占位符的文本（原文不会进入会话历史）
 *   context      每次请求 LLM 前，再扫一遍整个对话（兜住工具输出、恢复的旧会话、扩展注入的消息）
 *   tool_result  工具输出（cat .env 之类）返回给 LLM 之前脱敏
 *
 * 可选：tool_call 时把占位符在本地还原成真值，这样 LLM 写出的命令
 *   psql "postgres://admin:[REDACTED:URL_PASSWORD#1]@db/app"
 * 在你本机依然能真正跑通，而真值从不发给 LLM。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Vault, redact, summarize } from "./detect.ts";

/** 工具执行前把占位符还原成真值（只在本机发生，不会发给 LLM） */
const RESTORE_IN_TOOLS = true;
/** 工具输出返回给 LLM 之前也做脱敏 */
const SCAN_TOOL_RESULTS = true;

export default function (pi: ExtensionAPI) {
	const vault = new Vault();
	let enabled = true;

	const scrub = (s: string): string => redact(s, vault, { entropy: false }).text;

	// ---- 1. 用户输入 --------------------------------------------------------
	pi.on("input", async (event, ctx) => {
		if (!enabled || event.source === "extension") return { action: "continue" };

		// 用户输入：开启高熵兜底（宁可多脱敏）
		const r = redact(event.text, vault, { entropy: true });
		if (!r.changed) return { action: "continue" };

		if (ctx.hasUI && r.hits.length > 0) {
			ctx.ui.notify(`已脱敏 ${r.hits.length} 处敏感信息后再发送给模型：${summarize(r.hits)}`, "warning");
		}
		return { action: "transform", text: r.text, images: event.images };
	});

	// ---- 2. 发给 LLM 之前，整体再扫一遍 ----------------------------------------
	pi.on("context", async (event) => {
		let changed = false;
		const messages = event.messages.map((msg: any) => {
			const next = redactMessage(msg, scrub);
			if (next !== msg) changed = true;
			return next;
		});
		return changed ? { messages } : undefined;
	});

	// ---- 3. 工具输出 --------------------------------------------------------
	pi.on("tool_result", async (event) => {
		if (!enabled || !SCAN_TOOL_RESULTS) return undefined;
		let changed = false;
		const content = event.content.map((part) => {
			if (part.type !== "text") return part;
			const text = scrub(part.text);
			if (text === part.text) return part;
			changed = true;
			return { ...part, text };
		});
		// 注意：result.details 通常只用于界面渲染，不发给模型；若你的工具把敏感内容放进 details 且会被发送，请一并处理
		return changed ? { content } : undefined;
	});

	// ---- 4. 本地执行前还原占位符 ------------------------------------------------
	pi.on("tool_call", async (event) => {
		if (!enabled || !RESTORE_IN_TOOLS || vault.size === 0) return undefined;
		restoreInPlace(event.input, vault);
		return undefined;
	});

	// ---- 命令：/redact [on|off|status] ---------------------------------------
	pi.registerCommand("redact", {
		description: "开关/查看敏感信息脱敏：/redact on | off | status",
		handler: async (arg, ctx) => {
			const a = (arg ?? "").trim().toLowerCase();
			if (a === "on") enabled = true;
			else if (a === "off") enabled = false;
			ctx.ui.notify(`敏感信息脱敏：${enabled ? "开启" : "关闭"}；本会话已登记 ${vault.size} 个敏感值（不显示明文）`, "info");
		},
	});
}

// ---------------------------------------------------------------------------

/** 只处理会发给模型的文本：字符串 content、text 片段、toolCall 参数。不碰 thinking 及其签名。 */
function redactMessage(msg: any, scrub: (s: string) => string): any {
	if (!msg || typeof msg !== "object") return msg;
	const c = msg.content;
	if (typeof c === "string") {
		const t = scrub(c);
		return t === c ? msg : { ...msg, content: t };
	}
	if (!Array.isArray(c)) return msg;

	let changed = false;
	const parts = c.map((p: any) => {
		if (p?.type === "text" && typeof p.text === "string") {
			const t = scrub(p.text);
			if (t !== p.text) {
				changed = true;
				return { ...p, text: t };
			}
		} else if (p?.type === "toolCall" && p.arguments && typeof p.arguments === "object") {
			const a = mapStrings(p.arguments, scrub);
			if (a !== p.arguments) {
				changed = true;
				return { ...p, arguments: a };
			}
		}
		return p;
	});
	return changed ? { ...msg, content: parts } : msg;
}

/** 不可变地遍历对象里的所有字符串；没有变化时返回原引用 */
function mapStrings(node: any, fn: (s: string) => string): any {
	if (typeof node === "string") return fn(node);
	if (Array.isArray(node)) {
		let changed = false;
		const out = node.map((x) => {
			const y = mapStrings(x, fn);
			if (y !== x) changed = true;
			return y;
		});
		return changed ? out : node;
	}
	if (node && typeof node === "object") {
		let changed = false;
		const out: Record<string, any> = {};
		for (const [k, v] of Object.entries(node)) {
			const y = mapStrings(v, fn);
			if (y !== v) changed = true;
			out[k] = y;
		}
		return changed ? out : node;
	}
	return node;
}

/** 原地把占位符还原成真值（tool_call 的 event.input 允许原地修改） */
function restoreInPlace(node: any, vault: Vault): void {
	if (Array.isArray(node)) {
		for (let i = 0; i < node.length; i++) {
			if (typeof node[i] === "string") node[i] = vault.restore(node[i]);
			else restoreInPlace(node[i], vault);
		}
	} else if (node && typeof node === "object") {
		for (const k of Object.keys(node)) {
			if (typeof node[k] === "string") node[k] = vault.restore(node[k]);
			else restoreInPlace(node[k], vault);
		}
	}
}
