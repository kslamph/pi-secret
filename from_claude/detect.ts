/**
 * detect.ts — 敏感信息检测与脱敏（纯函数，不依赖 pi，可单独测试）
 *
 * 三层检测，优先级从高到低：
 *   1. 已知格式（AWS/GitHub/OpenAI/Anthropic/JWT/私钥/URL 凭据 …）—— 精度最高
 *   2. 关键字上下文（password=…、密码是…、--token xxx …）—— 覆盖自定义/弱口令
 *   3. 高熵字符串兜底（可关闭）—— 抓"没有任何上下文的随机串"
 *
 * 脱敏方式：把值替换成稳定的占位符 [REDACTED:TYPE#n]，同一个值永远映射到同一个占位符，
 * 这样 LLM 仍然能理解"这里有个密码"，也能在回复里引用它。
 */

export interface Finding {
	start: number;
	end: number;
	type: string;
	value: string;
	/** 1=已知格式 2=关键字上下文 3=高熵；数字越小越优先 */
	priority: number;
}

export interface RedactOptions {
	/** 是否启用高熵兜底检测。对工具输出/代码文件建议关闭（误报多） */
	entropy?: boolean;
}

export interface RedactResult {
	text: string;
	hits: { type: string; placeholder: string }[];
	changed: boolean;
}

export const PLACEHOLDER_RE = /\[REDACTED:([A-Z_]+)#(\d+)\]/g;
const PLACEHOLDER_SPLIT = /(\[REDACTED:[A-Z_]+#\d+\])/;

type Groups = Record<string, string | undefined>;

interface Rule {
	type: string | ((g: Groups) => string);
	re: RegExp;
	priority: number;
	validate?: (value: string, g: Groups) => boolean;
	/** 去掉值末尾的标点（句号、引号等） */
	trimEnd?: RegExp;
}

// ---------------------------------------------------------------------------
// 误报过滤
// ---------------------------------------------------------------------------

const PLACEHOLDERISH =
	/^(?:x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,}|<[^>]*>|\[[^\]]*\]|\{\{.*\}\}|\$\{.*\}?|%[A-Za-z_]+%|your[_ -]?\w*|change[_-]?me|replace[_-]?me|example|placeholder|redacted|dummy|sample|todo|null|none|nil|undefined|true|false|string|str|int|integer|number|bool|boolean|any|object|required|optional|env|secret|password|token|api[_-]?key)$/i;

/** 值看起来是对变量/函数/路径/URL 的引用，而不是字面量密码 */
function looksLikeReference(v: string): boolean {
	if (/^(?:\$|%|@|process\.env|os\.environ|os\.getenv|System\.getenv|ENV\[|env\.|config\.|settings\.|self\.|this\.|args\.|opts\.|options\.|req\.|request\.|params\.|input\(|getpass|prompt\()/i.test(v)) return true;
	if (/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\(?\)?$/.test(v)) return true; // foo.bar.baz
	if (/^[A-Za-z_]\w*\(\)?$/.test(v)) return true; // getPassword()
	if (/^[A-Z]\w*\[.*\]$/.test(v)) return true; // Optional[str]
	if (/^(?:\.{0,2}\/|~\/|[A-Za-z]:\\)/.test(v)) return true; // 路径
	if (/^https?:\/\//i.test(v)) return true;
	return false;
}

const STRONG_KW = /pass|pwd|secret|private|密码|口令|密钥|秘钥|私钥/i;

/** 关键字上下文里的值是否像真的密钥 */
function plausibleValue(raw: string, kw: string): boolean {
	// 代码里值后面常跟着收尾符号：(password: string) { / def f(password: str):
	const v = raw.replace(/[)\]}>;:,]+$/, "");
	if (v.length === 0 || PLACEHOLDERISH.test(raw) || PLACEHOLDERISH.test(v) || looksLikeReference(raw) || looksLikeReference(v)) return false;
	if (!STRONG_KW.test(kw)) {
		// token / api key 之类：太短或纯短数字多半不是密钥（max_token: 4096）
		if (v.length < 8) return false;
		if (/^\d+$/.test(v) && v.length < 12) return false;
	}
	return true;
}

/** 英文口语 "my password is xxx" 里的值：必须看起来像密码，避免 "password is incorrect" */
function proseLooksLikeSecret(v: string, kw: string): boolean {
	if (!plausibleValue(v, kw)) return false;
	const hasDigit = /\d/.test(v);
	const hasSymbol = /[^A-Za-z0-9]/.test(v);
	const mixedCase = /[a-z]/.test(v) && /[A-Z]/.test(v);
	return hasDigit || hasSymbol || mixedCase;
}

function typeFromKeyword(kw: string): string {
	const k = kw.toLowerCase();
	if (/pass|pwd|密码|口令|^pin$/.test(k)) return "PASSWORD";
	if (/api[\s_-]?key|apikey/.test(k)) return "API_KEY";
	if (/token|令牌|bearer/.test(k)) return "TOKEN";
	if (/private|私钥/.test(k)) return "PRIVATE_KEY";
	if (/secret|密钥|秘钥/.test(k)) return "SECRET";
	if (/key/.test(k)) return "API_KEY";
	return "SECRET";
}

// ---------------------------------------------------------------------------
// 第 1 层：已知格式
// ---------------------------------------------------------------------------

const KNOWN: Rule[] = [
	{ type: "PRIVATE_KEY", priority: 1, re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/gd },
	// 被截断、没有 END 行的私钥：只吃紧跟着的 base64 正文
	{ type: "PRIVATE_KEY", priority: 1, re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\r\n ]{64,4096}/gd },
	{ type: "AWS_ACCESS_KEY_ID", priority: 1, re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/gd },
	{ type: "GITHUB_TOKEN", priority: 1, re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/gd },
	{ type: "GITLAB_TOKEN", priority: 1, re: /\bglpat-[A-Za-z0-9_-]{20,}/gd },
	{ type: "ANTHROPIC_API_KEY", priority: 1, re: /\bsk-ant-[A-Za-z0-9_-]{20,}/gd },
	{ type: "OPENAI_API_KEY", priority: 1, re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/gd },
	{ type: "GOOGLE_API_KEY", priority: 1, re: /\bAIza[0-9A-Za-z_-]{35}\b/gd },
	{ type: "SLACK_TOKEN", priority: 1, re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/gd },
	{ type: "STRIPE_KEY", priority: 1, re: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/gd },
	{ type: "JWT", priority: 1, re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/gd },
	{ type: "NPM_TOKEN", priority: 1, re: /\bnpm_[A-Za-z0-9]{36}\b/gd },
	{ type: "HF_TOKEN", priority: 1, re: /\bhf_[A-Za-z0-9]{30,}\b/gd },
	{ type: "SENDGRID_KEY", priority: 1, re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/gd },
	{ type: "BEARER_TOKEN", priority: 1, re: /\bBearer\s+(?<v>[A-Za-z0-9._~+/=-]{16,})/gdi, validate: (v) => !PLACEHOLDERISH.test(v) },
	{
		// Authorization: Basic base64(user:pass) —— 解码后必须是 "可打印字符:可打印字符"，避免 "Basic internationalization"
		type: "BASIC_AUTH",
		priority: 1,
		re: /\bBasic\s+(?<v>[A-Za-z0-9+/]{16,}={0,2})/gd,
		validate: (v) => /^[\x20-\x7E]+:[\x20-\x7E]+$/.test(Buffer.from(v, "base64").toString("latin1")),
	},
	{
		// scheme://user:password@host
		type: "URL_PASSWORD",
		priority: 1,
		re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/?#]+:(?<v>[^\s@/?#]{3,})@/gdi,
		validate: (v) => !PLACEHOLDERISH.test(v) && !looksLikeReference(v),
	},
	{
		// curl -u user:pass
		type: "BASIC_AUTH",
		priority: 1,
		re: /(?<![\w-])(?:-u|--user)[ \t]+['"]?[^\s:'"]+:(?<v>[^\s'"]{3,})/gd,
		validate: (v) => !PLACEHOLDERISH.test(v) && !looksLikeReference(v),
	},
];

// ---------------------------------------------------------------------------
// 第 2 层：关键字上下文
// ---------------------------------------------------------------------------

// 关键字（可带前缀/后缀：DB_PASSWORD、dbPassword、secret_key、X-API-Key …）
const KW = String.raw`(?<kw>(?:password|passwd|pwd|passphrase|passcode|secret[_-]?access[_-]?key|client[_-]?secret|api[_-]?secret|secret[_-]?key|private[_-]?key|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|secret|token|credentials?)(?:[_.-](?:key|token|secret|value|string|str|code))?)`;
// "=" 赋值（允许 Python/TS 类型标注：password: str = "x"）
const SEP_ASSIGN = String.raw`["'\x60]?(?:[ \t]*:[ \t]*[A-Za-z_][\w.\[\]| ]{0,40}?)?[ \t]*(?::=|=>|=)[ \t]*`;
// ":" 形式（JSON / YAML / HTTP 头）
const SEP_COLON = String.raw`["'\x60]?[ \t]*:[ \t]*`;
const VALUE = String.raw`(?:"(?<vdq>[^"\r\n]{3,})"|'(?<vsq>[^'\r\n]{3,})'|\x60(?<vbt>[^\x60\r\n]{3,})\x60|(?<vraw>[^\s"'\x60,;&]{3,}))`;

const TRAIL_PUNCT = /[.,;:)\]}>"'`]+$/;

const CONTEXT: Rule[] = [
	{
		type: (g) => typeFromKeyword(g.kw ?? ""),
		priority: 2,
		re: new RegExp(`${KW}(?:${SEP_ASSIGN}|${SEP_COLON})${VALUE}`, "gdi"),
		validate: (v, g) => plausibleValue(v, g.kw ?? ""),
	},
	{
		// --password xxx / --token=xxx / -password xxx
		type: (g) => typeFromKeyword(g.kw ?? ""),
		priority: 2,
		re: /(?<![\w-])--?(?<kw>password|passwd|pwd|pass|token|api-?key|secret|auth-?token|access-?token)(?:=|[ \t]+)(?:"(?<vdq>[^"\r\n]{3,})"|'(?<vsq>[^'\r\n]{3,})'|(?<vraw>[^\s"'-][^\s"']{2,}))/gdi,
		validate: (v, g) => plausibleValue(v, g.kw ?? ""),
	},
	{
		// 中文：密码是 xxx / 密码：xxx / 口令=xxx
		type: (g) => typeFromKeyword(g.kw ?? ""),
		priority: 2,
		re: /(?<kw>密码|口令|密钥|秘钥|令牌|私钥)(?:[ \t]*(?:是|为|叫|设为|设置为|改为|改成|修改为)[ \t]*|[ \t]*[:：=][ \t]*)["'“‘「]?(?<vzh>[\x21-\x7E]{3,})/gd,
		validate: (v, g) => plausibleValue(v, g.kw ?? ""),
		trimEnd: TRAIL_PUNCT,
	},
	{
		// 中英混写：我的 api key 是 xxx / password：xxx
		type: (g) => typeFromKeyword(g.kw ?? ""),
		priority: 2,
		re: /\b(?<kw>password|passwd|passphrase|api[ _-]?key|apikey|token|secret)\b[ \t]*(?:是|为|：)[ \t]*["'“‘「]?(?<vzh>[\x21-\x7E]{3,})/gdi,
		validate: (v, g) => plausibleValue(v, g.kw ?? ""),
		trimEnd: TRAIL_PUNCT,
	},
	{
		// 英文口语：my password is xxx
		type: (g) => typeFromKeyword(g.kw ?? ""),
		priority: 2,
		re: /\b(?<kw>password|passwd|passcode|passphrase|pin|secret|api[ _-]?key|token)\b[ \t]+(?:is|was)(?:[ \t]*:[ \t]*|[ \t]+)["'“‘]?(?<ven>[^\s"'”’,;]{4,})/gdi,
		validate: (v, g) => proseLooksLikeSecret(v, g.kw ?? ""),
		trimEnd: TRAIL_PUNCT,
	},
];

// ---------------------------------------------------------------------------
// 第 3 层：高熵字符串
// ---------------------------------------------------------------------------

function shannon(s: string): number {
	const freq = new Map<string, number>();
	for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
	let h = 0;
	for (const n of freq.values()) {
		const p = n / s.length;
		h -= p * Math.log2(p);
	}
	return h;
}

const ENTROPY_THRESHOLD = 4.0;

function findHighEntropy(text: string): Finding[] {
	const out: Finding[] = [];
	// 24~128 位、完整的一段 token 字符；更长的（base64 图片等）直接忽略
	const re = /(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{24,128}(?![A-Za-z0-9+/_=-])/g;
	for (const m of text.matchAll(re)) {
		const v = m[0];
		if (!/[a-z]/.test(v) || !/[A-Z]/.test(v) || !/\d/.test(v)) continue; // 要求大小写+数字都有（纯 hex 哈希/UUID 因此被排除）
		if ((v.match(/\//g)?.length ?? 0) >= 3) continue; // 像路径
		const segs = v.split(/[_-]/);
		if (segs.length >= 3 && segs.filter((s) => /^[A-Za-z]{2,}\d{0,4}$/.test(s)).length / segs.length >= 0.6) continue; // 像 snake/kebab 标识符
		// 驼峰标识符（getUserAccountInformationById2Handler）：由"单词"组成的比例高 → 不是随机串
		const wordChars = (v.match(/[A-Z]?[a-z]{3,}/g) ?? []).reduce((n, w) => n + w.length, 0);
		if (wordChars / v.length >= 0.6) continue;
		if (shannon(v) < ENTROPY_THRESHOLD) continue;
		out.push({ start: m.index!, end: m.index! + v.length, type: "HIGH_ENTROPY", value: v, priority: 3 });
	}
	return out;
}

// ---------------------------------------------------------------------------
// 扫描 & 合并
// ---------------------------------------------------------------------------

function collect(text: string, rule: Rule, into: Finding[]): void {
	for (const m of text.matchAll(rule.re)) {
		const ind = (m as any).indices as Array<[number, number]> & { groups?: Record<string, [number, number] | undefined> };
		let span: [number, number] = ind[0];
		for (const [name, range] of Object.entries(ind.groups ?? {})) {
			if (name.startsWith("v") && range) {
				span = range;
				break;
			}
		}
		let [start, end] = span;
		if (text.startsWith("[REDACTED:", start)) continue; // 已经是占位符，保持幂等
		if (rule.trimEnd) {
			const t = text.slice(start, end).match(rule.trimEnd);
			if (t) end -= t[0].length;
		}
		const value = text.slice(start, end);
		if (value.length === 0) continue;
		const groups = (m.groups ?? {}) as Groups;
		if (rule.validate && !rule.validate(value, groups)) continue;
		into.push({ start, end, type: typeof rule.type === "function" ? rule.type(groups) : rule.type, value, priority: rule.priority });
	}
}

export function scan(text: string, opts: RedactOptions = {}): Finding[] {
	const all: Finding[] = [];
	for (const rule of KNOWN) collect(text, rule, all);
	for (const rule of CONTEXT) collect(text, rule, all);
	if (opts.entropy) all.push(...findHighEntropy(text));

	// 按起点排序；同起点先长后短，再按优先级。重叠区间合并（取并集，类型沿用先到者）
	all.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start) || a.priority - b.priority);
	const merged: Finding[] = [];
	for (const f of all) {
		const last = merged[merged.length - 1];
		if (last && f.start < last.end) {
			if (f.end > last.end) {
				last.end = f.end;
				last.value = text.slice(last.start, last.end);
			}
			continue;
		}
		merged.push({ ...f });
	}
	return merged;
}

// ---------------------------------------------------------------------------
// Vault：值 <-> 占位符 的双向映射（仅存内存）
// ---------------------------------------------------------------------------

export class Vault {
	byValue = new Map<string, string>();
	byPlaceholder = new Map<string, string>();
	counters = new Map<string, number>();

	get size(): number {
		return this.byValue.size;
	}

	placeholderFor(type: string, value: string): string {
		const existing = this.byValue.get(value);
		if (existing) return existing;
		const n = (this.counters.get(type) ?? 0) + 1;
		this.counters.set(type, n);
		const ph = `[REDACTED:${type}#${n}]`;
		this.byValue.set(value, ph);
		this.byPlaceholder.set(ph, value);
		return ph;
	}

	/** 占位符 -> 原值（用于本地执行工具前还原） */
	restore(text: string): string {
		if (!text.includes("[REDACTED:")) return text;
		return text.replace(PLACEHOLDER_RE, (m) => this.byPlaceholder.get(m) ?? m);
	}

	/** 把文本里出现的、已登记过的明文值再次替换成占位符（检测漏掉的也能兜住） */
	maskKnown(text: string): string {
		if (this.byValue.size === 0) return text;
		const values = [...this.byValue.entries()].filter(([v]) => v.length >= 5).sort((a, b) => b[0].length - a[0].length);
		if (values.length === 0) return text;
		return text
			.split(PLACEHOLDER_SPLIT) // 奇数下标是占位符本身，不处理
			.map((seg, i) => {
				if (i % 2 === 1) return seg;
				for (const [v, ph] of values) if (seg.includes(v)) seg = seg.split(v).join(ph);
				return seg;
			})
			.join("");
	}
}

export function redact(text: string, vault: Vault, opts: RedactOptions = {}): RedactResult {
	const findings = scan(text, opts);
	let out = "";
	let cursor = 0;
	const hits: RedactResult["hits"] = [];
	for (const f of findings) {
		out += text.slice(cursor, f.start);
		const ph = vault.placeholderFor(f.type, f.value);
		out += ph;
		hits.push({ type: f.type, placeholder: ph });
		cursor = f.end;
	}
	out += text.slice(cursor);
	const masked = vault.maskKnown(out);
	return { text: masked, hits, changed: masked !== text };
}

/** "PASSWORD ×2, API_KEY ×1" */
export function summarize(hits: { type: string }[]): string {
	const counts = new Map<string, number>();
	for (const h of hits) counts.set(h.type, (counts.get(h.type) ?? 0) + 1);
	return [...counts.entries()].map(([t, n]) => `${t} ×${n}`).join(", ");
}
