// 运行：node test.ts   （Node ≥ 22.18 原生支持 .ts）
import { Vault, redact, scan } from "./detect.ts";
import extension from "./index.ts";

let failed = 0;
const ok = (name: string, cond: boolean, detail = "") => {
	if (!cond) failed++;
	console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  → " + detail}`);
};

const PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq98fakefakefakefakefakefakefakefakefake\nZm9vYmFyYmF6cXV4\n-----END RSA PRIVATE KEY-----";
const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// [输入, 必须被抹掉的明文]
const positives: [string, string][] = [
	["AWS key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"],
	["token ghp_1234567890abcdefghijklmnopqrstuvwxyz", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"],
	["ANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"],
	['{"password": "Sup3r$ecret!"}', "Sup3r$ecret!"],
	["DB_PASSWORD=hunter2", "hunter2"],
	["我的数据库密码是 Xy7#kLm9pQ，请帮我写连接代码", "Xy7#kLm9pQ"],
	["密码：abc12345", "abc12345"],
	["我的 api key 是 sk-test1234567890abcdefgh 帮我调用", "sk-test1234567890abcdefgh"],
	["postgres://admin:s3cretPass@db.example.com:5432/app", "s3cretPass"],
	[`here is my key:\n${PEM}\nthanks`, "MIIEowIBAAKCAQEA7bq98fake"],
	[`Authorization token ${JWT}`, JWT],
	['curl -H "Authorization: Bearer abcdefghijklmnop1234567890" https://api.x.com', "abcdefghijklmnop1234567890"],
	["curl -u admin:p@ssw0rd https://x.com", "p@ssw0rd"],
	["key is k8Jd92HsLq0PzXm3VnB7cT5yRw1Eu4Ga ok", "k8Jd92HsLq0PzXm3VnB7cT5yRw1Eu4Ga"],
	["my password is Tr0ub4dor&3", "Tr0ub4dor&3"],
	["mysql --password=abc123xyz -h host", "abc123xyz"],
	["mysql --password hunter22 -h host", "hunter22"],
	["aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
	['password: str = "abc12345"', "abc12345"],
	["export TOKEN=abcdef1234567890", "abcdef1234567890"],
	["Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQxMjM=", "YWRtaW46c3VwZXJzZWNyZXQxMjM="],
];

// 这些不应该被改动（常见误报）
const negatives: string[] = [
	"password: string",
	"const password = process.env.DB_PASSWORD;",
	"max_tokens: 4096",
	"token: <your-token>",
	"commit 3f786850e387550fdab836ed7e6dc881de23001b",
	"id 550e8400-e29b-41d4-a716-446655440000",
	"The password is incorrect, try again",
	"see src/components/dashboard/UserProfileSettingsPanel.tsx",
	"call getUserAccountInformationById2Handler now",
	"密码管理器很好用",
	'api_key = os.getenv("API_KEY")',
	"password = getpass.getpass()",
	"token_type: bearer",
	"report_2024_Final_Version_Q3Summary.pdf",
	"# Basic internationalization setup",
	"password: Optional[str] = None",
	"function foo(password: string) { return 1; }",
	"def connect(host, password: str):",
	"login(user, password=getpass())",
	"const { password } = req.body;",
	"if (password === confirmPassword) {",
];

for (const [input, secret] of positives) {
	const v = new Vault();
	const r = redact(input, v, { entropy: true });
	ok(`redact   ${input.slice(0, 50).replace(/\n/g, "⏎")}`, !r.text.includes(secret) && r.text.includes("[REDACTED:"), r.text);
	ok(`  restore round-trip`, v.restore(r.text) === input, v.restore(r.text));
	ok(`  idempotent`, redact(r.text, v, { entropy: true }).text === r.text);
}

for (const input of negatives) {
	const r = redact(input, new Vault(), { entropy: true });
	ok(`keep     ${input}`, r.text === input, r.text);
}

{
	const v = new Vault();
	const r = redact("pw1: password=hunter2 ; again password=hunter2", v);
	const phs = new Set(r.hits.map((h) => h.placeholder));
	ok("same value → same placeholder", phs.size === 1, [...phs].join(","));
	ok("maskKnown catches bare reuse", redact("later I typed hunter2 again", v).text.includes("[REDACTED:") && !redact("later I typed hunter2 again", v).text.includes("hunter2"));
}

// ---- 用假的 pi 对象测试扩展钩子 ----------------------------------------------
{
	const handlers: Record<string, Function> = {};
	const commands: Record<string, any> = {};
	const fakePi: any = { on: (n: string, h: Function) => (handlers[n] = h), registerCommand: (n: string, o: any) => (commands[n] = o) };
	extension(fakePi);

	const notes: string[] = [];
	const ctx: any = { hasUI: true, ui: { notify: (m: string) => notes.push(m) } };

	const r1 = await handlers.input({ type: "input", text: "连库用，密码是 Xy7#kLm9pQ，用户 admin", source: "interactive", images: undefined }, ctx);
	ok("input → transform", r1.action === "transform" && !r1.text.includes("Xy7#kLm9pQ"), JSON.stringify(r1));
	ok("input → UI notified", notes.length === 1 && notes[0].includes("PASSWORD"), notes.join("|"));

	const r0 = await handlers.input({ type: "input", text: "帮我写一个排序函数", source: "interactive" }, ctx);
	ok("input → continue when clean", r0.action === "continue");

	const rx = await handlers.input({ type: "input", text: "密码是 Zz9#extension", source: "extension" }, ctx);
	ok("input → skips extension-sourced", rx.action === "continue");

	const ph = r1.text.match(/\[REDACTED:PASSWORD#\d+\]/)![0];
	const call: any = { type: "tool_call", toolName: "bash", input: { command: `psql -W '${ph}' -U admin` } };
	await handlers.tool_call(call);
	ok("tool_call → placeholder restored locally", call.input.command === "psql -W 'Xy7#kLm9pQ' -U admin", call.input.command);

	const res = await handlers.tool_result({ type: "tool_result", toolName: "bash", content: [{ type: "text", text: "connected with Xy7#kLm9pQ ok" }, { type: "image", data: "x", mimeType: "image/png" }] });
	ok("tool_result → echoed secret re-masked", res && !res.content[0].text.includes("Xy7#kLm9pQ") && res.content[1].type === "image", JSON.stringify(res));

	const msgs = [
		{ role: "user", content: [{ type: "text", text: "password=hunter2" }] },
		{ role: "assistant", content: [{ type: "thinking", thinking: "t", thinkingSignature: "sig" }, { type: "toolCall", id: "1", name: "bash", arguments: { command: "echo Xy7#kLm9pQ" } }] },
		{ role: "toolResult", content: [{ type: "text", text: "ok" }] },
	];
	const cr = await handlers.context({ type: "context", messages: msgs });
	ok("context → text & toolCall args scrubbed", cr && !JSON.stringify(cr.messages).includes("hunter2") && !JSON.stringify(cr.messages).includes("Xy7#kLm9pQ"), JSON.stringify(cr));
	ok("context → thinking part untouched", cr.messages[1].content[0] === msgs[1].content[0]);
	ok("context → returns undefined when nothing to change", (await handlers.context({ type: "context", messages: [{ role: "user", content: "hello" }] })) === undefined);

	await commands.redact.handler("off", ctx);
	const roff = await handlers.input({ type: "input", text: "password=hunter2", source: "interactive" }, ctx);
	ok("/redact off → passthrough", roff.action === "continue");
}

console.log(failed === 0 ? "\n全部通过" : `\n${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
