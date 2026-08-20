import { readFile, rename, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [bundlePath, requestPath, resultPath] = process.argv.slice(2);
if (bundlePath === undefined || requestPath === undefined || resultPath === undefined) {
  process.stderr.write("hand tool runner requires bundle, request, and result paths\n");
  process.exit(70);
}

const abort = new AbortController();
process.on("SIGTERM", () => abort.abort(new Error("tool call cancelled")));
process.on("SIGINT", () => abort.abort(new Error("tool call cancelled")));

const writeResult = async (value) => {
  const temporary = `${resultPath}.tmp`;
  await writeFile(temporary, JSON.stringify(value), { mode: 0o600 });
  await rename(temporary, resultPath);
};

try {
  const request = JSON.parse(await readFile(requestPath, "utf8"));
  // This import is intentionally the first evaluation of customer code. The Hand runner is
  // spawned only after Brain has durably journaled this operation's call intent.
  const loaded = await import(pathToFileURL(bundlePath).href);
  const tool = loaded.default;
  if (tool === null || typeof tool !== "object" || tool.kind !== "brain.tool") {
    throw new TypeError("bundle default export is not a Brain Tool");
  }
  if (tool.name !== request.definition.name || tool.description !== request.definition.description) {
    throw new TypeError("bundle Tool definition does not match the sealed descriptor");
  }
  if (typeof tool.execute !== "function") {
    throw new TypeError("bundle Tool has no executable handler");
  }
  const required = Array.isArray(tool.requiredEnv) ? tool.requiredEnv : [];
  if (JSON.stringify(required) !== JSON.stringify(request.required_env)) {
    throw new TypeError("bundle required environment names do not match the execution seal");
  }
  for (const name of required) {
    if (process.env[name] === undefined) throw new Error(`required environment variable ${name} is unavailable`);
  }
  const input = typeof tool.input?.parseAsync === "function"
    ? await tool.input.parseAsync(request.input)
    : request.input;
  const value = await tool.execute(input, {
    signal: abort.signal,
    callId: request.call_id,
    workspace: request.workspace,
    deadlineMs: request.deadline_ms,
  });
  const output = typeof tool.output?.parseAsync === "function"
    ? await tool.output.parseAsync(value)
    : value;
  JSON.stringify(output);
  await writeResult({ ok: true, output });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  try {
    await writeResult({ ok: false, error: message });
  } catch (writeError) {
    process.stderr.write(`could not persist tool result: ${String(writeError)}\n`);
  }
  process.exitCode = 1;
}
