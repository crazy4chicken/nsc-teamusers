const MAX_CONDITION_SOURCE_LENGTH = 4 * 1024;
const MAX_AST_NODES = 4096;
const MAX_PARSE_DEPTH = 128;

/** Subject values exposed to an authorization condition. */
export interface Subject {
  readonly id?: string;
  readonly kind?: string;
  readonly [key: string]: unknown;
}

/** Resource values exposed to an authorization condition. */
export interface Resource {
  readonly owner_id?: string;
  readonly team_id?: string;
  readonly attrs?: Readonly<Record<string, unknown>>;
  readonly ownerId?: string;
  readonly teamId?: string;
  readonly [key: string]: unknown;
}

/** Request values exposed to an authorization condition. */
export interface Request {
  readonly time?: Date | string | number;
  readonly [key: string]: unknown;
}

/** Complete condition context. Only the documented members are readable. */
export interface Context {
  readonly subject: Subject;
  readonly resource: Resource;
  readonly request: Request;
}

export type ABACContext = Context;
export type SubjectContext = Subject;
export type ResourceContext = Resource;
export type RequestContext = Request;

export const MaxConditionSourceLength = MAX_CONDITION_SOURCE_LENGTH;

/** A compile-time error raised for unsupported or malformed condition syntax. */
export class ConditionCompileError extends Error {
  public readonly code = "CONDITION_COMPILE_FAILED" as const;

  public constructor(message: string) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

interface Token {
  readonly kind: "identifier" | "number" | "string" | "operator" | "punctuation" | "eof";
  readonly text: string;
  readonly position: number;
}

type Node =
  | { readonly kind: "literal"; readonly value: unknown }
  | { readonly kind: "path"; readonly segments: readonly (string | Node)[] }
  | { readonly kind: "array"; readonly items: readonly Node[] }
  | { readonly kind: "unary"; readonly operator: "!"; readonly operand: Node }
  | {
      readonly kind: "binary";
      readonly operator: "||" | "&&" | "==" | "!=" | "<" | "<=" | ">" | ">=" | "in";
      readonly left: Node;
      readonly right: Node;
    };

class Parser {
  private readonly tokens: readonly Token[];
  private index = 0;
  private nodes = 0;
  private depth = 0;

  public constructor(tokens: readonly Token[]) {
    this.tokens = tokens;
  }

  public parse(): Node {
    const node = this.parseOr();
    const token = this.current();
    if (token.kind !== "eof") {
      throw this.error(`unexpected token ${JSON.stringify(token.text)}`, token);
    }
    if (inferType(node) !== "boolean") {
      throw new ConditionCompileError("condition expression must evaluate to bool");
    }
    return node;
  }

  private parseOr(): Node {
    return this.parseBinary("||", () => this.parseAnd());
  }

  private parseAnd(): Node {
    return this.parseBinary("&&", () => this.parseUnary());
  }

  private parseBinary(
    operator: "||" | "&&",
    parseOperand: () => Node,
  ): Node {
    let left = parseOperand();
    while (this.accept("operator", operator)) {
      if (inferType(left) !== "boolean") {
        throw this.error(`${operator} requires boolean operands`, this.current());
      }
      const right = parseOperand();
      if (inferType(right) !== "boolean") {
        throw this.error(`${operator} requires boolean operands`, this.current());
      }
      left = this.make({ kind: "binary", operator, left, right });
    }
    return left;
  }

  private parseUnary(): Node {
    if (this.accept("operator", "!")) {
      const operand = this.parseUnary();
      if (inferType(operand) !== "boolean") {
        throw this.error("! requires a boolean operand", this.current());
      }
      return this.make({ kind: "unary", operator: "!", operand });
    }
    return this.parseComparison();
  }

  private parseComparison(): Node {
    let left = this.parsePrimary();
    const token = this.current();
    let operator: "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | undefined;
    if (token.kind === "operator" && isComparisonOperator(token.text)) {
      operator = token.text;
    } else if (token.kind === "identifier" && token.text === "in") {
      operator = "in";
    }
    if (operator === undefined) {
      return left;
    }
    this.index += 1;
    const right = this.parsePrimary();
    left = this.make({ kind: "binary", operator, left, right });
    const trailing = this.current();
    if (
      trailing.kind === "operator" &&
      isComparisonOperator(trailing.text)
    ) {
      throw this.error("comparisons cannot be chained", trailing);
    }
    return left;
  }

  private parsePrimary(): Node {
    const token = this.current();
    if (token.kind === "punctuation" && token.text === "(") {
      this.index += 1;
      this.depth += 1;
      if (this.depth > MAX_PARSE_DEPTH) {
        throw this.error("condition nesting exceeds limit", token);
      }
      const value = this.parseOr();
      this.expect("punctuation", ")");
      this.depth -= 1;
      return value;
    }
    if (token.kind === "punctuation" && token.text === "[") {
      this.index += 1;
      const items: Node[] = [];
      if (!this.accept("punctuation", "]")) {
        do {
          items.push(this.parseOr());
        } while (this.accept("punctuation", ","));
        this.expect("punctuation", "]");
      }
      return this.make({ kind: "array", items });
    }
    if (token.kind === "number") {
      this.index += 1;
      return this.make({ kind: "literal", value: Number(token.text) });
    }
    if (token.kind === "string") {
      this.index += 1;
      return this.make({ kind: "literal", value: token.text });
    }
    if (token.kind === "identifier") {
      this.index += 1;
      if (token.text === "true" || token.text === "false") {
        return this.make({ kind: "literal", value: token.text === "true" });
      }
      if (token.text === "null" || token.text === "nil") {
        return this.make({ kind: "literal", value: null });
      }
      if (token.text === "in") {
        throw this.error("in must follow a value", token);
      }
      return this.parsePath(token);
    }
    throw this.error(`expected a value, got ${JSON.stringify(token.text)}`, token);
  }

  private parsePath(root: Token): Node {
    if (root.text !== "subject" && root.text !== "resource" && root.text !== "request") {
      throw this.error(`unknown condition root ${JSON.stringify(root.text)}`, root);
    }
    const segments: Array<string | Node> = [root.text];
    while (this.accept("punctuation", ".") || this.accept("punctuation", "[")) {
      const opener = this.tokens[this.index - 1];
      if (opener.text === ".") {
        const member = this.current();
        if (member.kind !== "identifier") {
          throw this.error("member name is required after '.'", member);
        }
        this.index += 1;
        validateMemberPath(segments, member);
        segments.push(member.text);
      } else {
        const key = this.parseOr();
        this.expect("punctuation", "]");
        if (segments.length < 2 || segments[segments.length - 1] !== "attrs") {
          throw this.error("index access is only supported on resource.attrs", opener);
        }
        segments.push(key);
      }
    }
    if (segments.length === 1) {
      throw this.error("a condition root must select a member", root);
    }
    return this.make({ kind: "path", segments });
  }

  private current(): Token {
    return this.tokens[this.index] ?? this.tokens[this.tokens.length - 1];
  }

  private accept(kind: Token["kind"], text: string): boolean {
    const token = this.current();
    if (token.kind !== kind || token.text !== text) {
      return false;
    }
    this.index += 1;
    return true;
  }

  private expect(kind: Token["kind"], text: string): Token {
    const token = this.current();
    if (!this.accept(kind, text)) {
      throw this.error(`expected ${JSON.stringify(text)}`, token);
    }
    return token;
  }

  private make<T extends Node>(node: T): T {
    this.nodes += 1;
    if (this.nodes > MAX_AST_NODES) {
      throw new ConditionCompileError(`condition AST exceeds ${MAX_AST_NODES} nodes`);
    }
    return node;
  }

  private error(message: string, token: Token): ConditionCompileError {
    return new ConditionCompileError(`${message} at offset ${token.position}`);
  }
}

/** A compiled boolean condition. Evaluation errors fail closed. */
export class CompiledCondition {
  public readonly source: string;
  public readonly Source: string;
  private readonly program?: Node;

  public constructor(source: string, program?: Node) {
    this.source = source;
    this.Source = source;
    this.program = program;
  }

  /** Evaluate the condition, returning false for every runtime error. */
  public eval(values: Context): boolean {
    if (this.program === undefined) {
      return true;
    }
    try {
      return evaluateNode(this.program, values) === true;
    } catch {
      return false;
    }
  }

  public Eval(values: Context): boolean {
    return this.eval(values);
  }

  public evaluate(values: Context): boolean {
    return this.eval(values);
  }

  public Evaluate(values: Context): boolean {
    return this.eval(values);
  }

  /** Evaluate while honoring an already-cancelled request signal. */
  public evalWithContext(signal: AbortSignal | undefined, values: Context): boolean {
    if (signal?.aborted) {
      return false;
    }
    const allowed = this.eval(values);
    return signal?.aborted ? false : allowed;
  }

  public EvalWithContext(signal: AbortSignal | undefined, values: Context): boolean {
    return this.evalWithContext(signal, values);
  }
}

/** Compile the documented condition subset without external expression dependencies. */
export function compileCondition(source: string): CompiledCondition {
  const bytes = new TextEncoder().encode(source).byteLength;
  if (bytes > MAX_CONDITION_SOURCE_LENGTH) {
    throw new ConditionCompileError("condition source exceeds 4 KiB");
  }
  if (source.trim() === "") {
    return new CompiledCondition(source);
  }
  const parser = new Parser(tokenize(source));
  return new CompiledCondition(source, parser.parse());
}

export const CompileCondition = compileCondition;

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < source.length) {
    const start = index;
    const char = source[index];
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (/[A-Za-z_]/u.test(char)) {
      index += 1;
      while (index < source.length && /[A-Za-z0-9_]/u.test(source[index])) {
        index += 1;
      }
      const text = source.slice(start, index);
      tokens.push({ kind: "identifier", text, position: start });
      continue;
    }
    if (/[0-9]/u.test(char) || (char === "-" && /[0-9]/u.test(source[index + 1] ?? ""))) {
      index += char === "-" ? 1 : 0;
      while (index < source.length && /[0-9]/u.test(source[index])) {
        index += 1;
      }
      if (source[index] === ".") {
        index += 1;
        while (index < source.length && /[0-9]/u.test(source[index])) {
          index += 1;
        }
      }
      const text = source.slice(start, index);
      if (!Number.isFinite(Number(text))) {
        throw new ConditionCompileError(`invalid number at offset ${start}`);
      }
      tokens.push({ kind: "number", text, position: start });
      continue;
    }
    if (char === '"' || char === "'") {
      const quote = char;
      index += 1;
      let escaped = false;
      let raw = "";
      let closed = false;
      while (index < source.length) {
        const current = source[index++];
        if (!escaped && current === quote) {
          closed = true;
          break;
        }
        if (!escaped && current === "\n") {
          throw new ConditionCompileError(`unterminated string at offset ${start}`);
        }
        raw += current;
        if (escaped) {
          escaped = false;
        } else {
          escaped = current === "\\";
        }
      }
      if (!closed || escaped) {
        throw new ConditionCompileError(`unterminated string at offset ${start}`);
      }
      let text: string;
      try {
        text = quote === '"' ? JSON.parse(`"${raw}"`) as string : decodeSingleQuoted(raw);
      } catch (error) {
        throw new ConditionCompileError(`invalid string at offset ${start}: ${String(error)}`);
      }
      tokens.push({ kind: "string", text, position: start });
      continue;
    }
    const two = source.slice(index, index + 2);
    if (["==", "!=", "<=", ">=", "&&", "||"].includes(two)) {
      tokens.push({ kind: "operator", text: two, position: start });
      index += 2;
      continue;
    }
    if (["!", "<", ">"].includes(char)) {
      tokens.push({ kind: "operator", text: char, position: start });
      index += 1;
      continue;
    }
    if ([".", "(", ")", "[", "]", ","].includes(char)) {
      tokens.push({ kind: "punctuation", text: char, position: start });
      index += 1;
      continue;
    }
    throw new ConditionCompileError(`unsupported character ${JSON.stringify(char)} at offset ${start}`);
  }
  tokens.push({ kind: "eof", text: "", position: source.length });
  return tokens;
}

function decodeSingleQuoted(raw: string): string {
  let value = "";
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    if (char !== "\\") {
      value += char;
      continue;
    }
    const escaped = raw[++index];
    if (escaped === undefined) {
      throw new Error("trailing escape");
    }
    const replacements: Record<string, string> = { n: "\n", r: "\r", t: "\t", "\\": "\\", "'": "'" };
    value += replacements[escaped] ?? escaped;
  }
  return value;
}

function isComparisonOperator(value: string): value is "==" | "!=" | "<" | "<=" | ">" | ">=" {
  return value === "==" || value === "!=" || value === "<" || value === "<=" || value === ">" || value === ">=";
}

function validateMemberPath(segments: readonly (string | Node)[], token: Token): void {
  const root = segments[0];
  const previous = segments[segments.length - 1];
  if (segments.length === 1) {
    if (
      (root === "subject" && token.text !== "id" && token.text !== "kind") ||
      (root === "resource" && token.text !== "owner_id" && token.text !== "team_id" && token.text !== "attrs" && token.text !== "ownerId" && token.text !== "teamId") ||
      (root === "request" && token.text !== "time")
    ) {
      throw new ConditionCompileError(`unsupported member ${JSON.stringify(token.text)}`);
    }
    return;
  }
  if (root === "resource" && previous === "attrs") {
    return;
  }
  throw new ConditionCompileError(`unsupported member ${JSON.stringify(token.text)}`);
}

function inferType(node: Node): "boolean" | "string" | "number" | "date" | "unknown" {
  if (node.kind === "literal") {
    if (typeof node.value === "boolean") return "boolean";
    if (typeof node.value === "string") return "string";
    if (typeof node.value === "number") return "number";
    return "unknown";
  }
  if (node.kind === "array") return "unknown";
  if (node.kind === "path") {
    const root = node.segments[0];
    const leaf = node.segments[node.segments.length - 1];
    if (root === "subject" && (leaf === "id" || leaf === "kind")) return "string";
    if (root === "resource" && (leaf === "owner_id" || leaf === "team_id" || leaf === "ownerId" || leaf === "teamId")) return "string";
    if (root === "request" && leaf === "time") return "date";
    return "unknown";
  }
  if (node.kind === "unary") return "boolean";
  return node.operator === "&&" || node.operator === "||" || node.operator === "==" || node.operator === "!=" || node.operator === "<" || node.operator === "<=" || node.operator === ">" || node.operator === ">=" || node.operator === "in"
    ? "boolean"
    : "unknown";
}

function evaluateNode(node: Node, context: Context): unknown {
  if (node.kind === "literal") return node.value;
  if (node.kind === "array") return node.items.map((item) => evaluateNode(item, context));
  if (node.kind === "path") return evaluatePath(node.segments, context);
  if (node.kind === "unary") {
    const value = evaluateNode(node.operand, context);
    if (typeof value !== "boolean") throw new Error("logical negation requires bool");
    return !value;
  }
  if (node.operator === "&&") {
    const left = evaluateNode(node.left, context);
    if (left !== true) return false;
    return evaluateNode(node.right, context) === true;
  }

  if (node.operator === "||") {
    const left = evaluateNode(node.left, context);
    if (left === true) return true;
    return evaluateNode(node.right, context) === true;
  }
  const left = evaluateNode(node.left, context);
  const right = evaluateNode(node.right, context);
  if (node.operator === "in") return isIn(left, right);
  if (!isComparisonOperator(node.operator)) throw new Error("unsupported binary operator");
  return compareValues(left, right, node.operator);
}

function evaluatePath(segments: readonly (string | Node)[], context: Context): unknown {
  const root = segments[0];
  const contextRecord = context as unknown as Record<string, unknown>;
  let value: unknown = root === "subject"
    ? context.subject ?? contextRecord.Subject
    : root === "resource"
      ? context.resource ?? contextRecord.Resource
      : context.request ?? contextRecord.Request;
  if (value === undefined) return undefined;
  for (const segment of segments.slice(1)) {
    if (typeof segment === "string") {
      if (value === null || typeof value !== "object") return undefined;
      const record = value as Record<string, unknown>;
      if (segment in record) {
        value = record[segment];
      } else if (root === "subject" && segment === "id") {
        value = record.ID;
      } else if (root === "subject" && segment === "kind") {
        value = record.Kind;
      } else if (root === "resource" && segment === "owner_id") {
        value = record.ownerId ?? record.OwnerID;
      } else if (root === "resource" && segment === "team_id") {
        value = record.teamId ?? record.TeamID;
      } else if (root === "request" && segment === "time") {
        value = record.Time;
      } else {
        return undefined;
      }
    } else {
      const key = evaluateNode(segment, context);
      if (typeof key !== "string" && typeof key !== "number") return undefined;
      if (value === null || typeof value !== "object") return undefined;
      const record = value as Record<string | number, unknown>;
      value = Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
    }
  }
  return value;
}

function compareValues(
  left: unknown,
  right: unknown,
  operator: "==" | "!=" | "<" | "<=" | ">" | ">=",
): boolean {
  const normalized = normalizeComparable(left, right);
  if (operator === "==") return sameValue(normalized.left, normalized.right);
  if (operator === "!=") return !sameValue(normalized.left, normalized.right);
  if (typeof normalized.left !== "number" || typeof normalized.right !== "number") {
    throw new Error("ordered comparison requires comparable values");
  }
  if (operator === "<") return normalized.left < normalized.right;
  if (operator === "<=") return normalized.left <= normalized.right;
  if (operator === ">") return normalized.left > normalized.right;
  return normalized.left >= normalized.right;
}

function normalizeComparable(left: unknown, right: unknown): { left: unknown; right: unknown } {
  const leftTime = timeValue(left);
  const rightTime = timeValue(right);
  if (leftTime !== undefined && rightTime !== undefined) {
    return { left: leftTime, right: rightTime };
  }
  return { left, right };
}

function timeValue(value: unknown): number | undefined {
  if (value instanceof Date) {
    const timestamp = value.getTime();
    return Number.isFinite(timestamp) ? timestamp : undefined;
  }
  if (typeof value === "string") {
    const timestamp = Date.parse(value);
    return Number.isNaN(timestamp) ? undefined : timestamp;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.abs(value) < 1e11 ? value * 1000 : value;
  }
  return undefined;
}

function sameValue(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  const leftTime = timeValue(left);
  const rightTime = timeValue(right);
  return leftTime !== undefined && rightTime !== undefined && leftTime === rightTime;
}

function isIn(left: unknown, right: unknown): boolean {
  if (Array.isArray(right)) return right.some((candidate) => sameValue(left, candidate));
  if (typeof right === "string") return typeof left === "string" && right.includes(left);
  if (right !== null && typeof right === "object") {
    return (typeof left === "string" || typeof left === "number") && Object.prototype.hasOwnProperty.call(right, left);
  }
  return false;
}
