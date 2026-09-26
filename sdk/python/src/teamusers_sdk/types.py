"""Permission grammar and zero-dependency ABAC condition evaluation."""

from __future__ import annotations

import math
import re
import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


MAX_CONDITION_SOURCE_LENGTH = 4 * 1024
CONDITION_MAX_NODES = 4096


@dataclass(frozen=True, slots=True)
class Subject:
    """Subject values exposed to an authorization condition."""

    id: str = ""
    kind: str = ""

    @property
    def ID(self) -> str:
        return self.id


@dataclass(frozen=True, slots=True)
class Resource:
    """Resource values exposed to an authorization condition."""

    owner_id: str = ""
    team_id: str = ""
    attrs: Mapping[str, Any] | None = None

    @property
    def OwnerID(self) -> str:
        return self.owner_id

    @property
    def TeamID(self) -> str:
        return self.team_id

    @property
    def Attrs(self) -> Mapping[str, Any] | None:
        return self.attrs


@dataclass(frozen=True, slots=True)
class Request:
    """Request values exposed to an authorization condition."""

    time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def Time(self) -> datetime:
        return self.time


@dataclass(frozen=True, slots=True)
class Context:
    """The fixed subject/resource/request condition context."""

    subject: Subject = field(default_factory=Subject)
    resource: Resource = field(default_factory=Resource)
    request: Request = field(default_factory=Request)

    @property
    def Subject(self) -> Subject:
        return self.subject

    @property
    def Resource(self) -> Resource:
        return self.resource

    @property
    def Request(self) -> Request:
        return self.request


ABACContext = Context
SubjectContext = Subject
ResourceContext = Resource
RequestContext = Request


class ConditionCompileError(ValueError):
    """The condition source is outside the supported safe subset."""


class _ConditionSyntaxError(ConditionCompileError):
    pass


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: Any
    position: int


class _Lexer:
    _two_character = {"==", "!=", "<=", ">=", "&&", "||"}
    _single_character = set("!<>()[],.-")

    def __init__(self, source: str) -> None:
        self._source = source
        self._index = 0

    def tokens(self) -> list[_Token]:
        result: list[_Token] = []
        source = self._source
        length = len(source)
        while self._index < length:
            index = self._index
            char = source[index]
            if char.isspace():
                self._index += 1
                continue
            if source.startswith("//", index) or source.startswith("/*", index):
                raise _ConditionSyntaxError("comments are not supported in conditions")
            if index + 1 < length and source[index : index + 2] in self._two_character:
                result.append(_Token("operator", source[index : index + 2], index))
                self._index += 2
                continue
            if char in self._single_character:
                if char == "." and index + 1 < length and source[index + 1].isdigit():
                    result.append(self._number())
                else:
                    result.append(_Token("operator", char, index))
                    self._index += 1
                continue
            if char in ('"', "'"):
                result.append(self._string())
                continue
            if char.isdigit():
                result.append(self._number())
                continue
            if char.isalpha() or char == "_":
                result.append(self._identifier())
                continue
            raise _ConditionSyntaxError(f"unsupported character at offset {index}: {char!r}")
        result.append(_Token("eof", "", length))
        return result

    def _identifier(self) -> _Token:
        start = self._index
        source = self._source
        self._index += 1
        while self._index < len(source) and (source[self._index].isalnum() or source[self._index] == "_"):
            self._index += 1
        value = source[start : self._index]
        if value in {"in", "true", "false", "nil", "null"}:
            return _Token("keyword", value, start)
        return _Token("identifier", value, start)

    def _number(self) -> _Token:
        start = self._index
        source = self._source
        if source[self._index] == ".":
            self._index += 1
            while self._index < len(source) and source[self._index].isdigit():
                self._index += 1
        else:
            while self._index < len(source) and source[self._index].isdigit():
                self._index += 1
            if self._index < len(source) and source[self._index] == ".":
                self._index += 1
                while self._index < len(source) and source[self._index].isdigit():
                    self._index += 1
        if self._index < len(source) and source[self._index] in "eE":
            self._index += 1
            if self._index < len(source) and source[self._index] in "+-":
                self._index += 1
            exponent_start = self._index
            while self._index < len(source) and source[self._index].isdigit():
                self._index += 1
            if exponent_start == self._index:
                raise _ConditionSyntaxError(f"invalid number at offset {start}")
        text = source[start : self._index]
        try:
            value: int | float = int(text) if not any(ch in text for ch in ".eE") else float(text)
        except ValueError as error:
            raise _ConditionSyntaxError(f"invalid number at offset {start}") from error
        if isinstance(value, float) and not math.isfinite(value):
            raise _ConditionSyntaxError(f"number is not finite at offset {start}")
        return _Token("number", value, start)

    def _string(self) -> _Token:
        start = self._index
        quote = self._source[self._index]
        self._index += 1
        chars: list[str] = []
        source = self._source
        while self._index < len(source):
            char = source[self._index]
            self._index += 1
            if char == quote:
                return _Token("string", "".join(chars), start)
            if char == "\\":
                if self._index >= len(source):
                    break
                escaped = source[self._index]
                self._index += 1
                escapes = {
                    "\\": "\\",
                    '"': '"',
                    "'": "'",
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    "b": "\b",
                    "f": "\f",
                }
                if escaped == "u":
                    digits = source[self._index : self._index + 4]
                    if len(digits) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                        raise _ConditionSyntaxError(f"invalid unicode escape at offset {self._index - 2}")
                    chars.append(chr(int(digits, 16)))
                    self._index += 4
                elif escaped in escapes:
                    chars.append(escapes[escaped])
                else:
                    raise _ConditionSyntaxError(f"unsupported string escape at offset {self._index - 2}")
            else:
                if ord(char) < 0x20:
                    raise _ConditionSyntaxError(f"control character in string at offset {self._index - 1}")
                chars.append(char)
        raise _ConditionSyntaxError(f"unterminated string at offset {start}")


@dataclass(frozen=True, slots=True)
class _Literal:
    value: Any


@dataclass(frozen=True, slots=True)
class _Path:
    root: str
    parts: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class _List:
    values: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class _Unary:
    operator: str
    value: Any


@dataclass(frozen=True, slots=True)
class _Binary:
    operator: str
    left: Any
    right: Any


class _Parser:
    _roots = {"subject", "resource", "request"}
    _subject_fields = {"id", "kind"}
    _resource_fields = {"owner_id", "team_id", "attrs"}
    _request_fields = {"time"}
    _comparison_operators = {"==", "!=", "<", "<=", ">", ">=", "in"}

    def __init__(self, source: str) -> None:
        self._tokens = _Lexer(source).tokens()
        self._index = 0
        self._nodes = 0

    def parse(self) -> Any:
        if self._peek().kind == "eof":
            return _Literal(True)
        expression = self._parse_or()
        token = self._peek()
        if token.kind != "eof":
            raise self._error(token, "unexpected token")
        if not self._is_boolean_expression(expression):
            raise _ConditionSyntaxError("condition must evaluate to bool")
        return expression

    def _parse_or(self) -> Any:
        expression = self._parse_and()
        while self._accept("||"):
            expression = self._node(_Binary("||", expression, self._parse_and()))
        return expression

    def _parse_and(self) -> Any:
        expression = self._parse_not()
        while self._accept("&&"):
            expression = self._node(_Binary("&&", expression, self._parse_not()))
        return expression

    def _parse_not(self) -> Any:
        if self._accept("!"):
            return self._node(_Unary("!", self._parse_not()))
        return self._parse_compare()

    def _parse_compare(self) -> Any:
        expression = self._parse_primary()
        if self._peek().value in self._comparison_operators:
            operator = self._advance().value
            right = self._parse_primary()
            expression = self._node(_Binary(operator, expression, right))
            if self._peek().value in self._comparison_operators:
                raise self._error(self._peek(), "comparison chaining is not supported")
        return expression

    def _parse_primary(self) -> Any:
        token = self._peek()
        if token.value == "-":
            self._advance()
            value = self._parse_primary()
            if not isinstance(value, _Literal) or isinstance(value.value, bool) or not isinstance(value.value, (int, float)):
                raise self._error(token, "unary - requires a numeric literal")
            return self._node(_Literal(-value.value))
        if token.kind == "number" or token.kind == "string":
            self._advance()
            return self._node(_Literal(token.value))
        if token.kind == "keyword":
            self._advance()
            if token.value == "true":
                return self._node(_Literal(True))
            if token.value == "false":
                return self._node(_Literal(False))
            if token.value in {"nil", "null"}:
                return self._node(_Literal(None))
            raise self._error(token, f"unexpected keyword {token.value!r}")
        if token.value == "(":
            self._advance()
            expression = self._parse_or()
            self._expect(")")
            return expression
        if token.value == "[":
            return self._parse_list()
        if token.kind == "identifier":
            return self._parse_path()
        raise self._error(token, "expected literal, path, or parenthesized expression")

    def _parse_path(self) -> _Path:
        root_token = self._advance()
        root = root_token.value
        if root not in self._roots:
            raise self._error(root_token, f"unknown condition root {root!r}")
        parts: list[tuple[str, Any]] = []
        while True:
            if self._accept("."):
                field = self._peek()
                if field.kind != "identifier":
                    raise self._error(field, "expected member name")
                self._advance()
                allowed = self._allowed_fields(root, parts)
                if field.value not in allowed and not (parts and parts[-1] == ("field", "attrs")):
                    raise self._error(field, f"unknown member {field.value!r}")
                parts.append(("field", field.value))
                continue
            if self._accept("["):
                key = self._peek()
                if key.kind not in {"string", "number"}:
                    raise self._error(key, "attribute indexes must be string or number literals")
                self._advance()
                self._expect("]")
                if not parts or parts[-1] != ("field", "attrs"):
                    raise self._error(key, "only resource.attrs can be indexed")
                parts.append(("index", key.value))
                continue
            break
        if not parts:
            raise self._error(root_token, "condition roots must use a member")
        return self._node(_Path(root, tuple(parts)))

    def _parse_list(self) -> Any:
        self._expect("[")
        values: list[Any] = []
        if not self._accept("]"):
            while True:
                values.append(self._parse_primary())
                if self._accept("]"):
                    break
                self._expect(",")
                if self._accept("]"):
                    break
        return self._node(_List(tuple(values)))

    def _allowed_fields(self, root: str, parts: Sequence[tuple[str, Any]]) -> set[str]:
        if not parts:
            if root == "subject":
                return self._subject_fields
            if root == "resource":
                return self._resource_fields
            return self._request_fields
        return set()

    def _is_boolean_expression(self, expression: Any) -> bool:
        if isinstance(expression, _Binary):
            return expression.operator in {"==", "!=", "<", "<=", ">", ">=", "in", "&&", "||"}
        if isinstance(expression, _Unary):
            return expression.operator == "!"
        if isinstance(expression, _Literal):
            return isinstance(expression.value, bool)
        return False

    def _node(self, expression: Any) -> Any:
        self._nodes += 1
        if self._nodes > CONDITION_MAX_NODES:
            raise _ConditionSyntaxError("condition AST exceeds node limit")
        return expression

    def _peek(self) -> _Token:
        return self._tokens[self._index]

    def _advance(self) -> _Token:
        token = self._peek()
        self._index += 1
        return token

    def _accept(self, value: str) -> bool:
        if self._peek().value == value:
            self._index += 1
            return True
        return False

    def _expect(self, value: str) -> _Token:
        token = self._peek()
        if token.value != value:
            raise self._error(token, f"expected {value!r}")
        self._index += 1
        return token

    @staticmethod
    def _error(token: _Token, message: str) -> _ConditionSyntaxError:
        return _ConditionSyntaxError(f"{message} at offset {token.position}")


_MISSING = object()


def _field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        if name in value:
            return value[name]
        aliases = {"owner_id": "ownerID", "team_id": "teamID"}
        alias = aliases.get(name)
        if alias is not None and alias in value:
            return value[alias]
        return _MISSING
    if hasattr(value, name):
        return getattr(value, name)
    aliases = {"owner_id": "OwnerID", "team_id": "TeamID", "id": "ID", "kind": "Kind", "time": "Time"}
    alias = aliases.get(name)
    if alias and hasattr(value, alias):
        return getattr(value, alias)
    return _MISSING


def _resolve_path(path: _Path, values: Context | Mapping[str, Any] | Any) -> Any:
    root = _field(values, path.root)
    if root is _MISSING:
        return _MISSING
    current = root
    for kind, part in path.parts:
        if kind == "field":
            current = _field(current, part)
        else:
            if current is _MISSING or current is None:
                return _MISSING
            if isinstance(current, Mapping):
                current = current.get(part, _MISSING)
            elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
                if isinstance(part, int) and 0 <= part < len(current):
                    current = current[part]
                else:
                    return _MISSING
            else:
                return _MISSING
    return current


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    return None


def _equal(left: Any, right: Any) -> bool:
    if left is _MISSING:
        left = None
    if right is _MISSING:
        right = None
    left_time = _as_datetime(left)
    right_time = _as_datetime(right)
    if left_time is not None and right_time is not None:
        return left_time.astimezone(timezone.utc) == right_time.astimezone(timezone.utc)
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return math.isfinite(float(left)) and math.isfinite(float(right)) and left == right
    return type(left) is type(right) and left == right


def _compare(left: Any, right: Any, operator: str) -> bool:
    if operator in {"==", "!="}:
        result = _equal(left, right)
        return not result if operator == "!=" else result
    if left is _MISSING:
        left = None
    if right is _MISSING:
        right = None
    left_time = _as_datetime(left)
    right_time = _as_datetime(right)
    if left_time is not None or right_time is not None:
        if left_time is None or right_time is None:
            raise TypeError("incomparable time values")
        left = left_time.astimezone(timezone.utc)
        right = right_time.astimezone(timezone.utc)
    elif isinstance(left, bool) or isinstance(right, bool):
        raise TypeError("boolean values are not ordered")
    elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
        if not math.isfinite(float(left)) or not math.isfinite(float(right)):
            raise TypeError("non-finite numbers are not comparable")
    elif not isinstance(left, str) or not isinstance(right, str):
        raise TypeError("values have incompatible types")
    if operator == "<":
        return left < right
    if operator == "<=":
        return left <= right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    raise TypeError(f"unsupported comparison operator {operator!r}")


def _eval(node: Any, values: Context | Mapping[str, Any] | Any) -> Any:
    if isinstance(node, _Literal):
        return node.value
    if isinstance(node, _Path):
        value = _resolve_path(node, values)
        return None if value is _MISSING else value
    if isinstance(node, _List):
        return [_eval(item, values) for item in node.values]
    if isinstance(node, _Unary):
        value = _eval(node.value, values)
        if node.operator == "!" and isinstance(value, bool):
            return not value
        raise TypeError("! requires a boolean operand")
    if isinstance(node, _Binary):
        if node.operator == "&&":
            left = _eval(node.left, values)
            if not isinstance(left, bool):
                raise TypeError("&& requires boolean operands")
            if not left:
                return False
            right = _eval(node.right, values)
            if not isinstance(right, bool):
                raise TypeError("&& requires boolean operands")
            return right
        if node.operator == "||":
            left = _eval(node.left, values)
            if not isinstance(left, bool):
                raise TypeError("|| requires boolean operands")
            if left:
                return True
            right = _eval(node.right, values)
            if not isinstance(right, bool):
                raise TypeError("|| requires boolean operands")
            return right
        left = _eval(node.left, values)
        right = _eval(node.right, values)
        if node.operator == "in":
            if right is None or right is _MISSING:
                return False
            if isinstance(right, Mapping):
                return left in right
            if isinstance(right, (str, bytes, bytearray, list, tuple, set, frozenset)):
                return any(_equal(left, item) for item in right)
            raise TypeError("right operand of in is not a collection")
        return _compare(left, right, node.operator)
    raise TypeError("invalid condition node")


@dataclass(frozen=True, slots=True)
class CompiledCondition:
    """A compiled condition whose runtime errors deny access."""

    source: str = ""
    _tree: Any = field(default=None, repr=False, compare=False)

    @property
    def Source(self) -> str:
        return self.source

    def eval(self, values: Context | Mapping[str, Any] | Any) -> bool:
        if self._tree is None:
            return True
        try:
            result = _eval(self._tree, values)
            return result if isinstance(result, bool) else False
        except BaseException:
            return False

    def evaluate(self, values: Context | Mapping[str, Any] | Any) -> bool:
        return self.eval(values)

    def Eval(self, values: Context | Mapping[str, Any] | Any) -> bool:
        return self.eval(values)

    def Evaluate(self, values: Context | Mapping[str, Any] | Any) -> bool:
        return self.eval(values)

    def eval_with_context(self, values: Context | Mapping[str, Any] | Any, context: Any = None) -> bool:
        if context is not None and hasattr(context, "cancelled") and context.cancelled():
            return False
        return self.eval(values)

    def EvalWithContext(self, context: Any, values: Context | Mapping[str, Any] | Any) -> bool:
        return self.eval_with_context(values, context)


def compile_condition(source: str) -> CompiledCondition:
    if not isinstance(source, str):
        raise ConditionCompileError("condition source must be a string")
    if len(source.encode("utf-8")) > MAX_CONDITION_SOURCE_LENGTH:
        raise ConditionCompileError("condition source exceeds 4 KiB")
    if not source.strip():
        return CompiledCondition(source=source)
    try:
        tree = _Parser(source).parse()
    except (ConditionCompileError, RecursionError) as error:
        if isinstance(error, ConditionCompileError):
            raise
        raise ConditionCompileError("condition nesting exceeds limit") from error
    return CompiledCondition(source=source, _tree=tree)


def CompileCondition(source: str) -> CompiledCondition:
    return compile_condition(source)
def Eval(condition: CompiledCondition | None, values: Context | Mapping[str, Any] | Any) -> bool:
    return True if condition is None else condition.eval(values)


def Evaluate(condition: CompiledCondition | None, values: Context | Mapping[str, Any] | Any) -> bool:
    return Eval(condition, values)


# Pythonic and Go-shaped aliases.
Compile = compile_condition
Condition = CompiledCondition


_RESOURCE_RE = re.compile(r"^[a-z][a-z0-9_.-]*$")
_ACTION_RE = re.compile(r"^(?:\*|[a-z][a-z0-9_-]*)$")
_SCOPES = {"own", "team", "any", "*"}


@dataclass(frozen=True, slots=True)
class Permission:
    resource: str
    action: str
    scope: str
    deny: bool = False

    @property
    def Resource(self) -> str:
        return self.resource

    @property
    def Action(self) -> str:
        return self.action

    @property
    def Scope(self) -> str:
        return self.scope
    @property
    def Deny(self) -> bool:
        return self.deny

    def validate(self) -> None:
        if not _RESOURCE_RE.fullmatch(self.resource):
            raise ValueError(f"invalid permission resource {self.resource!r}")
        if not _ACTION_RE.fullmatch(self.action):
            raise ValueError(f"invalid permission action {self.action!r}")
        if self.scope not in _SCOPES:
            raise ValueError(f"invalid permission scope {self.scope!r}")
        if self.resource == "iam":
            if self.scope == "any":
                return
            if self.action in {"teams", "groups", "roles", "bindings"} and self.scope == "team":
                return
            raise ValueError(f"invalid iam permission scope {self.scope!r} for area {self.action!r}")

    def Validate(self) -> None:
        self.validate()

    def string(self) -> str:
        prefix = "!" if self.deny else ""
        return f"{prefix}{self.resource}:{self.action}:{self.scope}"

    def String(self) -> str:
        return self.string()

    def __str__(self) -> str:
        return self.string()


def parse_permission(key: str) -> Permission:
    if not isinstance(key, str) or key == "":
        raise ValueError("permission key is empty")
    deny = key.startswith("!")
    if deny:
        key = key[1:]
    parts = key.split(":")
    if len(parts) != 3:
        raise ValueError("permission key must contain resource, action, and scope")
    permission = Permission(parts[0], parts[1], parts[2], deny)
    permission.validate()
    return permission


def Parse(key: str) -> Permission:
    return parse_permission(key)


def ParsePermission(key: str) -> Permission:
    return parse_permission(key)


def validate_permission_key(key: str) -> None:
    parse_permission(key)


def ValidatePermissionKey(key: str) -> None:
    validate_permission_key(key)
def Validate(key: str) -> None:
    validate_permission_key(key)


def String(permission: Permission) -> str:
    return permission.string()


def match(grant: Permission, request: Permission) -> bool:
    try:
        grant.validate()
        request.validate()
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        grant.deny == request.deny
        and (grant.resource == request.resource)
        and (grant.action == "*" or grant.action == request.action)
        and (grant.scope == "*" or grant.scope == request.scope)
    )


def Match(grant: Permission, request: Permission) -> bool:
    return match(grant, request)


def match_keys(grant: str, request: str) -> bool:
    try:
        return match(parse_permission(grant), parse_permission(request))
    except (TypeError, ValueError):
        return False


def MatchKeys(grant: str, request: str) -> bool:
    return match_keys(grant, request)


# Keep a small convenience alias used by some Python callers.
parse = parse_permission
validate = validate_permission_key

__all__ = [
    "ABACContext",
    "Eval",
    "Evaluate",
    "CONDITION_MAX_NODES",
    "String",
    "Compile",
    "CompileCondition",
    "CompiledCondition",
    "Condition",
    "ConditionCompileError",
    "Context",
    "MAX_CONDITION_SOURCE_LENGTH",
    "Match",
    "MatchKeys",
    "Parse",
    "Validate",
    "ParsePermission",
    "Permission",
    "Request",
    "RequestContext",
    "Resource",
    "ResourceContext",
    "Subject",
    "SubjectContext",
    "ValidatePermissionKey",
    "compile_condition",
    "match",
    "match_keys",
    "parse",
    "parse_permission",
    "validate",
    "validate_permission_key",
]
