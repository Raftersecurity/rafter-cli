"""Parity-safe YAML loading for attack-surface extractors."""

from __future__ import annotations

import re
from collections.abc import Generator
from typing import Any, Literal, TypeAlias

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 100_000

YamlStringValue: TypeAlias = str | list["YamlStringValue"] | dict[str, "YamlStringValue"]
ParsedScalar: TypeAlias = str | int | bool | None
YamlAdapterReason: TypeAlias = Literal["parse_error", "unsupported_syntax"]

_NULL_SCALARS = frozenset({"~", "null", "Null", "NULL"})
_TRUE_SCALARS = frozenset({"true", "True", "TRUE"})
_FALSE_SCALARS = frozenset({"false", "False", "FALSE"})
_DECIMAL_INTEGER = re.compile(r"^[+-]?(?:0|[1-9][0-9]*)$")
_PARSE_ERROR_DETAIL = "YAML could not be parsed"
_UNSUPPORTED_TAG_DETAIL = "YAML uses an unsupported tag"
_UNSUPPORTED_KEY_DETAIL = "YAML mapping keys must be scalar strings"
_UNSUPPORTED_EMPTY_KEY_DETAIL = "Empty YAML mapping keys are unsupported"
_BLOCK_SCALAR_HEADER = re.compile(
    r"(?:^|:\s*|-\s*)[|>](?:(?:[+-]([1-9])?)|(?:([1-9])[+-]?))?\s*$"
)


class YamlAdapterError(ValueError):
    """A content-free failure that an extractor can turn into Unanalyzed."""

    def __init__(self, reason: YamlAdapterReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class _UnsupportedYamlSyntax(Exception):
    pass


class RafterBaseLoader(yaml.BaseLoader):
    """String-only loader with strict tags, scalar keys, and duplicate rejection."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._rafter_source = stream if isinstance(stream, str) else None

    def compose_node(self, parent: Node | None, index: Any) -> Node:
        if (
            isinstance(parent, MappingNode)
            and index is None
            and self.check_event(AliasEvent)
        ):
            event = self.peek_event()
            if (
                self._rafter_source is not None
                and self._rafter_source[event.end_mark.index : event.end_mark.index + 1]
                == ":"
            ):
                raise ComposerError(
                    "while composing a mapping",
                    parent.start_mark,
                    "compact aliases used as mapping keys are unsupported",
                    event.start_mark,
                )
        return super().compose_node(parent, index)

    def construct_object(self, node: Node, deep: bool = False) -> Any:
        if isinstance(node, ScalarNode):
            expected_tag = "tag:yaml.org,2002:str"
        elif isinstance(node, SequenceNode):
            expected_tag = "tag:yaml.org,2002:seq"
        elif isinstance(node, MappingNode):
            expected_tag = "tag:yaml.org,2002:map"
        else:
            raise _UnsupportedYamlSyntax("unsupported YAML node kind")
        if node.tag != expected_tag:
            raise _UnsupportedYamlSyntax(_UNSUPPORTED_TAG_DETAIL)
        return super().construct_object(node, deep=deep)


def _construct_mapping(
    loader: RafterBaseLoader,
    node: Node,
    deep: bool = False,
) -> Generator[dict[str, Any], None, None]:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a mapping node", node.start_mark)

    mapping: dict[str, Any] = {}
    # Yield first so aliases can refer to the mapping. The adapter later rejects
    # cycles and bounds expanded aliases while allowing ordinary aliases.
    yield mapping
    for key_node, value_node in node.value:
        if not isinstance(key_node, ScalarNode):
            raise _UnsupportedYamlSyntax(_UNSUPPORTED_KEY_DETAIL)
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise _UnsupportedYamlSyntax(_UNSUPPORTED_KEY_DETAIL)
        if not key:
            raise _UnsupportedYamlSyntax(_UNSUPPORTED_EMPTY_KEY_DETAIL)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found duplicate mapping key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)


def _construct_sequence(
    loader: RafterBaseLoader,
    node: Node,
    deep: bool = False,
) -> Generator[list[Any], None, None]:
    if not isinstance(node, SequenceNode):
        raise ConstructorError(None, None, "expected a sequence node", node.start_mark)
    sequence: list[Any] = []
    yield sequence
    sequence.extend(loader.construct_sequence(node, deep=deep))


RafterBaseLoader.add_constructor("tag:yaml.org,2002:map", _construct_mapping)
RafterBaseLoader.add_constructor("tag:yaml.org,2002:seq", _construct_sequence)


def parse_scalar(value: str) -> ParsedScalar:
    """Apply Rafter's deliberately narrow scalar rules after string-only loading.

    Floats, timestamps, base-prefixed integers, digit separators, leading-zero
    integers, and integers outside JavaScript's safe range remain strings.
    """

    if value in _NULL_SCALARS:
        return None
    if value in _TRUE_SCALARS:
        return True
    if value in _FALSE_SCALARS:
        return False
    if _DECIMAL_INTEGER.fullmatch(value):
        digits = value[1:] if value[:1] in {"+", "-"} else value
        if len(digits) < 16 or (
            len(digits) == 16 and digits <= "9007199254740991"
        ):
            return int(value, 10)
    return value


def load_yaml_string_only(source: str) -> YamlStringValue:
    """Load YAML into a bounded tree containing only strings, lists, and dicts.

    The boundary is source text -> BaseLoader -> strict tag/key checks -> copied
    string tree. Alias occurrences are copied under shared depth/node budgets,
    rejecting cycles and expansion bombs before callers serialize the result.
    """

    if _has_unsupported_tab(source):
        raise YamlAdapterError(
            "unsupported_syntax", "YAML containing tab characters is unsupported"
        )
    try:
        loaded = yaml.load(source, Loader=RafterBaseLoader)
    except YamlAdapterError:
        raise
    except _UnsupportedYamlSyntax as error:
        raise YamlAdapterError("unsupported_syntax", str(error)) from None
    except (yaml.YAMLError, RecursionError):
        raise YamlAdapterError("parse_error", _PARSE_ERROR_DETAIL) from None

    state = {"nodes": 0}
    try:
        return _normalize_value(loaded, 0, set(), state)
    except RecursionError:
        raise YamlAdapterError("parse_error", _PARSE_ERROR_DETAIL) from None


def _has_unsupported_tab(source: str) -> bool:
    block_parent_indent: int | None = None
    block_content_indent: int | None = None
    quote: str | None = None

    for line in re.split(r"\r?\n", source):
        indent = len(line) - len(line.lstrip(" "))
        if block_parent_indent is not None:
            if not line.strip() and "\t" not in line:
                continue
            if block_content_indent is None and indent > block_parent_indent:
                block_content_indent = indent
                continue
            if block_content_indent is not None and indent >= block_content_indent:
                continue
            block_parent_indent = None
            block_content_indent = None

        structural: list[str] = []
        index = 0
        while index < len(line):
            character = line[index]
            if quote == "'":
                if (
                    character == "'"
                    and index + 1 < len(line)
                    and line[index + 1] == "'"
                ):
                    index += 1
                elif character == "'":
                    quote = None
            elif quote == '"':
                if character == "\\":
                    index += 1
                elif character == '"':
                    quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == "#" and (index == 0 or line[index - 1].isspace()):
                break
            elif character == "\t":
                return True
            else:
                structural.append(character)
            index += 1

        structural_text = "".join(structural)
        block_header = (
            _BLOCK_SCALAR_HEADER.search(structural_text.rstrip())
            if quote is None
            else None
        )
        if block_header:
            sequence_prefix = re.match(r"^ *(?:- +)+", structural_text)
            explicit_indent = block_header.group(1) or block_header.group(2)
            direct_sequence_scalar = bool(
                sequence_prefix
                and structural_text[len(sequence_prefix.group()) :].startswith(
                    ("|", ">")
                )
            )
            if direct_sequence_scalar:
                block_parent_indent = sequence_prefix.group().rfind("-")
                block_content_indent = block_parent_indent + int(
                    explicit_indent or 2
                )
            else:
                block_parent_indent = (
                    len(sequence_prefix.group()) if sequence_prefix else indent
                )
                block_content_indent = (
                    block_parent_indent + int(explicit_indent)
                    if explicit_indent
                    else None
                )
    return False


def load_yaml_safe(source: str) -> YamlStringValue:
    """Public adapter name; ``load_yaml_string_only`` states its contract."""

    return load_yaml_string_only(source)


def _normalize_value(
    value: Any,
    depth: int,
    active: set[int],
    state: dict[str, int],
) -> YamlStringValue:
    state["nodes"] += 1
    if state["nodes"] > MAX_YAML_NODES:
        raise YamlAdapterError("parse_error", _PARSE_ERROR_DETAIL)
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if not isinstance(value, (list, dict)):
        raise YamlAdapterError(
            "unsupported_syntax", "YAML parser produced an unsupported scalar"
        )
    if depth >= MAX_YAML_DEPTH:
        raise YamlAdapterError("parse_error", _PARSE_ERROR_DETAIL)

    identity = id(value)
    if identity in active:
        raise YamlAdapterError(
            "unsupported_syntax", "Cyclic YAML aliases are unsupported"
        )
    active.add(identity)
    try:
        if isinstance(value, list):
            return [_normalize_value(item, depth + 1, active, state) for item in value]
        output: dict[str, YamlStringValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise YamlAdapterError(
                    "unsupported_syntax", _UNSUPPORTED_KEY_DETAIL
                )
            if not key:
                raise YamlAdapterError(
                    "unsupported_syntax",
                    _UNSUPPORTED_EMPTY_KEY_DETAIL,
                )
            output[key] = _normalize_value(item, depth + 1, active, state)
        return output
    finally:
        active.remove(identity)
