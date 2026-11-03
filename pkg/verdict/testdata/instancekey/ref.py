#!/usr/bin/env python3
"""Throwaway reference producer for the instance_key goldens.

Reads <type>/plan.json and <type>/schema.json in every subdirectory and writes
<type>/canonical.json and <type>/expected.json. FORMAT.md is the normative
text; this script is one implementation of it, kept only until the Go
canonicalizer reproduces the goldens. Standard library only:

    python3 -I ref.py            regenerate every golden
    python3 -I ref.py --check    exit 1 if any committed golden differs
"""

import copy
import hashlib
import hmac
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path

GOLDEN_FORMAT = "compliancetf.instancekey.golden/v1"
# Fixed, publicly known test secret. Never a real run secret: ctfkit and the
# provider refuse it outside test builds (FORMAT.md, "Test secret").
TEST_SECRET = b"INSECURE-TEST-SECRET-instancekey"
assert len(TEST_SECRET) == 32

INFO_LEAF = b"compliancetf.verdict/v1 leaf"
INFO_CHECK = b"compliancetf.verdict/v1 key-check"
KEY_DOMAIN = b"compliancetf.instance_key/v1\x00"
PREC = 512
MAX_EXP = 1000
# Longest accepted number text; covers every value inside MAX_EXP in Text('f', -1).
MAX_NUM_LEN = 1200
# The hashicorp/aws release the schemas and plans were taken from.
PROVIDER_VERSION = "hashicorp/aws 6.65.0"


class FormatError(Exception):
    """A value the format refuses; the instance gets no key (fail closed)."""


class Num:
    """A JSON number kept as its raw decimal text (never a float)."""

    def __init__(self, text):
        self.text = text


# ---------------------------------------------------------------- JSON input


def _no_dup(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise FormatError(f"duplicate object key {k!r}")
        out[k] = v
    return out


def _reject_constant(name):
    raise FormatError(f"non-JSON number {name}")


def _check_text(obj):
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError as e:
            raise FormatError("string is not valid UTF-8 (lone surrogate)") from e
    elif isinstance(obj, list):
        for v in obj:
            _check_text(v)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_text(k)
            _check_text(v)


def load_json(path):
    try:
        raw = path.read_bytes().decode("utf-8")  # strict
    except UnicodeDecodeError as e:
        raise FormatError("file is not valid UTF-8") from e
    obj = json.loads(
        raw,
        object_pairs_hook=_no_dup,
        parse_float=Num,
        parse_int=Num,
        parse_constant=_reject_constant,
    )
    _check_text(obj)
    return obj


# ------------------------------------------------------------------ numbers


def _round512(x):
    """Round a positive Fraction to a 512-bit mantissa, half to even.

    Returns (m, e) with x ~= m * 2**e and 2**511 <= m < 2**512.
    """
    e = x.numerator.bit_length() - x.denominator.bit_length() - PREC
    while True:
        scaled = x / (Fraction(2) ** e)
        if scaled >= 2**PREC:
            e += 1
        elif scaled < 2 ** (PREC - 1):
            e -= 1
        else:
            break
    q, r = divmod(scaled.numerator, scaled.denominator)
    twice = 2 * r
    if twice > scaled.denominator or (twice == scaled.denominator and q & 1):
        q += 1
    if q == 2**PREC:
        q //= 2
        e += 1
    return q, e


def _decimal_of(mant, exp2):
    """Exact decimal digits of mant * 2**exp2 as (digits, dp), zeros trimmed."""
    if exp2 >= 0:
        digits = str(mant << exp2)
        dp = len(digits)
    else:
        digits = str(mant * 5 ** (-exp2))
        dp = len(digits) + exp2
    stripped = digits.rstrip("0")
    if not stripped:
        return "", 0
    lead = len(digits) - len(digits.lstrip("0"))
    return stripped.lstrip("0"), dp - lead


def _round_up(d, dp, n):
    digits = list(d[:n])
    i = n - 1
    while i >= 0 and digits[i] == "9":
        i -= 1
    if i < 0:
        return "1", dp + 1
    digits[i] = chr(ord(digits[i]) + 1)
    return "".join(digits[: i + 1]), dp


def _round_down(d, dp, n):
    out = d[:n].rstrip("0")
    return (out, dp) if out else ("", 0)


def _round_nearest(d, dp, n):
    if n >= len(d):
        return d, dp
    if d[n] == "5" and n + 1 == len(d):
        up = n > 0 and (int(d[n - 1]) & 1) == 1
    else:
        up = d[n] >= "5"
    return _round_up(d, dp, n) if up else _round_down(d, dp, n)


def _shortest(m, e):
    """Port of math/big roundShortest for a 512-bit float m * 2**e."""
    d, dp = _decimal_of(m, e)
    mant, exp = 2 * m, e - 1  # lsb == 1/2 ulp
    lo, _ = _decimal_of(mant - 1, exp)
    up, _ = _decimal_of(mant + 1, exp)
    inclusive = (mant & 2) == 0

    # math/big indexes the digit strings of x, lower and upper by position,
    # without aligning their decimal points; mirror that exactly.
    def at(s, i):
        return s[i] if i < len(s) else "0"

    for i, mch in enumerate(d):
        lch = at(lo, i)
        uch = at(up, i)
        okdown = lch != mch or (inclusive and i + 1 == len(lo))
        okup = mch != uch and (
            inclusive or ord(mch) + 1 < ord(uch) or i + 1 < len(up) or (i >= len(up) and mch < "9")
        )
        if okdown and okup:
            return _round_nearest(d, dp, i + 1)
        if okdown:
            return _round_down(d, dp, i + 1)
        if okup:
            return _round_up(d, dp, i + 1)
    return d, dp


def _fmt_g(d, dp):
    exp = dp - 1
    if exp < -4 or exp >= 6:
        out = d[0]
        if len(d) > 1:
            out += "." + d[1:]
        sign = "-" if exp < 0 else "+"
        return f"{out}e{sign}{abs(exp):02d}"
    if dp > 0:
        whole = d[:dp].ljust(dp, "0")
        frac = d[dp:]
    else:
        whole = "0"
        frac = "0" * (-dp) + d
    return whole + ("." + frac if frac else "")


NUMBER = re.compile(r"-?((?:0|[1-9][0-9]*)(?:\.[0-9]+)?)(?:[eE][+-]?[0-9]+)?", re.ASCII)


def number_text(raw):
    if len(raw) > MAX_NUM_LEN:
        raise FormatError(f"number text longer than {MAX_NUM_LEN} bytes")
    m = NUMBER.fullmatch(raw)
    if not m:
        raise FormatError(f"bad number {raw!r}")
    if not m.group(1).strip("0."):
        return "0"  # zero, whatever its sign or exponent
    try:
        dec = Decimal(raw)
    except InvalidOperation as e:
        raise FormatError(f"bad number {raw!r}") from e
    if not dec.is_finite():
        raise FormatError(f"bad number {raw!r}")
    if dec.is_zero():
        return "0"  # -0 and 0 both
    if abs(dec.adjusted()) > MAX_EXP:
        raise FormatError(f"number exponent out of range: {raw}")
    x = Fraction(dec)
    neg = x < 0
    m, e = _round512(abs(x))
    if e >= 0 or m % (1 << -e) == 0:
        text = str(m << e if e >= 0 else m >> -e)
    else:
        text = _fmt_g(*_shortest(m, e))
    return ("-" if neg else "") + text


# ----------------------------------------------------------- schema typing
#
# A "type" below is one of:
#   ("prim", "string"|"number"|"bool")  ("dynamic",)
#   ("list", T) ("set", T) ("map", T) ("tuple", [T...])
#   ("object", {name: T})               ("block", attrs, blocks) with
#   blocks = {name: (nesting_mode, ("block", ...))}


def cty_type(t):
    if t == "dynamic":
        return ("dynamic",)
    if t in ("string", "number", "bool"):
        return ("prim", t)
    kind = t[0]
    if kind in ("list", "set", "map"):
        return (kind, cty_type(t[1]))
    if kind == "object":
        return ("object", {k: cty_type(v) for k, v in t[1].items()})
    if kind == "tuple":
        return ("tuple", [cty_type(v) for v in t[1]])
    raise FormatError(f"unknown schema type {t!r}")


def nested_type(nt):
    elem = ("object", {k: attr_type(v) for k, v in nt["attributes"].items()})
    mode = nt.get("nesting_mode", "single")
    if mode in ("single", "group"):
        return elem
    if mode in ("list", "set", "map"):
        return (mode, elem)
    raise FormatError(f"unknown nesting_mode {mode!r}")


def attr_type(a):
    if "nested_type" in a:
        return nested_type(a["nested_type"])
    return cty_type(a["type"])


def block_type(b):
    attrs = {k: attr_type(v) for k, v in b.get("attributes", {}).items()}
    blocks = {}
    for k, bt in b.get("block_types", {}).items():
        inner = block_type(bt["block"])
        mode = bt["nesting_mode"]
        if mode in ("single", "group"):
            blocks[k] = inner
        elif mode in ("list", "set", "map"):
            blocks[k] = (mode, inner)
        else:
            raise FormatError(f"unknown nesting_mode {mode!r}")
    return ("object", {**attrs, **blocks})


def has_dynamic(t):
    k = t[0]
    if k == "dynamic":
        return True
    if k in ("list", "set", "map"):
        return has_dynamic(t[1])
    if k == "tuple":
        return any(has_dynamic(x) for x in t[1])
    if k == "object":
        return False  # dynamic attributes inside are omitted one by one
    return False


def child_type(t, step):
    k = t[0]
    if k == "object":
        if step not in t[1]:
            raise FormatError(f"attribute {step!r} not in schema")
        return t[1][step]
    if k in ("list", "set", "map"):
        return t[1]
    if k == "tuple":
        if not step.isdigit() or int(step) >= len(t[1]):
            raise FormatError(f"tuple index {step!r} out of range")
        return t[1][int(step)]
    raise FormatError(f"cannot step into {k} with {step!r}")


# ------------------------------------------------------------- unknown paths


def _any_true(u):
    if u is True:
        return True
    if u is None or u is False:
        return False
    if isinstance(u, list):
        return any(_any_true(x) for x in u)
    if isinstance(u, dict):
        return any(_any_true(x) for x in u.values())
    raise FormatError(f"after_unknown holds a {type(u).__name__}")


def check_unknown(u, t, path):
    """Validate every after_unknown marker against the schema (no short-circuit)."""
    if u is None or u is False or u is True:
        return
    k = t[0]
    if k == "dynamic" or has_dynamic(t):
        return  # excluded; its markers are dropped
    if k in ("list", "set", "tuple") and isinstance(u, list):
        for i, v in enumerate(u):
            check_unknown(v, t[1] if k != "tuple" else child_type(t, str(i)), path + [str(i)])
    elif k == "object" and isinstance(u, dict):
        for key, v in u.items():
            check_unknown(v, child_type(t, key), path + [key])
    elif k == "map" and isinstance(u, dict):
        for key, v in u.items():
            check_unknown(v, t[1], path + [key])
    else:
        raise FormatError(f"after_unknown shape does not match schema at {path}")


def collect_unknown(u, t, path, out):
    """Schema-driven walk of after_unknown; appends normalized paths."""
    if u is True and not path:
        raise FormatError("whole planned value unknown")
    if u is None or u is False:
        return
    if t[0] == "dynamic" or has_dynamic(t):
        return  # dynamic attributes are excluded; their paths are dropped
    if not (u is True or isinstance(u, (list, dict))):
        raise FormatError(f"after_unknown holds a {type(u).__name__} at {path}")
    if t[0] == "set":
        if _any_true(u):
            out.append(path)  # any unknown inside masks the whole set
        return
    if u is True:
        out.append(path)
        return
    if t[0] == "object" and isinstance(u, dict):
        for k, v in u.items():
            collect_unknown(v, child_type(t, k), path + [k], out)
    elif t[0] in ("list", "tuple") and isinstance(u, list):
        for i, v in enumerate(u):
            collect_unknown(v, child_type(t, str(i)), path + [str(i)], out)
    elif t[0] == "map" and isinstance(u, dict):
        for k, v in u.items():
            collect_unknown(v, t[1], path + [k], out)
    else:
        raise FormatError(f"after_unknown shape does not match schema at {path}")


def normalize_paths(paths):
    uniq = {jcs(p): p for p in paths}
    keep = []
    for key in sorted(uniq, key=lambda s: s.encode("utf-8")):
        p = uniq[key]
        if any(len(q) < len(p) and p[: len(q)] == q for q in uniq.values()):
            continue
        keep.append(p)
    return keep


INDEX = re.compile(r"(0|[1-9][0-9]{0,8})\Z", re.ASCII)  # at most 9 digits, never wraps


def validate_path(p, root_type):
    """Check a whole path against the schema alone, before any value is read."""
    if not isinstance(p, list) or not p or not all(isinstance(x, str) for x in p):
        raise FormatError(f"invalid unknown path {p!r}")
    if p[0] not in root_type[1]:
        raise FormatError(f"unknown path {p!r} does not start at a schema attribute")
    t = root_type
    for step in p:
        kind = t[0]
        if kind == "object":
            t = child_type(t, step)
        elif kind == "map":
            t = t[1]
        elif kind in ("list", "tuple"):
            if not INDEX.match(step):
                raise FormatError(f"invalid list index {step!r} in {p!r}")
            if kind == "tuple" and int(step) >= len(t[1]):
                raise FormatError(f"tuple index {step} out of range in {p!r}")
            t = child_type(t, step)
        else:
            raise FormatError(f"path {p!r} steps into a {kind}")


def apply_paths(after, paths, root_type):
    """Provider-side masking: remove attributes and map keys, null list slots.

    Each step is read by the schema node it lands on. A path that does not
    resolve in the value is a no-op; one the schema cannot read is an error.
    """
    for p in paths:
        validate_path(p, root_type)
    after = copy.deepcopy(after)
    for p in paths:
        node, t = after, root_type
        for i, step in enumerate(p):
            last = i == len(p) - 1
            kind = t[0]
            if kind in ("object", "map"):
                t = child_type(t, step) if kind == "object" else t[1]
                if not isinstance(node, dict) or step not in node:
                    break
                if last:
                    del node[step]
                else:
                    node = node[step]
            elif kind in ("list", "tuple"):
                t = child_type(t, step)
                idx = int(step)
                if not isinstance(node, list) or idx >= len(node):
                    break  # never extends a list
                if last:
                    node[idx] = None
                else:
                    node = node[idx]
    return after


# ------------------------------------------------------------- canonical tree
#
# Canonical nodes: ("leaf", tag, text) | ("null",) | ("list", [n]) |
# ("set", [n]) | ("obj", {k: n}). Objects and maps share "obj".

OMIT = object()


def canon(v, t, path):
    if t[0] == "dynamic" or has_dynamic(t):
        return OMIT
    if v is None:
        return OMIT
    k = t[0]
    if k == "prim":
        p = t[1]
        if p == "string":
            if not isinstance(v, str):
                raise FormatError(f"{path}: expected string")
            return ("leaf", "s", v)
        if p == "number":
            if not isinstance(v, Num):
                raise FormatError(f"{path}: expected number")
            return ("leaf", "n", number_text(v.text))
        if not isinstance(v, bool):
            raise FormatError(f"{path}: expected bool")
        return ("leaf", "b", "true" if v else "false")
    if k in ("list", "set", "tuple"):
        if not isinstance(v, list):
            raise FormatError(f"{path}: expected array")
        if k == "tuple" and len(v) != len(t[1]):
            raise FormatError(f"{path}: tuple has {len(v)} elements, schema {len(t[1])}")
        items = []
        for i, x in enumerate(v):
            ct = child_type(t, str(i))
            n = canon(x, ct, path + [str(i)])
            items.append(("null",) if n is OMIT else n)
        return ("set" if k == "set" else "list", items)
    if k == "map":
        if not isinstance(v, dict):
            raise FormatError(f"{path}: expected object")
        out = {}
        for mk, x in v.items():
            n = canon(x, t[1], path + [mk])
            if n is not OMIT:
                out[mk] = n
        return ("obj", out)
    if k == "object":
        if not isinstance(v, dict):
            raise FormatError(f"{path}: expected object")
        out = {}
        for ak, x in v.items():
            n = canon(x, child_type(t, ak), path + [ak])
            if n is not OMIT:
                out[ak] = n
        return ("obj", out)
    raise FormatError(f"{path}: unsupported type {k}")


# --------------------------------------------------------------- hashing / JCS


def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v):
    """RFC 8785 for the value kinds the hashed tree holds: str, None, list, dict."""
    if v is None:
        return "null"
    if isinstance(v, str):
        return _jcs_str(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_str(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v))


def hkdf(ikm, info):
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def hashed(node, k_leaf):
    """H(tree) plus the display tree in the same (hashed) set order."""
    kind = node[0]
    if kind == "leaf":
        msg = node[1].encode() + b"\x00" + node[2].encode("utf-8")
        return hmac.new(k_leaf, msg, hashlib.sha256).hexdigest(), f"{node[1]}:{node[2]}"
    if kind == "null":
        return None, None
    if kind == "list":
        pairs = [hashed(x, k_leaf) for x in node[1]]
        return [p[0] for p in pairs], [p[1] for p in pairs]
    if kind == "set":
        pairs = [hashed(x, k_leaf) for x in node[1]]
        pairs.sort(key=lambda p: jcs(p[0]).encode("utf-8"))
        return [p[0] for p in pairs], [p[1] for p in pairs]
    if kind == "obj":
        h, d = {}, {}
        for key, x in node[1].items():
            h[key], d[key] = hashed(x, k_leaf)
        return h, d
    raise TypeError(kind)


# ---------------------------------------------------------------- key forms


def prior_identity(change, ident_type):
    before = change.get("before")
    if before is not None and not isinstance(before, dict):
        raise FormatError("before is not an object")
    bi = change.get("before_identity")
    if bi is not None and not isinstance(bi, dict):
        raise FormatError("before_identity is not an object")
    if isinstance(bi, dict) and ident_type is not None:
        tree = canon(bi, ident_type, ["<before_identity>"])
        if tree is not OMIT and _has_leaf(tree):
            return "identity", tree
    pid = (before or {}).get("id")
    if not isinstance(pid, str) or pid == "":
        raise FormatError("no usable prior identity and no non-empty prior id")
    return "id", ("obj", {"id": ("leaf", "s", pid)})


def _has_leaf(n):
    if n[0] == "leaf":
        return True
    if n[0] in ("list", "set"):
        return any(_has_leaf(x) for x in n[1])
    if n[0] == "obj":
        return any(_has_leaf(x) for x in n[1].values())
    return False


def one_key(rtype, form, change, res_type, ident_type, k_leaf, action_reason=None):
    if form == "delete":
        after_tree, unknown = None, []
    else:
        raw = []
        check_unknown(change.get("after_unknown"), res_type, [])
        collect_unknown(change.get("after_unknown"), res_type, [], raw)
        unknown = normalize_paths(raw)
        after = change.get("after")
        if not isinstance(after, dict):
            raise FormatError("planned after is not an object")
        canon(after, res_type, [])  # validate every value first; masking must not hide a bad one
        masked = apply_paths(after, unknown, res_type)
        after_tree = canon(masked, res_type, [])
    if form == "create":
        kind, prior_tree = "none", None
    else:
        # the destroy half of a tainted replace always keys kind id: OpenTofu emits a
        # usable before_identity there, the provider keys that RPC by id
        if form == "delete" and action_reason == "replace_because_tainted":
            ident_type = None
        kind, prior_tree = prior_identity(change, ident_type)
    ah, ad = hashed(after_tree, k_leaf) if after_tree is not None else (None, None)
    ph, pd = hashed(prior_tree, k_leaf) if prior_tree is not None else (None, None)
    ajcs, pjcs = jcs(ah), jcs(ph)
    pre = (
        KEY_DOMAIN
        + rtype.encode()
        + b"\x00"
        + form.encode()
        + b"\x00"
        + ajcs.encode("utf-8")
        + b"\x00"
        + pjcs.encode("utf-8")
    )
    key = "sha256:" + hashlib.sha256(pre).hexdigest()
    field = "delete_key" if form == "delete" else "instance_key"
    expected = {
        "field": field,
        "form": form,
        "key": key,
        "prior_identity_kind": kind,
        "unknown_paths": unknown,
    }
    canonical = {
        "after": ad,
        "after_hashed_jcs": ajcs,
        "field": field,
        "form": form,
        "prior_identity": pd,
        "prior_identity_hashed_jcs": pjcs,
        "prior_identity_kind": kind,
    }
    return expected, canonical


FORMS = {
    ("create",): ["create"],
    ("update",): ["update"],
    ("delete",): ["delete"],
    ("delete", "create"): ["delete", "create"],
    ("create", "delete"): ["create", "delete"],
}


def build(dirpath):
    k_leaf = hkdf(TEST_SECRET, INFO_LEAF)
    k_check = hkdf(TEST_SECRET, INFO_CHECK)
    try:
        plan = load_json(dirpath / "plan.json")
        schema = load_json(dirpath / "schema.json")
    except FormatError as err:
        # the whole file is refused; no instance in it gets a key
        out = {"error": str(err), "format": GOLDEN_FORMAT}
        return out, out
    exp_entries, can_entries = [], []
    for rc in plan["resource_changes"]:
        if rc.get("mode") != "managed":
            continue
        actions = tuple(rc["change"]["actions"])
        if actions in (("no-op",), ("read",)) and not rc.get("deposed"):
            continue
        head = {"actions": list(actions), "address": rc["address"]}
        if rc.get("deposed"):
            head["deposed"] = rc["deposed"]
        if rc.get("action_reason"):
            head["action_reason"] = rc["action_reason"]
        try:
            pschema = schema["provider_schemas"].get(rc["provider_name"])
            if pschema is None or rc["type"] not in pschema.get("resource_schemas", {}):
                raise FormatError("schema has no entry for this provider and type")
            res_type = block_type(pschema["resource_schemas"][rc["type"]]["block"])
            ident = pschema.get("resource_identity_schemas", {}).get(rc["type"])
            ident_type = (
                ("object", {k: attr_type(v) for k, v in ident["attributes"].items()})
                if ident
                else None
            )
            if actions not in FORMS:
                raise FormatError(f"unsupported actions {list(actions)}")
            if rc.get("deposed") and actions != ("delete",):
                raise FormatError("a deposed object takes only a delete entry")
            keys, cans = [], []
            for form in FORMS[actions]:
                e, c = one_key(
                    rc["type"], form, rc["change"], res_type, ident_type, k_leaf, rc.get("action_reason")
                )
                keys.append(e)
                cans.append(c)
        except FormatError as err:
            exp_entries.append({**head, "error": str(err)})
            can_entries.append({**head, "error": str(err)})
            continue
        exp_entries.append({**head, "keys": keys})
        can_entries.append({**head, "keys": cans})
    meta = {
        "format": GOLDEN_FORMAT,
        "provider_version": PROVIDER_VERSION,
        "terraform_version": plan.get("terraform_version"),
    }
    expected = {
        **meta,
        "entries": exp_entries,
        "k_leaf_hex": k_leaf.hex(),
        "key_check": hmac.new(k_check, INFO_CHECK, hashlib.sha256).hexdigest(),
        "test_secret_hex": TEST_SECRET.hex(),
    }
    canonical = {**meta, "entries": can_entries}
    return canonical, expected


def dump(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


FAKE_ACCOUNTS = {"111111111111", "222222222222"}


ARN_ACCOUNT = re.compile(r"arn:aws[a-z-]*:[^:]*:[^:]*:([0-9]{12}):")
KEY_ID = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")


def _num_or_none(text):
    try:
        return Decimal(text)
    except ArithmeticError:
        return None  # out of Decimal's range; cannot be a 12-digit account id


class Pairs(list):
    """Every (key, value) pair of one JSON object, duplicates included."""


def _strings(v, key=None):
    if isinstance(v, str):
        yield key, v
    elif isinstance(v, Decimal):
        # only a 12-digit integer can be an account id; never expand anything larger
        if 10**11 <= v < 10**12 and v == v.to_integral_value():
            yield key, str(int(v))  # 123456789012.0 and 1.23456789012e11 read as integers
    elif isinstance(v, Pairs):
        for k, x in v:
            yield None, k
            yield from _strings(x, k)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x, key)
    elif isinstance(v, dict):
        for k, x in v.items():
            yield None, k
            yield from _strings(x, k)


def hygiene(d):
    """Committed inputs carry only fake bobthecorp data (AGENTS.md, fixture provenance)."""
    problems = []
    for name in ("plan.json", "schema.json"):
        if not (d / name).is_file():
            problems.append(f"{d.name}/{name}: missing")
            continue
        try:
            # keep every pair, so a value hidden behind a duplicate key is still seen
            doc = json.loads(
                (d / name).read_text(encoding="utf-8", errors="replace"),
                object_pairs_hook=Pairs,
                parse_float=_num_or_none,
                parse_int=_num_or_none,
            )
        except ValueError:
            continue
        for key, text in _strings(doc):
            accounts = set(ARN_ACCOUNT.findall(text))
            if key and ("account" in key.lower() or "owner" in key.lower()) and re.fullmatch(r"[0-9]{12}", text):
                accounts.add(text)
            for acct in accounts - FAKE_ACCOUNTS:
                problems.append(f"{d.name}/{name}: account id {acct} is not a fake one")
            if KEY_ID.search(text):
                problems.append(f"{d.name}/{name}: access key id")
    return problems


def selftest():
    """Assert-based checks of rules the goldens cannot pin (provider-side paths)."""
    T = ("object", {"lst": ("list", ("prim", "string")), "st": ("set", ("prim", "string")),
                    "tp": ("tuple", [("prim", "string")]), "m": ("map", ("prim", "string"))})
    for bad in (["lst", "01"], ["lst", "-1"], ["lst", "\u0661"], ["lst", "1234567890"],
                ["st", "0"], ["tp", "1"], [], ["nope"]):
        for value in ({}, {"lst": ["a", "b"], "st": ["a"], "tp": ["a"]}):
            try:
                apply_paths(value, [bad], T)
            except FormatError:
                continue
            raise AssertionError(f"path {bad!r} accepted on {value!r}")
    assert apply_paths({"lst": ["a"]}, [["lst", "5"]], T) == {"lst": ["a"]}
    assert apply_paths({"lst": None}, [["lst", "0"]], T) == {"lst": None}
    assert apply_paths({"m": {"01": "x"}}, [["m", "01"]], T) == {"m": {}}
    assert number_text("0e" + "9" * 100) == "0" and number_text("-0.0") == "0"
    for bad in ("01", "1.", ".5", "+1", "NaN", "1e"):
        try:
            number_text(bad)
        except FormatError:
            continue
        raise AssertionError(f"number {bad!r} accepted")


def main(argv):
    selftest()
    check = "--check" in argv
    root = Path(__file__).resolve().parent
    names = ("plan.json", "schema.json", "expected.json", "canonical.json")
    dirs = sorted(p for p in root.iterdir() if p.is_dir() and any((p / n).exists() for n in names))
    bad = 0
    for d in dirs:
        problems = hygiene(d)
        for problem in problems:
            print(problem)
            bad += 1
        if not ((d / "plan.json").is_file() and (d / "schema.json").is_file()):
            continue
        canonical, expected = build(d)
        for name, obj in (("canonical.json", canonical), ("expected.json", expected)):
            text = dump(obj)
            target = d / name
            if check:
                if not target.is_file() or target.read_text(encoding="utf-8") != text:
                    print(f"differs: {d.name}/{name}")
                    bad += 1
            else:
                target.write_text(text, encoding="utf-8", newline="\n")
    print(f"{len(dirs)} directories, {'%d problems' % bad if check else 'written'}")
    return 1 if bad else 0  # also when only writing: a hygiene problem fails the run


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
