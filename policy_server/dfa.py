from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


@dataclass(slots=True)
class _Node:
    nxt: Dict[int, int]
    fail: int
    out: bool


def build_char_mapping(patterns: Iterable[str]) -> Dict[str, int]:
    """
    Build a compact alphabet mapping for DFA scanning.

    - Normalization: caller should already upper-case patterns if desired.
    - Symbol 0 is reserved for OTHER (any char not in the mapping).
    - Characters that appear in patterns get stable IDs in [1..K].
    """
    chars = set()
    for p in patterns:
        for ch in p:
            chars.add(ch)
    # Deterministic ordering for reproducible artifacts.
    ordered = sorted(chars)
    m: dict[str, int] = {}
    sym = 1
    for ch in ordered:
        m[ch] = sym
        sym += 1
    return m


def _sym_seq(s: str, *, char_to_sym: Dict[str, int]) -> List[int]:
    return [char_to_sym.get(ch, 0) for ch in s]


def build_aho_corasick_dfa(patterns: Iterable[str], *, char_to_sym: Dict[str, int]) -> Tuple[List[List[int]], List[bool]]:
    """
    Build a full DFA transition table for multi-pattern substring matching (Aho-Corasick).

    Returns:
      trans[state][sym] -> next_state
      out[state] -> whether any pattern matches ending at this state
    """
    pats = [p for p in patterns if p]
    alpha = 1 + len(char_to_sym)  # include OTHER=0

    nodes: list[_Node] = [_Node(nxt={}, fail=0, out=False)]

    # Build trie
    for p in pats:
        cur = 0
        for sym in _sym_seq(p, char_to_sym=char_to_sym):
            if sym not in nodes[cur].nxt:
                nodes[cur].nxt[sym] = len(nodes)
                nodes.append(_Node(nxt={}, fail=0, out=False))
            cur = nodes[cur].nxt[sym]
        nodes[cur].out = True

    # BFS failure links
    q: list[int] = []
    for sym, nxt_state in nodes[0].nxt.items():
        nodes[nxt_state].fail = 0
        q.append(nxt_state)

    while q:
        r = q.pop(0)
        for sym, s in nodes[r].nxt.items():
            q.append(s)
            f = nodes[r].fail
            while f != 0 and sym not in nodes[f].nxt:
                f = nodes[f].fail
            nodes[s].fail = nodes[f].nxt.get(sym, 0)
            nodes[s].out = nodes[s].out or nodes[nodes[s].fail].out

    # Build full DFA table
    trans: list[list[int]] = [[0] * alpha for _ in range(len(nodes))]
    out: list[bool] = [n.out for n in nodes]

    for st in range(len(nodes)):
        for sym in range(alpha):
            if sym in nodes[st].nxt:
                ns = nodes[st].nxt[sym]
            else:
                f = st
                while f != 0 and sym not in nodes[f].nxt:
                    f = nodes[f].fail
                ns = nodes[f].nxt.get(sym, 0)
            trans[st][sym] = ns

    # Propagate outputs through transition targets (so caller can test after consuming a char).
    # Note: Aho-Corasick's out[] already includes fail-propagation; this is just convenience.
    out2: list[bool] = [False] * len(out)
    for st in range(len(out)):
        out2[st] = out[st]
    return trans, out2

