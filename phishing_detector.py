"""
Phishing URL Detector  -  FLAT case study (Regular Expressions + DFA)
=====================================================================

The program reads a URL and checks it against 6 rules.  Every rule is
described in two ways:

  1. a Regular Expression  (the "pattern" view)
  2. a DFA                 (the "machine" view, reads the text one
                            character at a time)

For every URL the program runs BOTH and checks that they agree, which is
the practical proof that "regular expression == finite automaton".

How the DFAs are made
  * Keyword rules and the TLD rule: written as an NFA, converted to a DFA
    with the SUBSET CONSTRUCTION, then MINIMIZED (equivalent states merged).
  * IP address, '@', hyphen-count and dot-count rules: small DFAs built
    by hand (they are easy to draw).

Rules
  R1  suspicious keyword   login | verify | secure | update   (whole URL)
  R2  IP address as host   e.g. 192.168.4.5                    (host)
  R3  '@' symbol in URL    e.g. google.com@evil.top            (whole URL)
  R4  3 or more hyphens    e.g. a-b-c-d.com                    (host)
  R5  4 or more dots       e.g. a.b.c.d.example.com            (host)
  R6  suspicious ending    .xyz | .tk | .top                   (host)

Decision: number of rules triggered (score)
  score 0            -> SAFE
  score 1            -> CAUTION
  score >= threshold -> PHISHING   (default threshold = 2)

Run it
  python phishing_detector.py                     interactive mode
  python phishing_detector.py URL [URL ...]       check given URLs
  python phishing_detector.py --test test_urls.csv   evaluate on a CSV
  python phishing_detector.py --dfa-tables        print DFA specifications
  python phishing_detector.py --dot diagrams      write DFA diagrams
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import time

OTHER = "other"          # every character that is not in a DFA's alphabet
DEAD = "qD"              # dead (trap) state name


# ---------------------------------------------------------------------
#  1.  The DFA class
# ---------------------------------------------------------------------
class DFA:
    """M = (Q, Sigma, delta, q0, F)   -   a complete deterministic automaton."""

    def __init__(self, name, regex_text, states, alphabet, delta, start,
                 accepts, classify=None, accept_examples=(), reject_examples=()):
        self.name = name
        self.regex_text = regex_text          # shown in the specification
        self.states = states                  # list of state names
        self.alphabet = alphabet              # list of symbols
        self.delta = delta                    # dict (state, symbol) -> state
        self.start = start
        self.accepts = set(accepts)
        self._classify = classify             # optional char -> symbol
        self.accept_examples = list(accept_examples)
        self.reject_examples = list(reject_examples)
        self.built_note = "designed by hand"

    def classify(self, ch):
        if self._classify:
            return self._classify(ch)
        return ch if ch in self.alphabet else OTHER

    def run(self, text):
        """Read text one character at a time.
        Returns (accepted?, steps) where steps = [(index, char, from, to)]
        for every move in which the state CHANGED (keeps the trace short)."""
        state, steps = self.start, []
        for i, ch in enumerate(text):
            nxt = self.delta[(state, self.classify(ch))]
            if nxt != state:
                steps.append((i, ch, state, nxt))
            state = nxt
        return state in self.accepts, steps, state


# ---------------------------------------------------------------------
#  2.  NFA  ->  DFA  (subset construction)
# ---------------------------------------------------------------------
def build_nfa(patterns, sticky):
    """NFA for   Sigma* (p1 | p2 | ...)   [ followed by Sigma* if sticky ].
    State 0 loops on every symbol, each pattern is a chain of states."""
    alphabet = sorted(set("".join(patterns))) + [OTHER]
    delta, accepts, nxt = {}, set(), 1

    def add(s, a, t):
        delta.setdefault((s, a), set()).add(t)

    for a in alphabet:
        add(0, a, 0)
    for p in patterns:
        cur = 0
        for ch in p:
            add(cur, ch, nxt)
            cur, nxt = nxt, nxt + 1
        accepts.add(cur)
        if sticky:                       # 'contains' : once found, stay accepted
            for a in alphabet:
                add(cur, a, cur)
    return alphabet, delta, accepts


def subset_construction(alphabet, nfa_delta, nfa_accepts):
    """Standard textbook subset construction (start state = {0})."""
    start = frozenset([0])
    names, order, trans = {start: "q0"}, [start], {}
    i = 0
    while i < len(order):
        S = order[i]
        i += 1
        for a in alphabet:
            T = frozenset(t for s in S for t in nfa_delta.get((s, a), ()))
            if T not in names:
                names[T] = "q%d" % len(names)
                order.append(T)
            trans[(names[S], a)] = names[T]
    states = [names[S] for S in order]
    accepts = [names[S] for S in order if S & nfa_accepts]
    return states, trans, accepts


def minimize(states, alphabet, trans, accepts):
    """DFA minimization by partition refinement: merge states that behave
    identically.  Returns (states, trans, accepts) with states renamed q0.."""
    group = {s: int(s in accepts) for s in states}
    while True:
        sig = {s: (group[s], tuple(group[trans[(s, a)]] for a in alphabet)) for s in states}
        ids = {}
        new = {s: ids.setdefault(sig[s], len(ids)) for s in states}
        done = len(set(new.values())) == len(set(group.values()))
        group = new
        if done:
            break
    # rename groups q0, q1, ... in the order a breadth-first walk meets them
    name, order, queue = {group["q0"]: "q0"}, ["q0"], ["q0"]
    rep = {}
    for s in states:
        rep.setdefault(group[s], s)
    while queue:
        s = queue.pop(0)
        for a in alphabet:
            g = group[trans[(s, a)]]
            if g not in name:
                name[g] = "q%d" % len(name)
                order.append(name[g])
                queue.append(rep[g])
    new_trans = {}
    for g, nm in name.items():
        for a in alphabet:
            new_trans[(nm, a)] = name[group[trans[(rep[g], a)]]]
    new_accepts = [name[g] for g in name if rep[g] in accepts]
    return order, new_trans, new_accepts


def dfa_from_patterns(name, regex_text, patterns, sticky, accept_ex, reject_ex):
    alphabet, nd, na = build_nfa(patterns, sticky)
    states, trans, accepts = subset_construction(alphabet, nd, na)
    before = len(states)
    states, trans, accepts = minimize(states, alphabet, trans, accepts)
    d = DFA(name, regex_text, states, alphabet, trans, "q0", accepts,
            accept_examples=accept_ex, reject_examples=reject_ex)
    d.built_note = ("built from an NFA by subset construction (%d states), "
                    "then minimized (%d states)" % (before, len(states)))
    return d


# ---------------------------------------------------------------------
#  3.  DFAs built by hand
# ---------------------------------------------------------------------
def counting_dfa(name, regex_text, symbol, n, accept_ex, reject_ex):
    """Accepts any string that has at least n copies of `symbol`.
    States q0..qn  (qn = 'seen n copies', accepting, absorbing)."""
    states = ["q%d" % i for i in range(n + 1)]
    alphabet = [symbol, OTHER]
    delta = {}
    for i in range(n):
        delta[(states[i], symbol)] = states[i + 1]
        delta[(states[i], OTHER)] = states[i]
    delta[(states[n], symbol)] = states[n]
    delta[(states[n], OTHER)] = states[n]
    return DFA(name, regex_text, states, alphabet, delta, "q0", [states[n]],
               accept_examples=accept_ex, reject_examples=reject_ex)


def ip_dfa():
    """Accepts  digits . digits . digits . digits   (and nothing else)."""
    states = ["q%d" % i for i in range(8)] + [DEAD]
    alphabet = ["D", ".", OTHER]              # D = any digit 0-9
    delta = {}
    for s in states:                           # default: everything -> dead
        for a in alphabet:
            delta[(s, a)] = DEAD
    chain = [("q0", "D", "q1"), ("q1", "D", "q1"), ("q1", ".", "q2"),
             ("q2", "D", "q3"), ("q3", "D", "q3"), ("q3", ".", "q4"),
             ("q4", "D", "q5"), ("q5", "D", "q5"), ("q5", ".", "q6"),
             ("q6", "D", "q7"), ("q7", "D", "q7")]
    for s, a, t in chain:
        delta[(s, a)] = t

    def classify(ch):
        return "D" if ch.isdigit() and ch.isascii() else ("." if ch == "." else OTHER)

    return DFA("IP address host", r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", states,
               alphabet, delta, "q0", ["q7"], classify=classify,
               accept_examples=["192.168.4.5", "203.0.113.7"],
               reject_examples=["google.com", "192.168.4", "12.34.56.78.9"])


def at_dfa():
    states = ["q0", "q1"]
    alphabet = ["@", OTHER]
    delta = {("q0", "@"): "q1", ("q0", OTHER): "q0",
             ("q1", "@"): "q1", ("q1", OTHER): "q1"}
    return DFA("At symbol (@)", r".*@.*", states, alphabet, delta, "q0", ["q1"],
               accept_examples=["google.com@evil.top", "a@b"],
               reject_examples=["google.com", "https://www.python.org/"])


# ---------------------------------------------------------------------
#  4.  The six rules (regex + DFA(s))
# ---------------------------------------------------------------------
KEYWORDS = ["login", "verify", "secure", "update"]
TLDS = [".xyz", ".tk", ".top"]


class Rule:
    def __init__(self, rid, name, target, regex, dfas):
        self.rid, self.name, self.target = rid, name, target   # target: 'url'|'host'
        self.regex = re.compile(regex)
        self.regex_text = regex
        self.dfas = dfas

    def check(self, url, host):
        text = url if self.target == "url" else host
        dfa_hit, hits = False, []
        for d in self.dfas:
            ok, steps, final = d.run(text)
            if ok:
                dfa_hit = True
                hits.append((d, steps, final))
        regex_hit = self.regex.search(text) is not None
        return dfa_hit, regex_hit, hits


def build_rules():
    r1 = Rule("R1", "Suspicious keyword (login/verify/secure/update)", "url",
              r"login|verify|secure|update",
              [dfa_from_patterns("Keyword '%s'" % w, ".*%s.*" % w, [w], True,
                                 ["xx%sxx" % w, w], ["", w[:-1], "hello"])
               for w in KEYWORDS])
    r2 = Rule("R2", "IP address used as host", "host",
              r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", [ip_dfa()])
    r3 = Rule("R3", "'@' symbol in URL", "url", r"@", [at_dfa()])
    r4 = Rule("R4", "3 or more hyphens in host", "host", r"^(?:[^-]*-){3}",
              [counting_dfa("Three or more hyphens", r"([^-]*-){3}.*", "-", 3,
                            ["a-b-c-d.com", "---"], ["a-b-c.com", "google.com"])])
    r5 = Rule("R5", "4 or more dots (too many subdomains)", "host",
              r"^(?:[^.]*\.){4}",
              [counting_dfa("Four or more dots", r"([^.]*\.){4}.*", ".", 4,
                            ["a.b.c.d.example.com", "...."],
                            ["www.example.co.uk", "google.com"])])
    r6 = Rule("R6", "Suspicious ending (.xyz/.tk/.top)", "host",
              r"\.(?:xyz|tk|top)$",
              [dfa_from_patterns("Suspicious ending (%s)" % " | ".join(TLDS),
                                 r".*\.(xyz|tk|top)", TLDS, False,
                                 ["secure-bank.xyz", "free.tk", "a.top"],
                                 ["google.com", "xyz.com", "top.in"])])
    return [r1, r2, r3, r4, r5, r6]


RULES = build_rules()


# ---------------------------------------------------------------------
#  5.  URL parsing and analysis
# ---------------------------------------------------------------------
def extract_host(url):
    """scheme://user@HOST:port/path?query#frag   ->   HOST (lower-case)."""
    u = re.sub(r"^[A-Za-z][A-Za-z0-9+.\-]*://", "", url.strip())
    u = re.split(r"[/?#]", u, maxsplit=1)[0]
    if "@" in u:                       # text before '@' is only a fake 'user name'
        u = u.rsplit("@", 1)[1]
    u = re.sub(r":\d+$", "", u)
    return u.lower()


def analyse(url, threshold=2):
    url = url.strip()
    low, host = url.lower(), extract_host(url)
    triggered, details, mismatch = [], [], []
    for rule in RULES:
        dfa_hit, regex_hit, hits = rule.check(low, host)
        if dfa_hit != regex_hit:
            mismatch.append(rule.rid)
        if dfa_hit:
            triggered.append(rule)
            details.append((rule, hits))
    score = len(triggered)
    verdict = "PHISHING" if score >= threshold else ("CAUTION" if score else "SAFE")
    return {"url": url, "host": host, "score": score, "verdict": verdict,
            "triggered": triggered, "details": details, "mismatch": mismatch}


def format_trace(steps, limit=14):
    if not steps:
        return "(stayed in start state)"
    parts = ["%s -(%s)-> %s" % (s, c, t) for _, c, s, t in steps[:limit]]
    txt = "  ".join(parts)
    return txt + ("  ..." if len(steps) > limit else "")


def print_report(res, verbose=False):
    bar = "=" * 70
    print(bar)
    print("URL     :", res["url"])
    print("Host    :", res["host"])
    print("Rules   :", ", ".join(r.rid for r in res["triggered"]) or "none triggered")
    print("Score   : %d / %d" % (res["score"], len(RULES)))
    print("Verdict :", res["verdict"])
    if res["mismatch"]:
        print("WARNING : regex and DFA disagree on", res["mismatch"])
    for rule, hits in res["details"]:
        print("  [%s] %s" % (rule.rid, rule.name))
        for d, steps, final in hits:
            print("      DFA '%s' accepted in state %s" % (d.name, final))
            print("      path:", format_trace(steps))
    if verbose and not res["details"]:
        print("  (no DFA reached an accepting state)")
    print(bar)


# ---------------------------------------------------------------------
#  6.  Evaluation on a CSV  (url,label)  label: 1 = phishing, 0 = safe
# ---------------------------------------------------------------------
def evaluate(path, threshold, out_csv="results.csv"):
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            rows.append((r["url"].strip(), int(r["label"])))
    tp = fp = tn = fn = 0
    out, wrong = [], []
    t0 = time.perf_counter()
    for url, label in rows:
        res = analyse(url, threshold)
        pred = 1 if res["verdict"] == "PHISHING" else 0
        tp += pred == 1 and label == 1
        fp += pred == 1 and label == 0
        tn += pred == 0 and label == 0
        fn += pred == 0 and label == 1
        ok = pred == label
        if not ok:
            wrong.append((url, label, res))
        out.append([url, label, pred, res["score"],
                    " ".join(r.rid for r in res["triggered"]), "OK" if ok else "WRONG"])
    elapsed = time.perf_counter() - t0
    n = len(rows)
    acc = (tp + tn) / n if n else 0
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0

    print("%-3s %-52s %-6s %-6s %-5s %s" % ("#", "URL", "Actual", "Pred", "Score", "Rules"))
    print("-" * 96)
    for i, o in enumerate(out, 1):
        u = o[0] if len(o[0]) <= 50 else o[0][:47] + "..."
        print("%-3d %-52s %-6s %-6s %-5s %s  %s" % (
            i, u, "phish" if o[1] else "safe", "phish" if o[2] else "safe", o[3], o[4],
            "" if o[5] == "OK" else "<-- WRONG"))
    print("\nThreshold (rules needed to call PHISHING): %d" % threshold)
    print("\nConfusion matrix            Predicted phishing   Predicted safe")
    print("  Actual phishing           %-20d %d   (TP / FN)" % (tp, fn))
    print("  Actual safe               %-20d %d   (FP / TN)" % (fp, tn))
    print("\nTotal URLs : %d" % n)
    print("Accuracy   : %.1f %%" % (acc * 100))
    print("Precision  : %.1f %%" % (prec * 100))
    print("Recall     : %.1f %%" % (rec * 100))
    print("F1-score   : %.1f %%" % (f1 * 100))
    print("Time       : %.2f ms total, %.1f microseconds per URL" % (
        elapsed * 1000, elapsed / n * 1e6 if n else 0))
    if wrong:
        print("\nMisclassified URLs:")
        for url, label, res in wrong:
            print("  - %s  (actual: %s, rules hit: %s)" % (
                url, "phishing" if label else "safe",
                ", ".join(r.rid for r in res["triggered"]) or "none"))
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "actual", "predicted", "score", "rules_triggered", "result"])
        w.writerows(out)
    print("\nDetailed results saved to", out_csv)


# ---------------------------------------------------------------------
#  7.  DFA specification printer (for the report: 5-tuple, delta, table)
# ---------------------------------------------------------------------
def all_dfas():
    return [(rule, d) for rule in RULES for d in rule.dfas]


def sym_label(a):
    return "other" if a == OTHER else a


def print_dfa_spec(index, rule, d):
    print("=" * 72)
    print("DFA %d  -  %s      (belongs to %s)" % (index, d.name, rule.rid))
    print("Regular expression : %s" % d.regex_text)
    print("Applied to         : %s" % ("the whole URL" if rule.target == "url" else "the host part"))
    print("How it was made    : %s" % d.built_note)
    print("-" * 72)
    print("5-tuple  M = (Q, Sigma, delta, q0, F)")
    print("  Q     = {%s}" % ", ".join(d.states))
    print("  Sigma = {%s}   ('other' = any character not listed)" %
          ", ".join(sym_label(a) for a in d.alphabet))
    print("  q0    = %s" % d.start)
    print("  F     = {%s}" % ", ".join(sorted(d.accepts, key=d.states.index)))
    print("\nTransition function delta:")
    for s in d.states:
        for a in d.alphabet:
            print("  delta(%s, %s) = %s" % (s, sym_label(a), d.delta[(s, a)]))
    print("\nTransition table:")
    head = ["State"] + [sym_label(a) for a in d.alphabet]
    w = max(7, max(len(h) for h in head) + 1)
    print("  " + "".join(h.ljust(w) for h in head))
    for s in d.states:
        mark = ("->" if s == d.start else "  ") + ("*" if s in d.accepts else " ")
        row = [mark + s] + [d.delta[(s, a)] for a in d.alphabet]
        print("  " + "".join(c.ljust(w) for c in row))
    print("  (-> start state, * accepting state)")
    print("\nAccepted example strings:")
    for x in d.accept_examples:
        ok = d.run(x)[0]
        print("  %-28r %s" % (x, "accepted" if ok else "!! NOT accepted (bug)"))
    print("Rejected example strings:")
    for x in d.reject_examples:
        ok = d.run(x)[0]
        print("  %-28r %s" % (x, "rejected" if not ok else "!! accepted (bug)"))
    print()


def print_all_specs():
    for i, (rule, d) in enumerate(all_dfas(), 1):
        print_dfa_spec(i, rule, d)


# ---------------------------------------------------------------------
#  8.  Graphviz diagrams
# ---------------------------------------------------------------------
def dfa_to_dot(d):
    edges = {}
    for (s, a), t in d.delta.items():
        edges.setdefault((s, t), []).append(sym_label(a))
    lines = ["digraph DFA {", "  rankdir=LR;", "  labelloc=t;",
             '  label="%s   [%s]";' % (d.name.replace('"', "'"), d.regex_text.replace('"', "'").replace("\\", "\\\\")),
             '  node [shape=circle, fontname="Helvetica"];',
             '  edge [fontname="Helvetica"];', "  __start [shape=point];"]
    for s in d.states:
        if s == DEAD:
            continue
        lines.append('  %s [shape=%s];' % (s, "doublecircle" if s in d.accepts else "circle"))
    if DEAD in d.states:
        lines.append('  %s [shape=circle, style=dashed];' % DEAD)
    lines.append("  __start -> %s;" % d.start)
    for (s, t), labels in edges.items():
        lines.append('  %s -> %s [label="%s"];' % (s, t, ", ".join(labels)))
    lines.append("}")
    return "\n".join(lines)


def write_diagrams(folder):
    os.makedirs(folder, exist_ok=True)
    have_dot = shutil.which("dot") is not None
    for i, (rule, d) in enumerate(all_dfas(), 1):
        slug = re.sub(r"[^a-z0-9]+", "_", d.name.lower()).strip("_")
        base = os.path.join(folder, "dfa%02d_%s" % (i, slug))
        with open(base + ".dot", "w") as f:
            f.write(dfa_to_dot(d))
        if have_dot:
            subprocess.run(["dot", "-Tpng", "-Gdpi=130", base + ".dot", "-o", base + ".png"], check=False)
    print("Diagrams written to '%s'%s" % (folder, "" if have_dot else
          "  (install Graphviz to turn .dot files into PNG images)"))


# ---------------------------------------------------------------------
#  9.  Command line
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Phishing URL detector (Regular Expressions + DFA)")
    ap.add_argument("urls", nargs="*", help="URLs to check")
    ap.add_argument("--test", metavar="CSV", help="evaluate on a CSV with columns url,label")
    ap.add_argument("--threshold", type=int, default=2, help="rules needed to say PHISHING (default 2)")
    ap.add_argument("--dfa-tables", action="store_true", help="print 5-tuple, delta and table of every DFA")
    ap.add_argument("--dot", metavar="DIR", help="write DFA diagrams (.dot and .png) into DIR")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    if a.dfa_tables:
        print_all_specs()
    elif a.dot:
        write_diagrams(a.dot)
    elif a.test:
        evaluate(a.test, a.threshold)
    elif a.urls:
        for u in a.urls:
            print_report(analyse(u, a.threshold), a.verbose)
    else:
        print("Phishing URL Detector  (type a URL, or 'q' to quit)")
        while True:
            try:
                u = input("\nURL> ").strip()
            except EOFError:
                break
            if u.lower() in ("q", "quit", "exit"):
                break
            if u:
                print_report(analyse(u, a.threshold), a.verbose)


if __name__ == "__main__":
    main()
