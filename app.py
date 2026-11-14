"""
Web demo for the Phishing URL Detector.

This page only SHOWS what phishing_detector.py already does. All the
detection (regular expressions and DFAs) is done by that file, so the
report and the demo always agree.

Run it:
    pip install streamlit pandas
    python -m streamlit run app.py
"""

import csv
import html
import io
import os
import sys

import pandas as pd
import streamlit as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import phishing_detector as pdet  # noqa: E402

st.set_page_config(page_title="PhishGuard - Phishing URL Detector",
                   layout="wide")

SAMPLES = [
    "http://paypa1-secure-login.xyz/verify",
    "https://www.google.com/",
    "https://github.com/login",
    "http://192.168.10.45/login/update.php",
    "http://www.google.com@malicious-site.top/login",
    "http://a.b.c.d.e.secure-mail.com/login",
    "http://www.amaz0n-offers.com/deal",
]

RULE_INFO = {  # short text shown on each rule card
    "R1": ("Suspicious Keyword", "login / verify / secure / update"),
    "R2": ("IP Address as Host", "e.g. 192.168.4.5"),
    "R3": ("'@' Symbol in URL", "e.g. google.com@evil.top"),
    "R4": ("3 or More Hyphens", "e.g. a-b-c-d.com"),
    "R5": ("4 or More Dots", "e.g. a.b.c.d.example.com"),
    "R6": ("Suspicious Ending", ".xyz | .tk | .top"),
}

# ------------------------------------------------------------------- style
CSS = """
<style>
:root{
  --bg:#070d1f; --panel:#0e1730; --panel2:#111c3a; --line:rgba(90,130,255,.22);
  --text:#e8edff; --muted:#93a1c9; --blue:#2f7bff; --green:#2fd27c;
  --amber:#ffb020; --red:#ff4d5e;
}
.stApp{background:radial-gradient(1200px 500px at 70% -10%,#12214a 0%,#070d1f 60%);color:var(--text);}
header[data-testid="stHeader"]{background:transparent;}
.block-container{padding-top:1.6rem;max-width:1500px;}
h1,h2,h3,h4,p,span,label,div{color:var(--text);}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0b1330 0%,#080e22 100%);
  border-right:1px solid var(--line);}
[data-testid="stSidebar"] *{color:var(--text);}

/* sidebar brand */
.brand{display:flex;flex-direction:column;align-items:center;padding:6px 0 18px 0;}
.brand .name{font-size:1.7rem;font-weight:800;letter-spacing:.3px;margin-top:6px;}
.brand .name b{color:#4aa3ff;font-weight:800;}

/* sidebar nav (plain buttons, works on every Streamlit version) */
[data-testid="stSidebar"] .stButton{margin-bottom:6px;}
[data-testid="stSidebar"] .stButton button{
  background:transparent !important;border:0 !important;box-shadow:none !important;
  width:100%;justify-content:flex-start;padding:11px 14px;border-radius:10px;color:var(--text) !important;}
[data-testid="stSidebar"] .stButton button p{font-size:1.02rem;font-weight:600;text-align:left;margin:0;}
[data-testid="stSidebar"] .stButton button:hover{background:rgba(47,123,255,.14) !important;}
.navon{background:linear-gradient(90deg,#2f7bff,#2a63d6);box-shadow:0 4px 16px rgba(47,123,255,.35);
  border-radius:10px;padding:11px 14px;font-size:1.02rem;font-weight:600;margin-bottom:6px;color:#fff;}

/* settings box */
.setbox{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px 4px 16px;margin-top:10px;}
.setbox .t{font-weight:700;font-size:1.05rem;}
.setbox .s{color:var(--muted);font-size:.9rem;margin:6px 0 2px 0;}
.infobox{background:rgba(47,123,255,.10);border:1px solid var(--line);border-radius:12px;
  padding:10px 12px;font-size:.85rem;color:var(--muted);margin-top:10px;}

/* header */
.hdr{display:flex;justify-content:space-between;align-items:flex-start;}
.hdr h1{font-size:2.3rem;margin:0;padding:0;line-height:1.15;font-weight:800;}
.hdr .sub{color:#c7d2f5;font-size:1.1rem;margin-top:2px;}
.badge{border:1px solid var(--line);background:rgba(47,123,255,.12);border-radius:999px;
  padding:9px 18px;font-size:.9rem;color:#bcd0ff;white-space:nowrap;}

/* stat cards */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:18px 0 20px 0;}
.stat{display:flex;align-items:center;gap:16px;border-radius:16px;padding:18px 20px;
  border:1px solid var(--line);background:var(--panel);}
.stat .ic{font-size:2.2rem;line-height:1;}
.stat .lb{color:#c0caea;font-size:.95rem;}
.stat .vl{font-size:1.9rem;font-weight:800;line-height:1.15;}
.stat .vl small{font-size:1.15rem;font-weight:700;margin-left:6px;}
.stat.s1{background:linear-gradient(135deg,#0f2250,#0d1a3c);border-color:rgba(47,123,255,.45);}
.stat.s2{background:linear-gradient(135deg,#0c2a2a,#0c1d27);border-color:rgba(47,210,124,.45);}
.stat.s2 .vl small{color:var(--green);}
.stat.s3{background:linear-gradient(135deg,#2b2410,#1c1b1b);border-color:rgba(255,176,32,.5);}
.stat.s3 .vl small{color:var(--amber);}
.stat.s4{background:linear-gradient(135deg,#2e1220,#1d1220);border-color:rgba(255,77,94,.5);}
.stat.s4 .vl small{color:var(--red);}

/* section panel */
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px 20px;margin-bottom:18px;}
.sec{font-size:1.35rem;font-weight:800;margin:6px 0 12px 0;}

/* verdict banner */
.verdict{display:flex;align-items:center;border-radius:16px;padding:18px 24px;margin-top:14px;gap:0;}
.verdict .main{display:flex;align-items:center;gap:18px;flex:2.2;}
.verdict .big{font-size:2.1rem;font-weight:900;letter-spacing:.5px;line-height:1.1;}
.verdict .msg{font-size:1.02rem;}
.verdict .icon{font-size:3rem;}
.verdict .cell{flex:1;padding:0 24px;border-left:1px solid rgba(255,255,255,.18);}
.verdict .cell .k{color:#d5dcf5;font-size:.95rem;}
.verdict .cell .v{font-size:1.6rem;font-weight:800;}
.verdict .host{font-size:1.2rem;font-weight:800;word-break:break-all;}
.verdict .ring{width:62px;height:62px;border-radius:50%;margin-left:14px;display:inline-block;vertical-align:middle;}
.verdict.phish{background:linear-gradient(90deg,#4a1220,#2b0f1d);border:1.5px solid var(--red);box-shadow:0 0 26px rgba(255,77,94,.25);}
.verdict.phish .big{color:#ff6070;}
.verdict.warn{background:linear-gradient(90deg,#463511,#2a2312);border:1.5px solid var(--amber);box-shadow:0 0 26px rgba(255,176,32,.2);}
.verdict.warn .big{color:#ffc04d;}
.verdict.safe{background:linear-gradient(90deg,#0f3d2a,#0c2a25);border:1.5px solid var(--green);box-shadow:0 0 26px rgba(47,210,124,.2);}
.verdict.safe .big{color:#46e08f;}

/* rule cards */
.rules{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;align-items:start;}
.rule{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px 16px;}
.rule .top{display:flex;align-items:center;justify-content:space-between;gap:10px;}
.rule .l{display:flex;gap:14px;align-items:center;}
.rule .id{font-size:1.15rem;font-weight:800;color:#cfe0ff;}
.rule .nm{font-weight:700;font-size:1rem;}
.rule .ex{color:var(--muted);font-size:.82rem;}
.rule details{margin-top:12px;border-top:1px solid var(--line);padding-top:10px;}
.rule summary{cursor:pointer;color:#7fb2ff;font-weight:700;font-size:.9rem;list-style:none;}
.rule summary::-webkit-details-marker{display:none;}
.rule summary::before{content:"+  ";}
.rule details[open] summary::before{content:"-  ";}
.wk{max-height:340px;overflow:auto;margin-top:10px;}
.wk .ttl{font-weight:700;font-size:.9rem;margin-top:10px;}
.wk .acc{color:#46e08f;} .wk .rej{color:#ff8a95;}
.wk .rd{color:var(--muted);font-size:.8rem;word-break:break-all;margin:2px 0 6px 0;}
.wk table{width:100%;border-collapse:collapse;font-size:.82rem;}
.wk th{color:var(--muted);text-align:left;font-weight:600;padding:4px 6px;border-bottom:1px solid var(--line);}
.wk td{padding:3px 6px;border-bottom:1px solid rgba(255,255,255,.05);}
.wk tr.ch td{background:rgba(47,123,255,.16);font-weight:700;}
.pill{border-radius:999px;padding:6px 14px;font-size:.88rem;font-weight:700;white-space:nowrap;}
.pill.on{background:rgba(255,77,94,.20);color:#ff6a78;border:1px solid rgba(255,77,94,.6);}
.pill.off{background:rgba(255,255,255,.07);color:#b4bfdc;border:1px solid rgba(255,255,255,.12);}

/* trace + insight */
.trace div{margin:7px 0;font-size:1rem;}
.trace .ok{color:var(--green);margin-right:8px;}
.insight{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:16px 18px;}
.insight .h{font-weight:800;font-size:1.1rem;margin-bottom:6px;}
.insight .b{color:#c0caea;font-size:.95rem;}

/* streamlit widgets */
div[data-baseweb="select"] > div, .stTextInput input{background:#0a1228 !important;
  border:1px solid var(--line) !important;border-radius:10px !important;color:var(--text) !important;}
.stButton button, div[data-testid="stFormSubmitButton"] button{
  background:linear-gradient(90deg,#2f7bff,#2a63d6);color:#fff;border:0;border-radius:10px;
  font-weight:700;padding:.55rem 1.2rem;width:100%;}
[data-testid="stMetric"]{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:12px 16px;}
[data-testid="stForm"]{border:0;padding:0;}
div[data-testid="stExpander"]{background:var(--panel2);border:1px solid var(--line);border-radius:12px;}
hr{border-color:var(--line);}
/* DFA diagrams: classic black-and-white, on a white card */
[data-testid="stGraphVizChart"]{background:#ffffff;border-radius:14px;padding:14px;
  border:1px solid var(--line);}
[data-testid="stGraphVizChart"] svg{background:#ffffff;}
[data-testid="stGraphVizChart"] *{color:#000;}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

LOGO = (
    '<svg width="86" height="96" viewBox="0 0 86 96" xmlns="http://www.w3.org/2000/svg">'
    '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
    '<stop offset="0" stop-color="#58b6ff"/><stop offset="1" stop-color="#2f5bff"/></linearGradient></defs>'
    '<path d="M43 4 L78 17 V46 C78 68 62 84 43 92 C24 84 8 68 8 46 V17 Z" fill="#0c1c45" '
    'stroke="url(#g)" stroke-width="5" stroke-linejoin="round"/>'
    '<circle cx="43" cy="44" r="20" fill="none" stroke="#58b6ff" stroke-width="3"/>'
    '<ellipse cx="43" cy="44" rx="9" ry="20" fill="none" stroke="#58b6ff" stroke-width="2.5"/>'
    '<line x1="23" y1="44" x2="63" y2="44" stroke="#58b6ff" stroke-width="2.5"/>'
    '<path d="M27 32 Q43 38 59 32 M27 56 Q43 50 59 56" fill="none" stroke="#58b6ff" stroke-width="2"/>'
    '</svg>'
)


# ----------------------------------------------------------------- helpers
def sym(a):
    return "other" if a == pdet.OTHER else a


def full_trace(dfa, text):
    """Every single move of the DFA on the text (one row per character)."""
    state, rows = dfa.start, []
    for i, ch in enumerate(text, 1):
        symbol = dfa.classify(ch)
        nxt = dfa.delta[(state, symbol)]
        rows.append({"#": i, "Character": ch, "Symbol read": sym(symbol),
                     "From state": state, "To state": nxt,
                     "Changed": "yes" if nxt != state else ""})
        state = nxt
    return rows, state


def working_html(rule, res, low):
    """The step-by-step working of one rule, as a small HTML block."""
    text = low if rule.target == "url" else res["host"]
    out = ['<div class="wk"><div class="rd">Applied to the %s: %s</div>' % (
        "whole URL" if rule.target == "url" else "host only", html.escape(text) or "(empty)")]
    out.append('<div class="rd">Highlighted rows are the moves where the state changed.</div>')
    for d in rule.dfas:
        rows, final = full_trace(d, text)
        ok = final in d.accepts
        out.append('<div class="ttl">%s &nbsp;<span class="%s">%s</span> (final state %s)</div>' % (
            html.escape(d.name), "acc" if ok else "rej",
            "ACCEPTED" if ok else "rejected", final))
        if not rows:
            out.append('<div class="rd">Nothing to read (empty text).</div>')
            continue
        out.append("<table><tr><th>#</th><th>Char</th><th>Symbol</th><th>From</th><th>To</th></tr>")
        for r in rows:
            out.append('<tr%s><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                ' class="ch"' if r["Changed"] else "", r["#"], html.escape(r["Character"]),
                html.escape(r["Symbol read"]), r["From state"], r["To state"]))
        out.append("</table>")
    out.append("</div>")
    return "".join(out)


def dark_dot(dot):
    """Same diagram as the report, recoloured so it is readable on dark."""
    dot = dot.replace('node [shape=circle, fontname="Helvetica"];',
                      'bgcolor="transparent"; fontcolor="#e8edff"; '
                      'node [shape=circle, fontname="Helvetica", color="#58b6ff", fontcolor="#e8edff"];')
    dot = dot.replace('edge [fontname="Helvetica"];',
                      'edge [fontname="Helvetica", color="#8aa4e8", fontcolor="#e8edff"];')
    return dot


def read_rows(text):
    return [(r["url"].strip(), int(r["label"])) for r in csv.DictReader(io.StringIO(text))]


def load_default_csv():
    path = os.path.join(HERE, "test_urls.csv")
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as f:
            return f.read()
    return None


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown('<div class="brand">%s<div class="name">Phish<b>Guard</b></div></div>' % LOGO,
                unsafe_allow_html=True)
    PAGES = ["Check a URL", "DFA Diagrams", "Test Set Results"]
    if "page" not in st.session_state:
        st.session_state.page = PAGES[0]

    def go_to(name):
        st.session_state.page = name

    for name in PAGES:
        if st.session_state.page == name:
            st.markdown('<div class="navon">%s</div>' % name, unsafe_allow_html=True)
        else:
            st.button(name, key="nav_" + name, on_click=go_to, args=(name,))
    page = st.session_state.page
    st.markdown('<div class="setbox"><div class="t">Detection Settings</div>'
                '<div class="s">Rules needed to call a URL PHISHING</div></div>',
                unsafe_allow_html=True)
    threshold = st.slider("Rules needed", 1, 6, 2, label_visibility="collapsed")
    st.markdown('<div class="infobox">Score = number of rules triggered.<br>'
                '0 rules = SAFE, 1 rule = CAUTION (when below the threshold).</div>',
                unsafe_allow_html=True)

# ----------------------------------------------------------------- header
st.markdown(
    '<div class="hdr"><div><h1>Phishing URL Detector</h1>'
    '<div class="sub">Regular Expressions + DFA</div></div>'
    '<div class="badge">Formal Languages &amp; Automata Theory</div></div>',
    unsafe_allow_html=True)

# ------------------------------------------------------- stat cards (test set)
default_csv = load_default_csv()
tot = safe_n = warn_n = phish_n = 0
if default_csv:
    for u, _ in read_rows(default_csv):
        v = pdet.analyse(u, threshold)["verdict"]
        tot += 1
        safe_n += v == "SAFE"
        warn_n += v == "CAUTION"
        phish_n += v == "PHISHING"


def pct(n):
    return "(%.1f%%)" % (100.0 * n / tot) if tot else ""


st.markdown(
    '<div class="stats">'
    '<div class="stat s1"><div><div class="lb">URLs in test set</div>'
    '<div class="vl">%d</div></div></div>'
    '<div class="stat s2"><div><div class="lb">Safe URLs</div>'
    '<div class="vl">%d<small>%s</small></div></div></div>'
    '<div class="stat s3"><div><div class="lb">Suspicious URLs</div>'
    '<div class="vl">%d<small>%s</small></div></div></div>'
    '<div class="stat s4"><div><div class="lb">Phishing URLs</div>'
    '<div class="vl">%d<small>%s</small></div></div></div>'
    '</div>' % (tot, safe_n, pct(safe_n), warn_n, pct(warn_n), phish_n, pct(phish_n)),
    unsafe_allow_html=True)

# ================================================================== page 1
if page.endswith("Check a URL"):
    st.markdown('<div class="sec">URL Analysis</div>', unsafe_allow_html=True)

    if "active_url" not in st.session_state:
        st.session_state.active_url = SAMPLES[0]

    with st.form("check"):
        c1, c2, c3 = st.columns([3, 3, 1.2])
        example = c1.selectbox("Try an example URL", SAMPLES)
        own = c2.text_input("or enter your own URL", placeholder="Enter URL here...")
        c3.markdown("<div style='height:1.9rem'></div>", unsafe_allow_html=True)
        go = c3.form_submit_button("Analyse URL")
    if go:
        st.session_state.active_url = own.strip() or example

    url = st.session_state.active_url
    res = pdet.analyse(url, threshold)
    verdict, score, nrules = res["verdict"], res["score"], len(pdet.RULES)
    fired = {r.rid for r in res["triggered"]}

    cls, icon, big, msg, col = {
        "PHISHING": ("phish", "", "PHISHING", "This URL is potentially dangerous!", "#ff4d5e"),
        "CAUTION": ("warn", "", "CAUTION", "One rule triggered. Be careful with this URL.", "#ffb020"),
        "SAFE": ("safe", "", "SAFE", "No rule triggered for this URL.", "#2fd27c"),
    }[verdict]
    deg = int(360 * score / nrules)
    ring = ("background:conic-gradient(%s %ddeg, rgba(255,255,255,.15) 0);"
            "-webkit-mask:radial-gradient(circle 21px,transparent 98%%,#000 100%%);"
            "mask:radial-gradient(circle 21px,transparent 98%%,#000 100%%);" % (col, deg))
    st.markdown(
        '<div class="verdict %s"><div class="main"><div class="icon">%s</div>'
        '<div><div class="big">%s</div><div class="msg">%s</div></div></div>'
        '<div class="cell"><div class="k">Risk Score</div><div class="v">%d / %d'
        '<span class="ring" style="%s"></span></div></div>'
        '<div class="cell" style="flex:1.6"><div class="k">Host (Website Name)</div>'
        '<div class="host">%s</div></div>'
        '<div class="cell"><div class="k">Triggered Rules</div>'
        '<div class="v" style="color:%s">%d of %d</div></div></div>'
        % (cls, icon, big, msg, score, nrules, ring, res["host"] or "(empty)", col, score, nrules),
        unsafe_allow_html=True)

    if res["mismatch"]:
        st.warning("Regex and DFA disagree on: " + ", ".join(res["mismatch"]))

    # -------- detection breakdown
    cards = ""
    low = url.strip().lower()
    for r in pdet.RULES:
        name, ex = RULE_INFO.get(r.rid, (r.name, ""))
        on = r.rid in fired
        cards += ('<div class="rule"><div class="top"><div class="l"><div class="id">%s</div><div>'
                  '<div class="nm">%s</div><div class="ex">%s</div></div></div>'
                  '<div class="pill %s">%s</div></div>'
                  '<details><summary>Show working</summary>%s</details></div>'
                  % (r.rid, name, ex, "on" if on else "off", "Triggered" if on else "Not Triggered",
                     working_html(r, res, low)))
    st.markdown('<div class="panel"><div class="sec">Detection Breakdown</div>'
                '<div class="rules">%s</div></div>' % cards, unsafe_allow_html=True)

    # -------- DFA analysis
    low = url.strip().lower()
    hit = None  # (rule, dfa) that accepted the URL
    for rule in pdet.RULES:
        if rule.rid in fired:
            text = low if rule.target == "url" else res["host"]
            for d in rule.dfas:
                _, final = full_trace(d, text)
                if final in d.accepts:
                    hit = (rule, d, text)
                    break
        if hit:
            break

    st.markdown('<div class="sec">DFA Analysis</div>', unsafe_allow_html=True)
    if hit:
        rule, d, text = hit
        rows, final = full_trace(d, text)
        a, b, c = st.columns([3.4, 2.4, 2])
        with a:
            st.caption("%s  |  %s" % (rule.rid, d.name))
            st.graphviz_chart(pdet.dfa_to_dot(d))
        with b:
            st.markdown("**Processing Trace**")
            _, steps, _fin = d.run(text)
            lines = "".join(
                '<div><span class="ok">●</span>Read \'%s\' → %s → %s</div>'
                % (ch.replace("<", "&lt;"), a_, b_) for (_i, ch, a_, b_) in steps[:6])
            if len(steps) > 6:
                lines += '<div><span class="ok">●</span>... (%d more state changes)</div>' % (len(steps) - 6)
            lines += ('<div style="margin-top:10px;color:#93a1c9;font-size:.85rem">'
                      'Only moves where the state changed are shown.</div>')
            lines += '<div style="margin-top:6px"><b>Final state: %s (ACCEPTED)</b></div>' % final
            st.markdown('<div class="trace">%s</div>' % lines, unsafe_allow_html=True)
        with c:
            st.markdown('<div class="insight"><div class="h">Key Insight</div>'
                        '<div class="b">This DFA ended in an accepting state, so rule %s triggered. '
                        'The regular expression and the DFA give the same answer.</div></div>' % rule.rid,
                        unsafe_allow_html=True)
    else:
        st.info("No rule triggered, so no DFA ended in an accepting state for this URL. "
                "Tick the box below to see how the DFAs read it anyway.")

    st.markdown("&nbsp;")
    show_all = st.checkbox("Show the full character-by-character trace of every DFA")
    if show_all:
        for rule in pdet.RULES:
            text = low if rule.target == "url" else res["host"]
            for d in rule.dfas:
                rows, final = full_trace(d, text)
                ok = final in d.accepts
                label = "%s  |  %s  |  %s (final state %s)" % (
                    rule.rid, d.name, "ACCEPTED" if ok else "rejected", final)
                with st.expander(label):
                    st.caption("Reading: %r" % text)
                    if rows:
                        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
                    else:
                        st.write("Nothing to read (empty text).")

# ================================================================== page 2
elif page.endswith("DFA Diagrams"):
    pairs = pdet.all_dfas()
    names = ["%d. %s  (%s)" % (i, d.name, r.rid) for i, (r, d) in enumerate(pairs, 1)]
    pick = st.selectbox("Choose a DFA", names)
    rule, d = pairs[names.index(pick)]

    left, right = st.columns([3, 2])
    with left:
        st.graphviz_chart(pdet.dfa_to_dot(d))
    with right:
        st.markdown("**Regular expression:** `%s`" % d.regex_text)
        st.markdown("**How it was made:** %s" % d.built_note)
        st.markdown("**5-tuple** M = (Q, Sigma, delta, q0, F)")
        st.code("Q     = {%s}\nSigma = {%s}\nq0    = %s\nF     = {%s}" % (
            ", ".join(d.states), ", ".join(sym(a) for a in d.alphabet), d.start,
            ", ".join(sorted(d.accepts, key=d.states.index))))
    st.markdown("**Transition table** (-> start state, * accepting state)")
    table = []
    for s in d.states:
        mark = ("->" if s == d.start else "") + ("*" if s in d.accepts else "")
        row = {"State": (mark + " " + s).strip()}
        for a in d.alphabet:
            row[sym(a)] = d.delta[(s, a)]
        table.append(row)
    st.dataframe(pd.DataFrame(table), hide_index=True, width="stretch")
    e1, e2 = st.columns(2)
    e1.markdown("**Accepted examples**")
    e1.write(d.accept_examples)
    e2.markdown("**Rejected examples**")
    e2.write(d.reject_examples)

# ================================================================== page 3
else:
    st.write("Runs the detector on a CSV with the columns **url** and **label** "
             "(1 = phishing, 0 = safe).")
    up = st.file_uploader("Upload a CSV (or leave empty to use test_urls.csv)", type="csv")
    data = up.getvalue().decode("utf-8-sig") if up is not None else default_csv
    if data is None:
        st.info("Upload a CSV to see results.")
    else:
        rows = read_rows(data)
        tp = fp = tn = fn = 0
        table = []
        for u, lab in rows:
            r = pdet.analyse(u, threshold)
            pred = 1 if r["verdict"] == "PHISHING" else 0
            tp += pred == 1 and lab == 1
            fp += pred == 1 and lab == 0
            tn += pred == 0 and lab == 0
            fn += pred == 0 and lab == 1
            table.append({"URL": u, "Actual": "phishing" if lab else "safe",
                          "Predicted": "phishing" if pred else "safe",
                          "Score": r["score"],
                          "Rules": " ".join(x.rid for x in r["triggered"]),
                          "Result": "OK" if pred == lab else "WRONG"})
        n = len(rows)
        acc = (tp + tn) / n if n else 0
        prec = tp / (tp + fp) if tp + fp else 0
        rec = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
        m = st.columns(5)
        m[0].metric("URLs", n)
        m[1].metric("Accuracy", "%.1f%%" % (acc * 100))
        m[2].metric("Precision", "%.1f%%" % (prec * 100))
        m[3].metric("Recall", "%.1f%%" % (rec * 100))
        m[4].metric("F1-score", "%.1f%%" % (f1 * 100))
        st.markdown("**Confusion matrix** (threshold = %d)" % threshold)
        st.dataframe(pd.DataFrame(
            [[tp, fn], [fp, tn]],
            index=["Actual phishing", "Actual safe"],
            columns=["Predicted phishing", "Predicted safe"]), width="stretch")
        st.markdown("**All URLs**")
        st.dataframe(pd.DataFrame(table), hide_index=True, width="stretch")
        wrong = [t for t in table if t["Result"] == "WRONG"]
        if wrong:
            st.markdown("**Wrongly classified**")
            st.dataframe(pd.DataFrame(wrong), hide_index=True, width="stretch")
