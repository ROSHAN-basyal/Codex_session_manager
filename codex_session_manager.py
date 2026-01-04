import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


DEFAULT_SESSIONS_DIR = Path.home() / ".codex" / "sessions"
SESSION_MANAGER_DIRNAME = "session mananger"
TITLE_STORE_DIRNAME = "titles"
TITLE_STORE_FILENAME = "session_titles.json"
SETTINGS_FILENAME = "settings.json"
APP_CONFIG_DIRNAME = ".codex_session_manager"
APP_CONFIG_FILENAME = "config.json"
DEFAULT_TITLE = "Untitled_session"


@dataclass
class SessionEntry:
    session_id: str
    title: str
    created_at: str
    updated_at: str
    cwd: str
    path: Path
    created_display: str
    updated_display: str
    short_id: str
    search_blob: str
    is_default_title: bool


def parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def format_local(value):
    dt = parse_iso(value)
    if not dt:
        return "-"
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def iso_from_mtime(path):
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")


def iter_session_files(root_dir):
    if not root_dir.exists():
        return []
    return list(root_dir.rglob("rollout-*.jsonl"))


def read_jsonl_lines(path, max_lines=None):
    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if max_lines is not None and idx >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def find_session_meta(path):
    for obj in read_jsonl_lines(path, max_lines=200):
        if obj.get("type") == "session_meta":
            return obj.get("payload", {})
    return {}


def extract_first_user_text(path):
    for obj in read_jsonl_lines(path):
        if obj.get("type") != "response_item":
            continue
        payload = obj.get("payload", {})
        if payload.get("type") != "message":
            continue
        if payload.get("role") != "user":
            continue
        content = payload.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") in ("input_text", "text"):
                        text = (item.get("text") or "").strip()
                        if text:
                            return text
                elif isinstance(item, str):
                    text = item.strip()
                    if text:
                        return text
        elif isinstance(content, str):
            text = content.strip()
            if text:
                return text
    return ""


def is_noise_text(text):
    stripped = text.strip()
    lowered = stripped.lower()
    if not stripped:
        return True
    if stripped.startswith("<environment_context>"):
        return True
    if stripped.startswith("# AGENTS.md instructions"):
        return True
    if stripped.startswith("<INSTRUCTIONS>"):
        return True
    if "<environment_context>" in lowered:
        return True
    return False


def make_title(text, max_len=80):
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_len:
        return cleaned
    snippet = cleaned[: max_len + 1]
    last_space = snippet.rfind(" ")
    if last_space >= 20:
        snippet = snippet[:last_space]
    return snippet.rstrip() + "..."


def generate_title(path, session_id):
    raw = extract_first_user_text(path)
    if raw and not is_noise_text(raw):
        return make_title(raw)
    return DEFAULT_TITLE


def read_last_nonempty_line(path):
    chunk_size = 8192
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        position = f.tell()
        buffer = b""
        while position > 0:
            read_size = min(chunk_size, position)
            position -= read_size
            f.seek(position)
            data = f.read(read_size)
            buffer = data + buffer
            if b"\n" in data:
                lines = buffer.splitlines()
                for line in reversed(lines):
                    if line.strip():
                        return line.decode("utf-8", errors="replace")
        return buffer.decode("utf-8", errors="replace").strip()


def find_last_timestamp(path):
    line = read_last_nonempty_line(path)
    if line:
        try:
            payload = json.loads(line)
            timestamp = payload.get("timestamp")
            if timestamp:
                return timestamp
        except json.JSONDecodeError:
            pass
    return iso_from_mtime(path)


def load_title_overrides(path):
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def save_title_overrides(path, overrides):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(overrides, f, indent=2, ensure_ascii=True)
        f.write("\n")
    tmp_path.replace(path)


def default_titles_path(sessions_dir):
    return Path(sessions_dir) / SESSION_MANAGER_DIRNAME / TITLE_STORE_DIRNAME / TITLE_STORE_FILENAME


def default_settings_path(sessions_dir):
    return Path(sessions_dir) / SESSION_MANAGER_DIRNAME / SETTINGS_FILENAME


def app_config_path():
    return Path.home() / APP_CONFIG_DIRNAME / APP_CONFIG_FILENAME


def load_app_config(path):
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def save_app_config(path, sessions_dir):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"sessions_dir": str(sessions_dir)}
    tmp_path = path.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=True)
        f.write("\n")
    tmp_path.replace(path)


def ensure_manager_dirs(sessions_dir):
    titles = default_titles_path(sessions_dir)
    settings = default_settings_path(sessions_dir)
    titles.parent.mkdir(parents=True, exist_ok=True)
    settings.parent.mkdir(parents=True, exist_ok=True)


def resolve_sessions_dir_from_choice(choice):
    path = Path(choice).resolve()
    if path.name == "sessions":
        return path
    for parent in path.parents:
        if parent.name == "sessions" and parent.parent.name == ".codex":
            return parent
    if path.name == ".codex":
        return path / "sessions"
    for parent in path.parents:
        if parent.name == ".codex":
            return parent / "sessions"
    if (path / "sessions").exists():
        return path / "sessions"
    return None


def choose_codex_dir():
    while True:
        root = tk.Tk()
        root.withdraw()
        selected = filedialog.askdirectory(title="Select your .codex folder")
        root.update()
        root.destroy()
        if not selected:
            return None
        resolved = resolve_sessions_dir_from_choice(selected)
        if resolved:
            return resolved
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Invalid selection", "Choose the .codex folder or a subfolder inside it.", parent=root)
        root.update()
        root.destroy()


def load_settings(path):
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def save_settings(path, settings):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=True)
        f.write("\n")
    tmp_path.replace(path)


def powershell_literal(value):
    return value.replace("'", "''")


def bash_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def find_git_bash():
    candidates = []
    env_paths = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LocalAppData"),
    ]
    for base in env_paths:
        if not base:
            continue
        candidates.extend(
            [
                Path(base) / "Git" / "git-bash.exe",
                Path(base) / "Git" / "bin" / "bash.exe",
                Path(base) / "Git" / "usr" / "bin" / "bash.exe",
            ]
        )
    for name in ["git-bash.exe", "bash.exe"]:
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for path in candidates:
        if path.exists():
            return path
    return None


def available_shells():
    shells = []
    if os.name == "nt":
        pwsh = shutil.which("pwsh")
        if pwsh:
            shells.append(("PowerShell 7", "pwsh", pwsh))
        powershell = shutil.which("powershell")
        if powershell:
            shells.append(("Windows PowerShell", "powershell", powershell))
        cmd = os.environ.get("COMSPEC") or shutil.which("cmd")
        if cmd:
            shells.append(("Command Prompt", "cmd", cmd))
        git_bash = find_git_bash()
        if git_bash:
            shells.append(("Git Bash", "gitbash", str(git_bash)))
    else:
        shell_names = []
        default_shell = os.environ.get("SHELL")
        if default_shell:
            shell_names.append(default_shell)
        for name in ["bash", "zsh", "fish", "sh"]:
            found = shutil.which(name)
            if found:
                shell_names.append(found)
        seen = set()
        for path in shell_names:
            if path in seen:
                continue
            seen.add(path)
            label = Path(path).name
            shells.append((label, "posix", path))
    return shells


def match_preferred_cli(pref, options):
    if not isinstance(pref, dict):
        return None
    pref_exe = pref.get("exe")
    pref_kind = pref.get("kind")
    pref_label = pref.get("label")
    if pref_exe:
        for opt in options:
            if os.name == "nt":
                if str(opt[2]).lower() == str(pref_exe).lower():
                    return opt
            else:
                if str(opt[2]) == str(pref_exe):
                    return opt
    if pref_kind:
        matches = [opt for opt in options if opt[1] == pref_kind]
        if len(matches) == 1:
            return matches[0]
    if pref_label:
        for opt in options:
            if opt[0] == pref_label:
                return opt
    return None


def normalize_search(text):
    lowered = text.lower()
    cleaned = []
    for ch in lowered:
        cleaned.append(ch if ch.isalnum() else " ")
    return " ".join("".join(cleaned).split())


def matches_query(haystack, query):
    if not query:
        return True
    hay_norm = normalize_search(haystack)
    query_norm = normalize_search(query)
    if not query_norm:
        return True
    for token in query_norm.split():
        if token not in hay_norm:
            return False
    return True


def build_cli_display_options(options, default_opt):
    counts = {}
    for label, _, _ in options:
        counts[label] = counts.get(label, 0) + 1
    display = []
    mapping = {}
    for opt in options:
        label, _, exe = opt
        base = label if counts[label] == 1 else f"{label} ({exe})"
        shown = f"{base} (default)" if default_opt and opt == default_opt else base
        display.append(shown)
        mapping[shown] = opt
    return display, mapping


def build_resume_command(shell, session_id, cwd):
    label, kind, exe = shell
    if os.name == "nt":
        if kind == "cmd":
            if cwd:
                cmd_str = f'cd /d "{cwd}" && codex resume {session_id}'
            else:
                cmd_str = f"codex resume {session_id}"
            return [exe, "/k", cmd_str]
        if kind in ("powershell", "pwsh"):
            if cwd:
                cwd_literal = powershell_literal(cwd)
                ps_cmd = f"Set-Location -LiteralPath '{cwd_literal}'; codex resume {session_id}"
            else:
                ps_cmd = f"codex resume {session_id}"
            return [exe, "-NoExit", "-Command", ps_cmd]
        if kind == "gitbash":
            if cwd:
                cwd_literal = bash_quote(cwd)
                bash_cmd = f"cd {cwd_literal}; codex resume {session_id}; exec bash"
            else:
                bash_cmd = f"codex resume {session_id}; exec bash"
            return [exe, "-c", bash_cmd]
    else:
        if cwd:
            cmd = f"cd {bash_quote(cwd)}; codex resume {session_id}; exec {bash_quote(exe)}"
        else:
            cmd = f"codex resume {session_id}; exec {bash_quote(exe)}"
        return [exe, "-c", cmd]
    return [exe]


def open_terminal(shell_cmd):
    if os.name == "nt":
        subprocess.Popen(shell_cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return
    terminal = shutil.which("x-terminal-emulator")
    if terminal:
        subprocess.Popen([terminal, "-e"] + shell_cmd)
        return
    terminal = shutil.which("gnome-terminal")
    if terminal:
        subprocess.Popen([terminal, "--"] + shell_cmd)
        return
    terminal = shutil.which("xterm")
    if terminal:
        subprocess.Popen([terminal, "-e"] + shell_cmd)
        return
    subprocess.Popen(shell_cmd)


def apply_untitled_numbers(sessions):
    untitled = [s for s in sessions if s.is_default_title]
    untitled.sort(key=lambda s: parse_iso(s.created_at) or datetime.min)
    for idx, session in enumerate(untitled, start=1):
        session.title = f"{DEFAULT_TITLE}_{idx}"
        session.search_blob = f"{session.title} {session.cwd} {session.session_id} {session.path}".lower()


def load_sessions(root_dir, title_overrides):
    sessions = []
    for path in iter_session_files(root_dir):
        meta = find_session_meta(path)
        session_id = meta.get("id") or path.stem
        created_at = meta.get("timestamp") or iso_from_mtime(path)
        updated_at = find_last_timestamp(path)
        cwd = meta.get("cwd") or ""
        override = title_overrides.get(session_id)
        if override is not None:
            title = override
            is_default_title = False
        else:
            title = generate_title(path, session_id)
            is_default_title = title == DEFAULT_TITLE
        created_display = format_local(created_at)
        updated_display = format_local(updated_at)
        short_id = session_id[:8] if session_id else "unknown"
        search_blob = f"{title} {cwd} {session_id} {path}".lower()
        sessions.append(
            SessionEntry(
                session_id=session_id,
                title=title,
                created_at=created_at,
                updated_at=updated_at,
                cwd=cwd,
                path=path,
                created_display=created_display,
                updated_display=updated_display,
                short_id=short_id,
                search_blob=search_blob,
                is_default_title=is_default_title,
            )
        )
    apply_untitled_numbers(sessions)
    sessions.sort(key=lambda s: parse_iso(s.created_at) or datetime.min, reverse=True)
    return sessions


class SessionApp:
    def __init__(self, root, sessions_dir, titles_path, settings_path):
        self.root = root
        self.sessions_dir = Path(sessions_dir)
        self.titles_path = Path(titles_path)
        self.settings_path = Path(settings_path)
        self.titles_path.parent.mkdir(parents=True, exist_ok=True)
        self.title_overrides = {}
        self.settings = {}
        self.default_cli_pref = None
        self.sessions = []
        self.session_map = {}
        self.search_var = tk.StringVar()
        self.detail_vars = {}
        self.cli_var = tk.StringVar(value="")
        self.cli_display_map = {}
        self.cli_options = []
        self.status_var = tk.StringVar(value="")
        self.cli_combo = None
        self.sort_column = "created"
        self.sort_desc = True
        self.column_labels = {
            "title": "Title",
            "created": "Created",
            "updated": "Updated",
            "cwd": "CWD",
            "id": "Session ID",
        }
        self.sortable_columns = {"title", "created", "updated"}

        self.root.title("Codex Sessions")
        self.root.geometry("1100x680")
        self.root.minsize(900, 600)
        self.build_ui()
        self.load_settings()
        self.load_and_render()

    def build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        search_frame = tk.Frame(top, highlightthickness=1, highlightbackground="#c0c0c0")
        search_frame.pack(side=tk.LEFT, padx=8)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=46)
        search_entry.pack(side=tk.LEFT, padx=(6, 2), pady=2)
        search_entry.bind("<Return>", lambda _event: self.apply_filter())
        clear_btn = ttk.Button(search_frame, text="x", width=2, command=self.clear_filter)
        clear_btn.pack(side=tk.LEFT, padx=(0, 4), pady=2)

        ttk.Button(top, text="Search", command=self.apply_filter).pack(side=tk.LEFT)
        ttk.Button(top, text="Refresh", command=self.load_and_render).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned, padding=10)
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        columns = ("title", "created", "updated", "cwd", "id")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        self.update_sort_headings()
        self.tree.column("title", width=350)
        self.tree.column("created", width=120)
        self.tree.column("updated", width=120)
        self.tree.column("cwd", width=220)
        self.tree.column("id", width=120, anchor=tk.CENTER)
        self.tree.tag_configure("odd", background="#f5f5f5")

        scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_details())
        self.tree.bind("<Double-1>", lambda _event: self.resume_selected())

        ttk.Label(right, text="Title").pack(anchor=tk.W, pady=(0, 2))
        title_var = tk.StringVar(value="-")
        title_entry = ttk.Entry(right, textvariable=title_var)
        title_entry.pack(fill=tk.X, pady=(0, 6))
        title_entry.bind("<Return>", lambda _event: self.save_title_override())
        self.detail_vars["title"] = title_var

        title_buttons = ttk.Frame(right)
        title_buttons.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(title_buttons, text="Save Title", command=self.save_title_override).pack(side=tk.LEFT)
        ttk.Button(title_buttons, text="Reset Title", command=self.reset_title_override).pack(side=tk.LEFT, padx=6)

        detail_fields = [
            ("Session ID", "session_id"),
            ("Created", "created"),
            ("Updated", "updated"),
            ("CWD", "cwd"),
            ("Log File", "path"),
        ]
        for label, key in detail_fields:
            ttk.Label(right, text=label).pack(anchor=tk.W, pady=(0, 2))
            var = tk.StringVar(value="-")
            entry = ttk.Entry(right, textvariable=var, state="readonly")
            entry.pack(fill=tk.X, pady=(0, 8))
            self.detail_vars[key] = var

        ttk.Label(right, text="CLI").pack(anchor=tk.W, pady=(4, 2))
        self.cli_combo = ttk.Combobox(right, textvariable=self.cli_var, state="readonly")
        self.cli_combo.pack(fill=tk.X, pady=(0, 6))
        self.cli_combo.bind("<<ComboboxSelected>>", lambda _event: self.on_cli_selected())
        cli_buttons = ttk.Frame(right)
        cli_buttons.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(cli_buttons, text="Clear Default", command=self.clear_default_cli).pack(side=tk.LEFT)

        buttons = ttk.Frame(right)
        buttons.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(buttons, text="Resume", command=self.resume_selected).pack(fill=tk.X)
        ttk.Button(buttons, text="Copy Session ID", command=self.copy_session_id).pack(fill=tk.X, pady=4)
        ttk.Button(buttons, text="Open CWD", command=self.open_cwd).pack(fill=tk.X)
        ttk.Button(buttons, text="Open Log", command=self.open_log).pack(fill=tk.X, pady=4)

        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=(10, 4))
        status.pack(side=tk.BOTTOM, fill=tk.X)

    def load_and_render(self):
        if not self.sessions_dir.exists():
            messagebox.showwarning("Missing sessions", f"No sessions folder: {self.sessions_dir}")
            return
        self.title_overrides = load_title_overrides(self.titles_path)
        self.sessions = load_sessions(self.sessions_dir, self.title_overrides)
        self.session_map = {s.session_id: s for s in self.sessions}
        self.apply_filter()
        self.refresh_cli_options()

    def load_settings(self):
        self.settings = load_settings(self.settings_path)
        self.default_cli_pref = self.settings.get("default_cli")
        self.refresh_cli_options()

    def refresh_cli_options(self):
        self.cli_options = available_shells()
        default_opt = match_preferred_cli(self.default_cli_pref, self.cli_options)
        display, mapping = build_cli_display_options(self.cli_options, default_opt)
        self.cli_display_map = mapping
        if self.cli_combo is not None:
            self.cli_combo["values"] = display
        if default_opt:
            for label, opt in mapping.items():
                if opt == default_opt:
                    self.cli_var.set(label)
                    break
        else:
            if self.cli_var.get() and self.cli_var.get() not in display:
                self.cli_var.set("")

    def clear_filter(self):
        self.search_var.set("")
        self.apply_filter()

    def apply_filter(self, select_id=None):
        query = self.search_var.get().strip()
        self.tree.delete(*self.tree.get_children())
        shown = 0
        for session in self.get_sorted_sessions():
            if query and not matches_query(session.search_blob, query):
                continue
            tag = "odd" if shown % 2 else "even"
            self.tree.insert(
                "",
                tk.END,
                iid=session.session_id,
                values=(
                    session.title,
                    session.created_display,
                    session.updated_display,
                    session.cwd or "-",
                    session.short_id,
                ),
                tags=(tag,),
            )
            shown += 1
        if select_id and select_id in self.tree.get_children():
            self.tree.selection_set(select_id)
            self.tree.see(select_id)
        self.update_details()
        total = len(self.sessions)
        if query:
            self.status_var.set(f"Showing {shown} of {total} sessions for filter: {query}")
        else:
            self.status_var.set(f"Showing {shown} sessions")

    def get_sorted_sessions(self):
        key_map = {
            "title": lambda s: s.title.lower(),
            "created": lambda s: parse_iso(s.created_at) or datetime.min,
            "updated": lambda s: parse_iso(s.updated_at) or datetime.min,
        }
        key_func = key_map.get(self.sort_column, lambda s: s.title.lower())
        return sorted(self.sessions, key=key_func, reverse=self.sort_desc)

    def sort_by(self, column):
        if column not in self.sortable_columns:
            return
        if self.sort_column == column:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_column = column
            self.sort_desc = column in ("created", "updated")
        self.update_sort_headings()
        self.apply_filter()

    def update_sort_headings(self):
        for column, label in self.column_labels.items():
            text = label
            if column == self.sort_column:
                text += " v" if self.sort_desc else " ^"
            if column in self.sortable_columns:
                self.tree.heading(column, text=text, command=lambda c=column: self.sort_by(c))
            else:
                self.tree.heading(column, text=text)

    def get_selected_session(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.session_map.get(selection[0])

    def update_details(self):
        session = self.get_selected_session()
        if not session:
            for var in self.detail_vars.values():
                var.set("-")
            return
        self.detail_vars["title"].set(session.title)
        self.detail_vars["session_id"].set(session.session_id)
        self.detail_vars["created"].set(session.created_display)
        self.detail_vars["updated"].set(session.updated_display)
        self.detail_vars["cwd"].set(session.cwd or "-")
        self.detail_vars["path"].set(str(session.path))

    def save_title_override(self):
        session = self.get_selected_session()
        if not session:
            messagebox.showinfo("Save Title", "Select a session first.")
            return
        new_title = self.detail_vars["title"].get().strip()
        if not new_title:
            new_title = DEFAULT_TITLE
            self.detail_vars["title"].set(new_title)
        self.title_overrides[session.session_id] = new_title
        save_title_overrides(self.titles_path, self.title_overrides)
        session.title = new_title
        session.is_default_title = False
        session.search_blob = f"{session.title} {session.cwd} {session.session_id} {session.path}".lower()
        apply_untitled_numbers(self.sessions)
        self.apply_filter(select_id=session.session_id)

    def reset_title_override(self):
        session = self.get_selected_session()
        if not session:
            messagebox.showinfo("Reset Title", "Select a session first.")
            return
        if session.session_id in self.title_overrides:
            del self.title_overrides[session.session_id]
            save_title_overrides(self.titles_path, self.title_overrides)
        session.title = generate_title(session.path, session.session_id)
        session.is_default_title = session.title == DEFAULT_TITLE
        if session.is_default_title:
            apply_untitled_numbers(self.sessions)
        session.search_blob = f"{session.title} {session.cwd} {session.session_id} {session.path}".lower()
        self.detail_vars["title"].set(session.title)
        self.apply_filter(select_id=session.session_id)

    def resume_selected(self):
        session = self.get_selected_session()
        if not session:
            messagebox.showinfo("Resume", "Select a session first.")
            return
        options = available_shells()
        if not options:
            messagebox.showerror("No CLI found", "No available CLI shells were detected on this system.")
            return
        selected = match_preferred_cli(self.default_cli_pref, options)
        if not selected and self.default_cli_pref:
            messagebox.showinfo("Default CLI unavailable", "Saved CLI preference was not found. Select another CLI.")
        if not selected:
            selected = self.cli_display_map.get(self.cli_var.get())
        if not selected:
            messagebox.showinfo("Select CLI", "Select a CLI from the dropdown first.")
            return
        cmd = build_resume_command(selected, session.session_id, session.cwd)
        try:
            open_terminal(cmd)
        except FileNotFoundError:
            messagebox.showerror("Codex not found", "Could not find the `codex` command in PATH.")

    def on_cli_selected(self):
        display = self.cli_var.get()
        selected = self.cli_display_map.get(display)
        if not selected:
            return
        label, kind, exe = selected
        self.default_cli_pref = {"label": label, "kind": kind, "exe": exe}
        self.settings["default_cli"] = self.default_cli_pref
        save_settings(self.settings_path, self.settings)
        self.refresh_cli_options()

    def clear_default_cli(self):
        if "default_cli" in self.settings:
            del self.settings["default_cli"]
        self.default_cli_pref = None
        save_settings(self.settings_path, self.settings)
        self.refresh_cli_options()

    def copy_session_id(self):
        session = self.get_selected_session()
        if not session:
            messagebox.showinfo("Copy Session ID", "Select a session first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(session.session_id)
        self.root.update()

    def open_cwd(self):
        session = self.get_selected_session()
        if not session or not session.cwd:
            messagebox.showinfo("Open CWD", "No CWD available for this session.")
            return
        try:
            if os.name == "nt":
                os.startfile(session.cwd)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", session.cwd])
            else:
                subprocess.Popen(["xdg-open", session.cwd])
        except OSError:
            messagebox.showerror("Open CWD", "Could not open the session working directory.")

    def open_log(self):
        session = self.get_selected_session()
        if not session:
            messagebox.showinfo("Open Log", "Select a session first.")
            return
        try:
            if os.name == "nt":
                os.startfile(session.path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(session.path)])
            else:
                subprocess.Popen(["xdg-open", str(session.path)])
        except OSError:
            messagebox.showerror("Open Log", "Could not open the session log file.")


def parse_args():
    parser = argparse.ArgumentParser(description="Codex session browser")
    parser.add_argument("--sessions-dir", default=str(DEFAULT_SESSIONS_DIR))
    parser.add_argument("--titles-file", default="")
    parser.add_argument("--settings-file", default="")
    return parser.parse_args()


def main():
    args = parse_args()
    sessions_dir = None
    if args.sessions_dir:
        sessions_dir = resolve_sessions_dir_from_choice(args.sessions_dir) or Path(args.sessions_dir)
    else:
        config = load_app_config(app_config_path())
        configured = config.get("sessions_dir") if isinstance(config, dict) else None
        if configured:
            sessions_dir = Path(configured)
    if sessions_dir is None:
        sessions_dir = choose_codex_dir()
        if sessions_dir is None:
            return
    sessions_dir.mkdir(parents=True, exist_ok=True)
    ensure_manager_dirs(sessions_dir)
    save_app_config(app_config_path(), sessions_dir)
    titles_path = args.titles_file or str(default_titles_path(sessions_dir))
    settings_path = args.settings_file or str(default_settings_path(sessions_dir))
    root = tk.Tk()
    app = SessionApp(root, str(sessions_dir), titles_path, settings_path)
    root.mainloop()


if __name__ == "__main__":
    main()
