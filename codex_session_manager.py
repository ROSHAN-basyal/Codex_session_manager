import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import customtkinter as ctk
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError as exc:
    ctk = None
    tk = None
    filedialog = None
    messagebox = None
    ttk = None
    TK_IMPORT_ERROR = exc
else:
    TK_IMPORT_ERROR = None


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


def sort_timestamp(value):
    dt = parse_iso(value)
    if not dt:
        return float("-inf")
    return dt.timestamp()


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
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home())
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / APP_CONFIG_DIRNAME / APP_CONFIG_FILENAME


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


def linux_terminal_candidates():
    return [
        ("x-terminal-emulator", lambda exe, shell_cmd: [exe, "-e"] + shell_cmd),
        ("gnome-terminal", lambda exe, shell_cmd: [exe, "--"] + shell_cmd),
        ("konsole", lambda exe, shell_cmd: [exe, "-e"] + shell_cmd),
        ("xfce4-terminal", lambda exe, shell_cmd: [exe, "-x"] + shell_cmd),
        ("tilix", lambda exe, shell_cmd: [exe, "-e"] + shell_cmd),
        ("alacritty", lambda exe, shell_cmd: [exe, "-e"] + shell_cmd),
        ("kitty", lambda exe, shell_cmd: [exe] + shell_cmd),
        ("xterm", lambda exe, shell_cmd: [exe, "-e"] + shell_cmd),
    ]


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


def build_terminal_command(shell, cwd):
    label, kind, exe = shell
    if os.name == "nt":
        if kind == "cmd":
            cmd_str = f'cd /d "{cwd}"' if cwd else ""
            return [exe, "/k", cmd_str] if cmd_str else [exe]
        if kind in ("powershell", "pwsh"):
            if cwd:
                cwd_literal = powershell_literal(cwd)
                ps_cmd = f"Set-Location -LiteralPath '{cwd_literal}'"
                return [exe, "-NoExit", "-Command", ps_cmd]
            return [exe, "-NoExit"]
        if kind == "gitbash":
            if cwd:
                cwd_literal = bash_quote(cwd)
                bash_cmd = f"cd {cwd_literal}; exec bash"
            else:
                bash_cmd = "exec bash"
            return [exe, "-c", bash_cmd]
    else:
        if cwd:
            cmd = f"cd {bash_quote(cwd)}; exec {bash_quote(exe)}"
        else:
            cmd = f"exec {bash_quote(exe)}"
        return [exe, "-c", cmd]
    return [exe]


def open_terminal(shell_cmd):
    if os.name == "nt":
        subprocess.Popen(shell_cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return
    for terminal_name, builder in linux_terminal_candidates():
        terminal = shutil.which(terminal_name)
        if terminal:
            subprocess.Popen(builder(terminal, shell_cmd))
            return
    raise RuntimeError("No supported terminal emulator was found. Install one such as gnome-terminal, konsole, kitty, xfce4-terminal, alacritty, or xterm.")


def open_with_default_app(target):
    if os.name == "nt":
        os.startfile(target)
        return
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(target)])
        return
    opener = shutil.which("xdg-open")
    if not opener:
        raise RuntimeError("`xdg-open` was not found. Install xdg-utils to open files and folders from the GUI.")
    subprocess.Popen([opener, str(target)])


def ensure_gui_runtime():
    if ctk is None:
        lines = ["CustomTkinter is not available in this Python runtime."]
        if sys.platform.startswith("linux"):
            lines.append("Install it with: pip install customtkinter")
            lines.append("Also ensure Tk is installed: sudo pacman -S tk (Arch) or sudo apt install python3-tk (Debian/Ubuntu)")
        elif sys.platform == "darwin":
            lines.append("Install it with: pip install customtkinter")
        else:
            lines.append("Install it with: pip install customtkinter")
        if TK_IMPORT_ERROR is not None:
            lines.append(f"Original import error: {TK_IMPORT_ERROR}")
        raise SystemExit("\n".join(lines))
    if os.name != "nt" and sys.platform != "darwin":
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            raise SystemExit("No graphical desktop session detected. Start the app with DISPLAY or WAYLAND_DISPLAY set.")


def apply_untitled_numbers(sessions):
    untitled = [s for s in sessions if s.is_default_title]
    untitled.sort(key=lambda s: sort_timestamp(s.created_at))
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
    sessions.sort(key=lambda s: sort_timestamp(s.created_at), reverse=True)
    return sessions


# ---------------------------------------------------------------------------
#  Themed colors helper — derives Treeview colors from current CTk mode
# ---------------------------------------------------------------------------

def _get_theme_colors():
    """Return a dict of context-aware colors based on current appearance mode."""
    mode = ctk.get_appearance_mode().lower()
    if mode == "dark":
        return {
            "bg": "#1a1b26",
            "panel": "#1e2030",
            "panel_alt": "#24273a",
            "field": "#2a2d3e",
            "border": "#363a4f",
            "text": "#cad3f5",
            "muted": "#6e738d",
            "accent": "#7aa2f7",
            "accent_hover": "#89b4fa",
            "accent_pressed": "#5d7cc7",
            "row_even": "#1e2030",
            "row_odd": "#24273a",
            "heading_bg": "#181926",
            "selected": "#3d59a1",
            "selected_fg": "#ffffff",
            "danger": "#f7768e",
            "danger_hover": "#ff9e9e",
            "success": "#9ece6a",
            "separator": "#363a4f",
        }
    else:
        return {
            "bg": "#eff1f5",
            "panel": "#ffffff",
            "panel_alt": "#e6e9ef",
            "field": "#dce0e8",
            "border": "#ccd0da",
            "text": "#4c4f69",
            "muted": "#8c8fa1",
            "accent": "#1e66f5",
            "accent_hover": "#4c82f8",
            "accent_pressed": "#1654d6",
            "row_even": "#ffffff",
            "row_odd": "#eff1f5",
            "heading_bg": "#e6e9ef",
            "selected": "#1e66f5",
            "selected_fg": "#ffffff",
            "danger": "#d20f39",
            "danger_hover": "#e63c5c",
            "success": "#40a02b",
            "separator": "#ccd0da",
        }


# ---------------------------------------------------------------------------
#  Font helper
# ---------------------------------------------------------------------------

def _pick_font():
    """Choose the best available font family."""
    if os.name == "nt":
        return "Segoe UI"
    for candidate in ["Inter", "Cantarell", "Noto Sans", "DejaVu Sans", "Liberation Sans"]:
        # We don't validate font availability here; Tk will fall back gracefully
        pass
    return "Sans"


# ---------------------------------------------------------------------------
#  SessionApp — the full GUI
# ---------------------------------------------------------------------------

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
        self.layout_mode = None
        self.left_min_width = 540
        self.right_min_width = 340
        self.breakpoint_width = self.left_min_width + self.right_min_width + 80
        self.center = None
        self.left_frame = None
        self.right_frame = None
        self.right_scroll_frame = None
        self.session_resume_glyph = "▶"

        self.font_family = _pick_font()
        self.colors = _get_theme_colors()

        self.root.title("Codex Sessions")
        self.root.geometry("1140x720")
        self.root.minsize(780, 580)

        self._style_treeview()
        self.build_ui()
        self.load_settings()
        self.load_and_render()
        self.root.bind("<Configure>", self.on_resize)

    # ------------------------------------------------------------------
    #  Style the ttk.Treeview to match CustomTkinter theme
    # ------------------------------------------------------------------

    def _style_treeview(self):
        c = self.colors
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(
            "Session.Treeview",
            background=c["panel"],
            fieldbackground=c["panel"],
            foreground=c["text"],
            rowheight=34,
            borderwidth=0,
            font=(self.font_family, 11),
        )
        style.map(
            "Session.Treeview",
            background=[("selected", c["selected"])],
            foreground=[("selected", c["selected_fg"])],
        )
        style.configure(
            "Session.Treeview.Heading",
            background=c["heading_bg"],
            foreground=c["muted"],
            font=(self.font_family, 10, "bold"),
            padding=(10, 8),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Session.Treeview.Heading",
            background=[("active", c["panel_alt"])],
            foreground=[("active", c["text"])],
        )

    # ------------------------------------------------------------------
    #  Build the entire UI
    # ------------------------------------------------------------------

    def build_ui(self):
        c = self.colors
        ff = self.font_family

        # ── Top bar ──────────────────────────────────────────────────
        top = ctk.CTkFrame(self.root, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(18, 0))

        # Header row
        header = ctk.CTkFrame(top, fg_color="transparent")
        header.pack(fill="x", pady=(0, 14))

        title_block = ctk.CTkFrame(header, fg_color="transparent")
        title_block.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            title_block,
            text="⚡ Codex Sessions",
            font=(ff, 22, "bold"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_block,
            text="Browse, rename, and resume your local session history",
            font=(ff, 12),
            text_color=c["muted"],
        ).pack(anchor="w", pady=(2, 0))

        ctk.CTkButton(
            header,
            text="↻  Refresh",
            command=self.load_and_render,
            width=100,
            height=34,
            corner_radius=8,
            font=(ff, 12, "bold"),
            fg_color=c["panel_alt"],
            hover_color=c["field"],
            text_color=c["text"],
        ).pack(side="right", pady=(4, 0))

        # ── Search bar ───────────────────────────────────────────────
        search_card = ctk.CTkFrame(top, corner_radius=12, fg_color=c["panel"], border_width=1, border_color=c["border"])
        search_card.pack(fill="x", pady=(0, 4))

        search_inner = ctk.CTkFrame(search_card, fg_color="transparent")
        search_inner.pack(fill="x", padx=14, pady=12)

        ctk.CTkLabel(
            search_inner,
            text="🔍  Search",
            font=(ff, 11, "bold"),
            text_color=c["muted"],
        ).pack(anchor="w", pady=(0, 8))

        search_row = ctk.CTkFrame(search_inner, fg_color="transparent")
        search_row.pack(fill="x")

        self.search_entry = ctk.CTkEntry(
            search_row,
            textvariable=self.search_var,
            placeholder_text="Type to filter by title, CWD, session ID, or path…",
            height=36,
            corner_radius=8,
            font=(ff, 12),
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.search_entry.bind("<Return>", lambda _e: self.apply_filter())

        ctk.CTkButton(
            search_row,
            text="Clear",
            command=self.clear_filter,
            width=70,
            height=36,
            corner_radius=8,
            font=(ff, 12),
            fg_color=c["panel_alt"],
            hover_color=c["field"],
            text_color=c["text"],
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            search_row,
            text="Search",
            command=self.apply_filter,
            width=80,
            height=36,
            corner_radius=8,
            font=(ff, 12, "bold"),
        ).pack(side="left")

        # ── Separator ────────────────────────────────────────────────
        sep = ctk.CTkFrame(self.root, height=1, fg_color=c["separator"])
        sep.pack(fill="x", padx=20, pady=(8, 0))

        # ── Center: table + detail panel ─────────────────────────────
        self.center = ctk.CTkFrame(self.root, fg_color="transparent")
        self.center.pack(fill="both", expand=True, padx=20, pady=(12, 8))

        # Left: sessions table card
        self.left_frame = ctk.CTkFrame(self.center, corner_radius=12, fg_color=c["panel"], border_width=1, border_color=c["border"])

        # Right: detail panel card
        self.right_frame = ctk.CTkFrame(self.center, corner_radius=12, fg_color=c["panel"], border_width=1, border_color=c["border"])

        # -- LEFT PANEL contents --
        left_inner = ctk.CTkFrame(self.left_frame, fg_color="transparent")
        left_inner.pack(fill="both", expand=True, padx=16, pady=14)

        ctk.CTkLabel(
            left_inner,
            text="Sessions",
            font=(ff, 13, "bold"),
            text_color=c["muted"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            left_inner,
            text="Double-click a row to resume it",
            font=(ff, 11),
            text_color=c["muted"],
        ).pack(anchor="w", pady=(2, 12))

        # Treeview (ttk — no CTk equivalent, but heavily styled)
        columns = ("created", "updated", "cwd", "id")
        tree_frame = tk.Frame(left_inner, bg=c["panel"], bd=0, highlightthickness=0)
        tree_frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings", selectmode="browse", style="Session.Treeview")
        self.update_sort_headings()
        self.tree.column("#0", width=260, minwidth=180, stretch=True)
        self.tree.column("created", width=130, minwidth=110, stretch=False)
        self.tree.column("updated", width=130, minwidth=110, stretch=False)
        self.tree.column("cwd", width=200, minwidth=140, stretch=True)
        self.tree.column("id", width=100, anchor="center", stretch=False)
        self.tree.tag_configure("even", background=c["row_even"])
        self.tree.tag_configure("odd", background=c["row_odd"])

        tree_scrollbar_kwargs = {
            "fg_color": "transparent",
            "button_color": c["panel_alt"],
            "button_hover_color": c["field"],
        }
        vscroll = ctk.CTkScrollbar(tree_frame, orientation="vertical", command=self.tree.yview, **tree_scrollbar_kwargs)
        hscroll = ctk.CTkScrollbar(tree_frame, orientation="horizontal", command=self.tree.xview, **tree_scrollbar_kwargs)
        self.tree.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.update_details())
        self.tree.bind("<Double-1>", lambda _e: self.resume_selected())
        self.tree.bind("<ButtonRelease-1>", self.on_tree_click_resume, add="+")

        # -- RIGHT PANEL contents --
        self.right_scroll_frame = ctk.CTkScrollableFrame(
            self.right_frame,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_fg_color="transparent",
            scrollbar_button_color=c["panel_alt"],
            scrollbar_button_hover_color=c["field"],
        )
        self.right_scroll_frame.pack(fill="both", expand=True, padx=8, pady=8)

        right_inner = ctk.CTkFrame(self.right_scroll_frame, fg_color="transparent")
        right_inner.pack(fill="both", expand=True, padx=8, pady=8)

        ctk.CTkLabel(
            right_inner,
            text="Session Details",
            font=(ff, 13, "bold"),
            text_color=c["muted"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            right_inner,
            text="Edit labels and launch the selected session",
            font=(ff, 11),
            text_color=c["muted"],
        ).pack(anchor="w", pady=(2, 14))

        # Title field (editable)
        ctk.CTkLabel(right_inner, text="Title", font=(ff, 11, "bold"), text_color=c["text"]).pack(anchor="w", pady=(0, 4))
        title_var = tk.StringVar(value="-")
        self.title_entry = ctk.CTkEntry(right_inner, textvariable=title_var, height=34, corner_radius=8, font=(ff, 12))
        self.title_entry.pack(fill="x", pady=(0, 8))
        self.title_entry.bind("<Return>", lambda _e: self.save_title_override())
        self.detail_vars["title"] = title_var

        title_buttons = ctk.CTkFrame(right_inner, fg_color="transparent")
        title_buttons.pack(fill="x", pady=(0, 14))

        ctk.CTkButton(
            title_buttons, text="💾  Save Title", command=self.save_title_override,
            height=32, corner_radius=8, font=(ff, 12),
            fg_color=c["accent"], hover_color=c["accent_hover"],
        ).pack(side="left")

        ctk.CTkButton(
            title_buttons, text="↺  Reset Title", command=self.reset_title_override,
            height=32, corner_radius=8, font=(ff, 12),
            fg_color=c["panel_alt"], hover_color=c["field"], text_color=c["text"],
        ).pack(side="left", padx=(8, 0))

        # Read-only detail fields
        detail_fields = [
            ("Session ID", "session_id"),
            ("Created", "created"),
            ("Updated", "updated"),
            ("CWD", "cwd"),
            ("Log File", "path"),
        ]
        for label, key in detail_fields:
            ctk.CTkLabel(right_inner, text=label, font=(ff, 11, "bold"), text_color=c["text"]).pack(anchor="w", pady=(0, 4))
            var = tk.StringVar(value="-")
            entry = ctk.CTkEntry(right_inner, textvariable=var, height=32, corner_radius=8, font=(ff, 11), state="disabled")
            entry.pack(fill="x", pady=(0, 10))
            self.detail_vars[key] = var

        # CLI selector
        sep2 = ctk.CTkFrame(right_inner, height=1, fg_color=c["separator"])
        sep2.pack(fill="x", pady=(4, 12))

        ctk.CTkLabel(right_inner, text="CLI Shell", font=(ff, 11, "bold"), text_color=c["text"]).pack(anchor="w", pady=(0, 4))
        self.cli_combo = ctk.CTkComboBox(
            right_inner,
            variable=self.cli_var,
            values=[],
            height=34,
            corner_radius=8,
            font=(ff, 12),
            state="readonly",
            command=lambda _v: self.on_cli_selected(),
        )
        self.cli_combo.pack(fill="x", pady=(0, 8))

        ctk.CTkButton(
            right_inner, text="Clear Default", command=self.clear_default_cli,
            height=28, corner_radius=6, font=(ff, 11),
            fg_color=c["panel_alt"], hover_color=c["field"], text_color=c["muted"],
        ).pack(anchor="w", pady=(0, 14))

        # Action buttons
        sep3 = ctk.CTkFrame(right_inner, height=1, fg_color=c["separator"])
        sep3.pack(fill="x", pady=(0, 12))

        ctk.CTkButton(
            right_inner, text="▶  Resume Session", command=self.resume_selected,
            height=38, corner_radius=8, font=(ff, 13, "bold"),
        ).pack(fill="x", pady=(0, 6))

        action_row1 = ctk.CTkFrame(right_inner, fg_color="transparent")
        action_row1.pack(fill="x", pady=(0, 6))

        ctk.CTkButton(
            action_row1, text="📋 Copy ID", command=self.copy_session_id,
            height=32, corner_radius=8, font=(ff, 11),
            fg_color=c["panel_alt"], hover_color=c["field"], text_color=c["text"],
        ).pack(side="left", fill="x", expand=True, padx=(0, 4))

        ctk.CTkButton(
            action_row1, text="📂 Open CWD", command=self.open_cwd,
            height=32, corner_radius=8, font=(ff, 11),
            fg_color=c["panel_alt"], hover_color=c["field"], text_color=c["text"],
        ).pack(side="left", fill="x", expand=True, padx=(4, 0))

        action_row2 = ctk.CTkFrame(right_inner, fg_color="transparent")
        action_row2.pack(fill="x")

        ctk.CTkButton(
            action_row2, text="🖥  CWD in Terminal", command=self.open_cwd_terminal,
            height=32, corner_radius=8, font=(ff, 11),
            fg_color=c["panel_alt"], hover_color=c["field"], text_color=c["text"],
        ).pack(side="left", fill="x", expand=True, padx=(0, 4))

        ctk.CTkButton(
            action_row2, text="📄 Open Log", command=self.open_log,
            height=32, corner_radius=8, font=(ff, 11),
            fg_color=c["panel_alt"], hover_color=c["field"], text_color=c["text"],
        ).pack(side="left", fill="x", expand=True, padx=(4, 0))

        self._bind_detail_scroll_events(right_inner)

        # ── Status bar ───────────────────────────────────────────────
        status_bar = ctk.CTkFrame(self.root, height=32, corner_radius=0, fg_color=c["heading_bg"])
        status_bar.pack(side="bottom", fill="x")

        self.status_label = ctk.CTkLabel(
            status_bar,
            textvariable=self.status_var,
            font=(ff, 11),
            text_color=c["muted"],
            anchor="w",
        )
        self.status_label.pack(side="left", padx=20, pady=6)

        self.apply_layout("horizontal")

    # ------------------------------------------------------------------
    #  Data loading
    # ------------------------------------------------------------------

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
            self.cli_combo.configure(values=display)
        if default_opt:
            for label, opt in mapping.items():
                if opt == default_opt:
                    self.cli_var.set(label)
                    break
        else:
            if self.cli_var.get() and self.cli_var.get() not in display:
                self.cli_var.set("")

    # ------------------------------------------------------------------
    #  Filter / sort
    # ------------------------------------------------------------------

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
                "end",
                iid=session.session_id,
                text=f"{self.session_resume_glyph}  {session.title}",
                values=(
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
            self.status_var.set(f"  Showing {shown} of {total} sessions  ·  filter: {query}")
        else:
            self.status_var.set(f"  {shown} sessions loaded")

    # ------------------------------------------------------------------
    #  Responsive layout
    # ------------------------------------------------------------------

    def on_resize(self, _event):
        width = self.root.winfo_width()
        mode = "vertical" if width < self.breakpoint_width else "horizontal"
        if mode != self.layout_mode:
            self.apply_layout(mode)

    def apply_layout(self, mode):
        self.layout_mode = mode
        self.left_frame.grid_forget()
        self.right_frame.grid_forget()
        for idx in range(2):
            self.center.grid_rowconfigure(idx, weight=0, minsize=0)
            self.center.grid_columnconfigure(idx, weight=0, minsize=0)
        if mode == "vertical":
            self.center.grid_columnconfigure(0, weight=1, minsize=self.left_min_width)
            self.center.grid_rowconfigure(0, weight=3, minsize=260)
            self.center.grid_rowconfigure(1, weight=2, minsize=260)
            self.left_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
            self.right_frame.grid(row=1, column=0, sticky="nsew")
        else:
            self.center.grid_rowconfigure(0, weight=1, minsize=400)
            self.center.grid_columnconfigure(0, weight=3, minsize=self.left_min_width)
            self.center.grid_columnconfigure(1, weight=1, minsize=self.right_min_width)
            self.left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            self.right_frame.grid(row=0, column=1, sticky="nsew")

    def _bind_detail_scroll_events(self, widget):
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            widget.bind(sequence, self._on_detail_mousewheel, add="+")
        for child in widget.winfo_children():
            self._bind_detail_scroll_events(child)

    def _on_detail_mousewheel(self, event):
        if self.right_scroll_frame is None:
            return None
        canvas = getattr(self.right_scroll_frame, "_parent_canvas", None)
        if canvas is None:
            return None

        if getattr(event, "num", None) == 4:
            delta = -1
        elif getattr(event, "num", None) == 5:
            delta = 1
        else:
            raw_delta = getattr(event, "delta", 0)
            if raw_delta == 0:
                return None
            steps = int(-raw_delta / 120)
            delta = steps if steps else (-1 if raw_delta > 0 else 1)

        canvas.yview_scroll(delta, "units")
        return "break"

    # ------------------------------------------------------------------
    #  Sorting
    # ------------------------------------------------------------------

    def get_sorted_sessions(self):
        key_map = {
            "title": lambda s: s.title.lower(),
            "created": lambda s: sort_timestamp(s.created_at),
            "updated": lambda s: sort_timestamp(s.updated_at),
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
                text += "  ▾" if self.sort_desc else "  ▴"
            column_id = "#0" if column == "title" else column
            if column in self.sortable_columns:
                self.tree.heading(column_id, text=text, command=lambda c=column: self.sort_by(c))
            else:
                self.tree.heading(column_id, text=text)

    def on_tree_click_resume(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id or self.tree.identify_column(event.x) != "#0":
            return None

        bbox = self.tree.bbox(item_id, "#0")
        if not bbox:
            return None

        if event.x <= bbox[0] + 24:
            self.tree.selection_set(item_id)
            self.tree.focus(item_id)
            self.resume_selected()
            return "break"
        return None

    # ------------------------------------------------------------------
    #  Detail panel
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    #  Title overrides
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    #  Resume / terminal actions
    # ------------------------------------------------------------------

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
        if not shutil.which("codex"):
            messagebox.showerror("Codex not found", "Could not find the `codex` command in PATH.")
            return
        cmd = build_resume_command(selected, session.session_id, session.cwd)
        try:
            open_terminal(cmd)
        except RuntimeError as exc:
            messagebox.showerror("Open Terminal", str(exc))

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
            open_with_default_app(session.cwd)
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("Open CWD", f"Could not open the session working directory.\n\n{exc}")

    def open_cwd_terminal(self):
        session = self.get_selected_session()
        if not session or not session.cwd:
            messagebox.showinfo("Open CWD in Terminal", "No CWD available for this session.")
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
        cmd = build_terminal_command(selected, session.cwd)
        try:
            open_terminal(cmd)
        except RuntimeError as exc:
            messagebox.showerror("Open Terminal", str(exc))

    def open_log(self):
        session = self.get_selected_session()
        if not session:
            messagebox.showinfo("Open Log", "Select a session first.")
            return
        try:
            open_with_default_app(session.path)
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("Open Log", f"Could not open the session log file.\n\n{exc}")


# ---------------------------------------------------------------------------
#  CLI entry point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Codex session browser")
    parser.add_argument("--sessions-dir", default="")
    parser.add_argument("--titles-file", default="")
    parser.add_argument("--settings-file", default="")
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_app_config(app_config_path())
    configured_dir = config.get("sessions_dir") if isinstance(config, dict) else None

    if args.sessions_dir:
        sessions_dir = resolve_sessions_dir_from_choice(args.sessions_dir) or Path(args.sessions_dir)
    elif configured_dir:
        sessions_dir = Path(configured_dir)
    elif DEFAULT_SESSIONS_DIR.exists():
        sessions_dir = DEFAULT_SESSIONS_DIR
    else:
        ensure_gui_runtime()
        sessions_dir = choose_codex_dir()
        if sessions_dir is None:
            return
    ensure_gui_runtime()
    sessions_dir = Path(sessions_dir)
    sessions_dir.mkdir(parents=True, exist_ok=True)
    ensure_manager_dirs(sessions_dir)
    save_app_config(app_config_path(), sessions_dir)
    titles_path = args.titles_file or str(default_titles_path(sessions_dir))
    settings_path = args.settings_file or str(default_settings_path(sessions_dir))

    # Set system-adaptive theme BEFORE creating the window
    ctk.set_appearance_mode("system")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    app = SessionApp(root, str(sessions_dir), titles_path, settings_path)
    root.mainloop()


if __name__ == "__main__":
    main()
