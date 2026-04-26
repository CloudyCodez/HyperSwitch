import tkinter as tk

from .runtime import resource_path


BG = "#0b0f14"
PANEL = "#141a22"
BORDER = "#262f3a"
PANEL_ALT = "#101720"
CARD_EDGE = "#334155"
GRID = "#0f1722"
GREEN = "#2ce391"
RED = "#ff4d6d"
AMBER = "#ffb000"
ACCENT = "#3ddbd9"
ACCENT_SOFT = "#1f3f48"
BLUE = "#67b7ff"
ROSE = "#ff7aa2"
MUTED = "#6b7280"
WHITE = "#f2f4f7"
DIM = "#98a2b3"

MONO_SM = ("Consolas", 9)
MONO_MD = ("Consolas", 10)
MONO_LG = ("Consolas", 12, "bold")
MONO_HDR = ("Consolas", 15, "bold")


def apply_window_icon(window: tk.Tk | tk.Toplevel) -> None:
    png_path = resource_path("hyperswitch.png")
    ico_path = resource_path("hyperswitch.ico")

    try:
        window._hyper_switch_icon = tk.PhotoImage(file=png_path)
        window.iconphoto(True, window._hyper_switch_icon)
    except Exception:
        pass

    try:
        window.iconbitmap(ico_path)
    except Exception:
        pass


class ToggleRow:
    def __init__(self, parent: tk.Widget, title: str, on_toggle) -> None:
        self.on_toggle = on_toggle
        self._active: bool | None = None

        self._outer = tk.Frame(
            parent,
            bg=PANEL_ALT,
            highlightthickness=1,
            highlightbackground=CARD_EDGE,
        )
        self._outer.pack(fill="x", padx=20, pady=4)

        accent = tk.Frame(self._outer, bg=ACCENT, width=4)
        accent.pack(side="left", fill="y")

        left = tk.Frame(self._outer, bg=PANEL_ALT)
        left.pack(side="left", fill="both", expand=True, padx=14, pady=12)

        tk.Label(
            left,
            text=title,
            font=MONO_LG,
            fg=WHITE,
            bg=PANEL_ALT,
            anchor="w",
        ).pack(anchor="w")

        self._sub_lbl = tk.Label(
            left,
            text="",
            font=MONO_SM,
            fg=DIM,
            bg=PANEL_ALT,
            anchor="w",
            justify="left",
            wraplength=360,
        )
        self._sub_visible = False

        right = tk.Frame(self._outer, bg=PANEL_ALT, width=260)
        right.pack(side="right", padx=18, pady=12)

        self._status_lbl = tk.Label(
            right,
            text="reading...",
            font=("Consolas", 10, "bold"),
            fg=MUTED,
            bg=PANEL_ALT,
            anchor="e",
            justify="right",
            wraplength=280,
        )
        self._status_lbl.pack(anchor="e", pady=(0, 5))

        self._btn = tk.Button(
            right,
            text="WAIT",
            font=("Consolas", 9, "bold"),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=12,
            pady=5,
            fg=BG,
            bg=MUTED,
            activeforeground=BG,
            activebackground="#7d8796",
            highlightthickness=1,
            highlightbackground=BORDER,
            command=self._click,
        )
        self._btn.pack(anchor="e")

    def update(
        self,
        active: bool | None,
        active_label: str,
        inactive_label: str,
        btn_when_active: str,
        btn_when_inactive: str,
    ) -> None:
        self._active = active

        if active is None:
            self._status_lbl.config(text="UNKNOWN", fg=AMBER)
            self._btn.config(text="RETRY", bg=AMBER, activebackground="#cc8800")
            return

        if active:
            self._status_lbl.config(text=f"\u25cf  {active_label}", fg=GREEN)
            self._btn.config(
                text=btn_when_active,
                fg=GREEN,
                bg="#00221a",
                activebackground="#003328",
                highlightthickness=1,
                highlightbackground="#00553a",
            )
            return

        self._status_lbl.config(text=f"\u25cb  {inactive_label}", fg=RED)
        self._btn.config(
            text=btn_when_inactive,
            fg=RED,
            bg="#200010",
            activebackground="#300018",
            highlightthickness=1,
            highlightbackground="#550022",
        )

    def set_subtitle(self, text: str) -> None:
        if text:
            if not self._sub_visible:
                self._sub_lbl.pack(anchor="w", pady=(4, 0))
                self._sub_visible = True
            self._sub_lbl.config(text=text)
            return

        if self._sub_visible:
            self._sub_lbl.pack_forget()
            self._sub_visible = False

    def update_custom(
        self,
        status_text: str,
        status_fg: str,
        btn_text: str,
        btn_fg: str,
        btn_bg: str,
        btn_activebg: str,
        btn_highlight: str,
        btn_state: str = "normal",
        btn_cursor: str = "hand2",
        active_state: bool | None = None,
    ) -> None:
        self._active = active_state
        self._status_lbl.config(text=status_text, fg=status_fg)
        self._btn.config(
            text=btn_text,
            fg=btn_fg,
            bg=btn_bg,
            activebackground=btn_activebg,
            highlightthickness=1,
            highlightbackground=btn_highlight,
            state=btn_state,
            cursor=btn_cursor,
        )

    def show(self) -> None:
        self._outer.pack(fill="x", padx=20, pady=4)

    def hide(self) -> None:
        self._outer.pack_forget()

    def _click(self) -> None:
        self.on_toggle(self._active)
