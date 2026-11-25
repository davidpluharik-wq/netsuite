"""Animated photo-traced skull and crossbones made of scrambling glyphs.

Copied from the desktop system monitor (skull version #4). Use add_skull(parent, bg)
to pack one into a window; it animates itself until the window closes.
"""
import random
import string
import tkinter as tk

FONT_FAMILY = "Fira Code"
FG_COLOR = "#e6e8ee"
DIM_COLOR = "#7c8394"
WARN_COLOR = "#f0b84f"
HOT_COLOR = "#f0605a"

ANIM_MS = 120                    # skull animation frame time
SKULL_FONT = (FONT_FAMILY, 2, "bold")  # 2x4 px glyphs; the skull is a character texture
GLYPHS = string.ascii_letters + string.digits
SKULL_COLOR = "#aab1be"
SCRAMBLE = {"calm": 0.03, "busy": 0.10, "hot": 0.20}   # share of glyphs re-rolled per frame
GLITCH = {"calm": (0.02, 1), "busy": (0.6, 3), "hot": (0.9, 5)}  # (chance per frame, max rows jumping sideways)
CORRUPT = {"calm": 0, "busy": 1, "hot": 3}             # runs of glyphs turned into symbols per frame
EMBERS = {"calm": (0, 0), "busy": (0, 0.04), "hot": (0.10, 0.08)}  # share of glyphs glowing (red, amber)
SCAN_ROWS = {"calm": 2, "busy": 3, "hot": 4}
SYMBOLS = "#%&$@!?*+=/\\"
EMBER_COLOR = "#ff8a3d"
LOOK = [(0, 0), (0, 0), (-2, 0), (-2, 0), (0, 0), (2, 0), (2, 0), (0, 1), (0, 0), (0, -1)]


# Traced from the reference skull-and-crossbones photo: # bright glyph, + gray glyph, o eye socket.
SKULL_ART = """
                      +######++##++
                   ++++###+#########++
  #+###          #+#+####+#++##++##+####          ++###
 +##+++++       +#+++####+++++#+++++##+#++      +#+#++#+
##++#++#+#+    +###+##+++++#######++##+##++    ###+##+#+#
 +##++++###+  #######+##+#####++++###+#+###  +######++#+#
   +++++###+  +#+++++#++++##+##+++++++####++ +#+#+#+##+#
              ###+##+########+######+##+##+   +
              +#++##++#+#+#++#++#+##+##+#+#
              +#++#++##++####+##+#+##+#+++#
              +#+#+++++##++##+##+++#+oo+#
                ++ooooooooo+++oooooooooo#+
                +ooooooooo+#+#+ooooooooo+#
               +#+ooo+###++   ##+##oooo#++
          +##  ##++##++++##   +#+###+++#++   ++
 ##++#+#++++++   +++++#++++++#######++#+   #+#+#+######+
+++++#+#++#++        #+#########++++        +##+++###++++
 #+#+#####+            #+++##++#+#             +++++#++++
  ++#+#+                                         ++###
   +##+                                           ++#+
"""


def skull_mask(art=SKULL_ART):
    """0 = empty, 1 = bright glyph, 2 = eye socket, 3 = gray glyph."""
    lines = art.strip("\n").split("\n")
    width = max(len(line) for line in lines)
    return [[" #o+".index(ch) for ch in line.ljust(width)] for line in lines]


class Skull(tk.Text):
    """Skull and crossbones made of scrambling glyphs, with a scan line, roaming pupils and glitches."""

    def __init__(self, parent, bg):
        self.mask = skull_mask()
        self.rows, self.cols = len(self.mask), len(self.mask[0])
        cols = self.cols
        super().__init__(
            parent, width=cols, height=self.rows, font=SKULL_FONT, bg=bg, fg=SKULL_COLOR,
            bd=0, highlightthickness=0, padx=0, pady=0, wrap="none", cursor="arrow",
            selectbackground=bg, inactiveselectbackground=bg,
            selectforeground=SKULL_COLOR, exportselection=False, takefocus=0,
        )
        self.cells = [(r, c) for r in range(self.rows) for c in range(cols) if self.mask[r][c] in (1, 3)]
        self.gray_runs = []                                     # (row, start, end) spans of gray glyphs
        for r, row in enumerate(self.mask):
            c = 0
            while c < cols:
                if row[c] == 3:
                    start = c
                    while c < cols and row[c] == 3:
                        c += 1
                    self.gray_runs.append((r, start, c))
                c += 1
        self.glyph = {cell: random.choice(GLYPHS) for cell in self.cells}
        sockets = [(r, c) for r in range(self.rows) for c in range(cols) if self.mask[r][c] == 2]
        self.sockets = sockets
        self.eye_centers = []
        for side in (lambda c: c < cols // 2, lambda c: c >= cols // 2):
            pts = [(r, c) for r, c in sockets if side(c)]
            self.eye_centers.append((round(sum(r for r, _ in pts) / len(pts)),
                                     round(sum(c for _, c in pts) / len(pts))))
        self.frame = 0
        for tag in ("gray", "ember2", "ember", "scan", "eye"):   # later tags draw on top
            self.tag_configure(tag)
        self.tag_configure("gray", foreground=DIM_COLOR)
        self.tag_configure("ember2", foreground=WARN_COLOR)
        self.tag_configure("ember", foreground=EMBER_COLOR)
        self.config(state="disabled")

    def render(self, mood):
        """Lines for this frame, {tag: [(row, col)]} of colored cells, and {row: shift} of moved rows."""
        for cell in random.sample(self.cells, int(len(self.cells) * SCRAMBLE[mood])):
            self.glyph[cell] = random.choice(GLYPHS)
        lines = [[self.glyph.get((r, c), " ") for c in range(self.cols)] for r in range(self.rows)]
        tagged = {"eye": [], "ember": [], "ember2": []}

        for _ in range(CORRUPT[mood]):                          # corrupt a run of glyphs into symbols
            r, c = random.choice(self.cells)
            for cc in range(c, min(c + random.randint(3, 8), self.cols)):
                if self.mask[r][cc] in (1, 3):
                    lines[r][cc] = random.choice(SYMBOLS)

        red, amber = EMBERS[mood]
        tagged["ember"] = random.sample(self.cells, int(len(self.cells) * red))
        tagged["ember2"] = random.sample(self.cells, int(len(self.cells) * amber))

        if mood == "hot":                                       # burning eyes: whole sockets flicker
            for r, c in self.sockets:
                lines[r][c] = random.choice("@#%&*")
                tagged["eye"].append((r, c))
        elif self.frame % 50 not in (0, 1, 2):                  # roaming pupils, blink every ~6 s
            dc, dr = LOOK[(self.frame // 8) % len(LOOK)]
            for er, ec in self.eye_centers:
                r = er + dr
                for c in range(ec + dc - 1, ec + dc + 2):
                    if 0 <= r < self.rows and 0 <= c < self.cols and self.mask[r][c] == 2:
                        lines[r][c] = "@"
                        tagged["eye"].append((r, c))

        shake = random.choice((-1, 0, 0, 1)) if mood == "hot" else 0
        shifts = {r: shake for r in range(self.rows)} if shake else {}
        chance, most = GLITCH[mood]
        if random.random() < chance:
            for r in random.sample(range(self.rows), random.randint(1, most)):
                shifts[r] = shifts.get(r, 0) + random.choice((-4, -3, -2, -1, 1, 2, 3, 4))
        lines = ["".join(line) for line in lines]
        for r, shift in shifts.items():
            lines[r] = lines[r][shift:] + lines[r][:shift]
        return lines, tagged, shifts

    def step(self, mood):
        lines, tagged, shifts = self.render(mood)
        color = {"hot": HOT_COLOR, "busy": WARN_COLOR}.get(mood, FG_COLOR)
        self.tag_configure("scan", foreground=color)
        self.tag_configure("eye", foreground=color)
        self.config(state="normal")
        self.delete("1.0", "end")
        self.insert("1.0", "\n".join(lines))

        def col(r, c):                                          # where column c of row r ended up
            return (c - shifts.get(r, 0)) % self.cols

        # One tag_add call per tag (Tk accepts many ranges at once); per-range calls cost ~2x the CPU.
        spans = []
        for r, a, b in self.gray_runs:
            a2 = col(r, a)
            if a2 + (b - a) <= self.cols:                       # skip the rare run that wrapped
                spans += (f"{r + 1}.{a2}", f"{r + 1}.{a2 + b - a}")
        if spans:
            self.tag_add("gray", *spans)
        for tag, cells in tagged.items():
            if cells:
                idx = [f"{r + 1}.{col(r, c)}" for r, c in cells]
                self.tag_add(tag, *[i for x in idx for i in (x, x + "+1c")])
        scan = self.frame % (self.rows + 10) + 1                # +10: pause below the skull
        spans = [i for r in range(scan - SCAN_ROWS[mood] + 1, scan + 1) if 1 <= r <= self.rows
                 for i in (f"{r}.0", f"{r}.end")]
        if spans:
            self.tag_add("scan", *spans)
        self.config(state="disabled")
        self.frame += 1


def add_skull(parent, bg, **pack):
    """Pack an animated calm skull into parent (default: top-right corner) and keep it animating."""
    skull = Skull(parent, bg)
    first = parent.pack_slaves()
    skull.pack(**{"side": "top", "anchor": "ne", "padx": 12, "pady": (8, 0),
                  **({"before": first[0]} if first else {}), **pack})

    def tick():
        if skull.winfo_exists():
            skull.step("calm")
            skull.after(ANIM_MS * 2, tick)          # calm runs at half rate to save CPU, like the monitor
    tick()
    return skull
