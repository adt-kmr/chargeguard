"""
Compose the 2-minute demo film (1920x1080, 30 fps, H.264 + AAC) from the real recording.

    python scripts/capture_media.py --only record           # media/raw/session.webm + timeline.json
    ffmpeg -i media/raw/session.webm -vf fps=30 -q:v 2 media/raw/frames/f_%05d.jpg
    python scripts/make_video.py --out deliverables/demo_video.mp4

Every product shot is real footage of the running system; title cards, captions and the
"further rounds" hardware explainers are drawn on top with PIL. The soundtrack is synthesised.
"""
from __future__ import annotations

import argparse
import math
import subprocess
import wave
from pathlib import Path

import imageio_ffmpeg
import numpy as np
from PIL import Image, ImageDraw, ImageFont

W, H, FPS = 1920, 1080, 30
FRAMES = Path("media/raw/frames")
CREAM, INK, INK2, CLAY, CLAY_D, CLAY_L = (250, 246, 239), (31, 27, 22), (91, 83, 72), (193, 95, 60), (162, 76, 45), (247, 233, 225)
GREEN, AMBER, RED, LINE = (47, 107, 79), (168, 106, 22), (179, 38, 30), (227, 217, 201)
FONTS = "C:/Windows/Fonts/"


def font(name, size):
    return ImageFont.truetype(FONTS + {"serif": "georgia.ttf", "serifb": "georgiab.ttf", "serifi": "georgiai.ttf",
                                       "sans": "calibri.ttf", "sansb": "calibrib.ttf", "sansl": "calibril.ttf"}[name], size)


def ease(x):
    x = min(1.0, max(0.0, x))
    return 1 - (1 - x) ** 3


def fade_in(t, start, dur=0.5):
    return ease((t - start) / dur)


# ── footage access ─────────────────────────────────────────────────────────
_cache: dict[int, Image.Image] = {}


def src_frame(sec: float) -> Image.Image:
    n = max(1, min(int(round(sec * FPS)) + 1, len(list_frames())))
    if n not in _cache:
        if len(_cache) > 8:
            _cache.clear()
        _cache[n] = Image.open(FRAMES / f"f_{n:05d}.jpg").convert("RGB")
    return _cache[n]


_frames_list: list | None = None


def list_frames():
    global _frames_list
    if _frames_list is None:
        _frames_list = sorted(FRAMES.glob("f_*.jpg"))
    return _frames_list


def zoomed(img: Image.Image, z: float, cx: float = 0.5, cy: float = 0.5) -> Image.Image:
    if z <= 1.001:
        return img.copy()
    cw, ch = W / z, H / z
    x0 = min(max(cx * W - cw / 2, 0), W - cw)
    y0 = min(max(cy * H - ch / 2, 0), H - ch)
    return img.resize((W, H), Image.BICUBIC, box=(x0, y0, x0 + cw, y0 + ch))


# ── overlays ───────────────────────────────────────────────────────────────
def text_w(d, s, f):
    return d.textlength(s, font=f)


def caption(img, t, start, kicker, line, color=CLAY, end=None):
    """Lower-third caption: dark ink card, clay bar, kicker + headline; slides in."""
    a = fade_in(t, start, 0.45)
    if end is not None:
        a *= 1 - fade_in(t, end - 0.35, 0.35)
    if a <= 0:
        return
    ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(ov)
    fk, fl = font("sansb", 24), font("serifb", 42)
    w = int(max(text_w(d, kicker.upper(), fk) * 1.1, text_w(d, line, fl)) + 84)
    x, y = 64 - int((1 - a) * 40), H - 190
    d.rectangle((x, y, x + w, y + 128), fill=INK + (int(236 * a),))
    d.rectangle((x, y, x + 8, y + 128), fill=color + (int(255 * a),))
    d.text((x + 40, y + 22), kicker.upper(), font=fk, fill=color + (int(255 * a),) if color != INK else CLAY + (int(255 * a),))
    d.text((x + 40, y + 56), line, font=fl, fill=CREAM + (int(255 * a),))
    img.paste(ov, (0, 0), ov)


def live_tag(img, t):
    d = ImageDraw.Draw(img)
    f = font("sansb", 22)
    s = "REAL RECORDING  ·  LIVE SYSTEM"
    tw = text_w(d, s, f)
    x, y = W - tw - 92, 1036
    blink = 0.55 + 0.45 * math.sin(t * 4)
    d.rounded_rectangle((x - 46, y - 10, W - 40, y + 30), 8, fill=INK)
    d.ellipse((x - 30, y + 4, x - 16, y + 18), fill=tuple(int(c * blink + 31 * (1 - blink)) for c in RED))
    d.text((x, y - 3), s, font=f, fill=CREAM)


def card_bg():
    img = Image.new("RGB", (W, H), CREAM)
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, W, 10), fill=CLAY)
    return img


def draw_text_anim(img, t, start, xy, s, f, fill, dur=0.6, dy=24, anchor="la"):
    a = fade_in(t, start, dur)
    if a <= 0:
        return
    ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(ov).text((xy[0], xy[1] + (1 - a) * dy), s, font=f, fill=fill + (int(255 * a),), anchor=anchor)
    img.paste(ov, (0, 0), ov)


def box(d, xy, title, sub=None, fill=(255, 255, 255), edge=LINE, tcol=INK, a=1.0, tf=None, sf=None):
    x0, y0, x1, y1 = xy
    d.rounded_rectangle(xy, 14, fill=fill, outline=edge, width=3)
    tf = tf or font("serifb", 34)
    sf = sf or font("sans", 25)
    cy = (y0 + y1) / 2 - (18 if sub else 0)
    d.text(((x0 + x1) / 2, cy), title, font=tf, fill=tcol, anchor="mm")
    if sub:
        for i, line in enumerate(sub.split("\n")):
            d.text(((x0 + x1) / 2, cy + 40 + i * 30), line, font=sf, fill=INK2, anchor="mm")


def arrow(d, a, b, col=CLAY, w=5, label=None):
    d.line((a, b), fill=col, width=w)
    ang = math.atan2(b[1] - a[1], b[0] - a[0])
    p = [b, (b[0] - 22 * math.cos(ang - 0.45), b[1] - 22 * math.sin(ang - 0.45)),
         (b[0] - 22 * math.cos(ang + 0.45), b[1] - 22 * math.sin(ang + 0.45))]
    d.polygon(p, fill=col)
    if label:
        d.text(((a[0] + b[0]) / 2, (a[1] + b[1]) / 2 - 26), label, font=font("sans", 24), fill=INK2, anchor="mm")


def fade_layer(base, top, a):
    return Image.blend(base, top, a) if 0 < a < 1 else (top if a >= 1 else base)


# ── scenes: each is (duration, render(t) -> Image) ─────────────────────────
def s_open(t):
    img = Image.new("RGB", (W, H), INK)
    f = font("serif", 66)
    lines = [("Public EV chargers are computers", 0.3), ("on someone else's network.", 1.6), ("Nobody checks them after installation.", 3.3)]
    for i, (s, st) in enumerate(lines):
        draw_text_anim(img, t, st, (160, 330 + i * 110), s, f, CREAM if i < 2 else CLAY, dur=0.8)
    return img


def s_threats(t):
    img = card_bg()
    d = ImageDraw.Draw(img)
    draw_text_anim(img, t, 0.1, (160, 120), "One plug. Six ways in.", font("serifb", 76), INK)
    items = [("Cloned charger", "steals an enrolled identity"), ("Tampered firmware", "modified after the vendor signed it"),
             ("Known CVEs", "signed, genuine and still exploitable"), ("Live compromise", "healthy at plug-in, hostile later"),
             ("Fake payment QR", "quishing on the charger's own screen"), ("Scam texts", "\"your charging account is suspended\"")]
    for i, (a, b) in enumerate(items):
        st = 0.6 + i * 0.35
        al = fade_in(t, st, 0.5)
        if al <= 0:
            continue
        cx, cy = 160 + (i % 3) * 540, 330 + (i // 3) * 290
        ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        o = ImageDraw.Draw(ov)
        yy = cy + (1 - al) * 30
        o.rounded_rectangle((cx, yy, cx + 500, yy + 240), 18, fill=(255, 255, 255, int(255 * al)), outline=LINE + (int(255 * al),), width=3)
        o.rectangle((cx, yy + 30, cx + 8, yy + 210), fill=RED + (int(255 * al),))
        o.text((cx + 44, yy + 50), f"0{i + 1}", font=font("sansb", 30), fill=CLAY + (int(255 * al),))
        o.text((cx + 44, yy + 96), a, font=font("serifb", 40), fill=INK + (int(255 * al),))
        o.text((cx + 44, yy + 158), b, font=font("sans", 27), fill=INK2 + (int(255 * al),))
        img.paste(ov, (0, 0), ov)
    return img


def s_title(t):
    img = Image.new("RGB", (W, H), CREAM)
    d = ImageDraw.Draw(img)
    a = fade_in(t, 0.0, 0.8)
    r = int(120 * a)
    d.ellipse((W / 2 - 120, 230 - 120 + 60, W / 2 + 120, 230 + 120 + 60), outline=LINE, width=14)
    d.arc((W / 2 - 120, 170, W / 2 + 120, 410), -90, -90 + 360 * a, fill=GREEN, width=14)
    if a >= 0.99:
        d.line((W / 2 - 48, 290, W / 2 - 12, 326, W / 2 + 56, 252), fill=GREEN, width=16, joint="curve")
    draw_text_anim(img, t, 0.5, (W / 2, 520), "Can this charger be trusted right now?", font("serifb", 78), INK, anchor="mm")
    draw_text_anim(img, t, 1.2, (W / 2, 630), "A verdict in five seconds. Enforced on the spot. Signed as evidence.", font("serif", 42), INK2, anchor="mm")
    draw_text_anim(img, t, 1.9, (W / 2, 730), "ONE ARM EDGE NODE  ·  NO CLOUD", font("sansb", 34), CLAY, anchor="mm")
    _ = r
    return img


def footage(src_start, src_end, dur, captions=(), zoom=(1.0, 1.0), focus=(0.5, 0.5), focus_end=None):
    def render(t):
        u = t / dur
        img = src_frame(src_start + u * (src_end - src_start))
        z = zoom[0] + (zoom[1] - zoom[0]) * ease(u)
        fx = focus if focus_end is None else tuple(focus[i] + (focus_end[i] - focus[i]) * ease(u) for i in range(2))
        img = zoomed(img, z, *fx)
        for c in captions:
            caption(img, t, *c)
        live_tag(img, t)
        return img
    return dur, render


_pair = None


def s_driver(t):
    global _pair
    if _pair is None:
        im = Image.open("media/report_img/driver_safety_llama_pair.png").convert("RGB")
        _pair = im.resize((int(im.width * 760 / im.height), 760), Image.LANCZOS)
    img = card_bg()
    a = fade_in(t, 0.0, 0.5)
    x = (W - _pair.width) // 2
    ImageDraw.Draw(img).rounded_rectangle((x - 14, 66, x + _pair.width + 14, 66 + 760 + 28), 16, fill=(255, 255, 255), outline=LINE, width=3)
    img.paste(_pair, (x, 80 + int((1 - a) * 20)))
    caption(img, t, 0.3, "Driver safety · on-device", "Flagged in milliseconds, explained by Llama on-device", CLAY)
    live_tag(img, t)
    return img


def s_numbers(t):
    img = card_bg()
    draw_text_anim(img, t, 0.1, (160, 130), "Measured, not promised.", font("serifb", 72), INK)
    stats = [("11 / 11", "attack scenarios caught end to end"), ("60", "automated tests passing"),
             ("< 100 ms", "real compute per verification"), ("0.942", "F1 on held-out scam messages"),
             ("12 µs", "per detector inference on ExecuTorch"), ("25 tok/s", "Llama 3.2 1B on ExecuTorch")]
    for i, (big, small) in enumerate(stats):
        cx, cy = 160 + (i % 3) * 540, 330 + (i // 3) * 280
        draw_text_anim(img, t, 0.5 + i * 0.3, (cx, cy), big, font("serifb", 92), CLAY)
        draw_text_anim(img, t, 0.7 + i * 0.3, (cx, cy + 120), small, font("sans", 32), INK2)
    return img


def further_header(img, t, n, title, label="FOR THE FURTHER ROUNDS", total=2, fill=CLAY):
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((160, 80, 640, 132), 26, fill=fill)
    d.text((400, 106), label, font=font("sansb", 26), fill=(255, 255, 255), anchor="mm")
    if n:
        d.text((680, 106), f"{n} / {total}", font=font("sansb", 26), fill=INK2, anchor="lm")
    draw_text_anim(img, t, 0.1, (160, 170), title, font("serifb", 62), INK)


def s_hw_node(t):
    img = card_bg()
    further_header(img, t, 1, "The node goes inline on a Raspberry Pi 5")
    d = ImageDraw.Draw(img)
    a = fade_in(t, 0.5, 0.6)
    if a > 0:
        box(d, (160, 420, 560, 640), "EV charger", "OCPP agent · payment screen\nverified boot · TPM", fill=CLAY_L, edge=CLAY)
        box(d, (760, 380, 1240, 680), "Edge trust node", "Raspberry Pi 5 · 4× Cortex-A76\nSPI TPM 2.0 · two-port bridge\nnftables enforcement", fill=(255, 255, 255), edge=CLAY)
        box(d, (1440, 420, 1800, 640), "Site network", "operator backend\ncompany LAN")
        arrow(d, (560, 530), (760, 530), label="Ethernet")
        arrow(d, (1240, 530), (1440, 530), label="only if trusted")
    draw_text_anim(img, t, 1.4, (160, 780), "Every packet and every OCPP frame physically passes the node, so it judges what it sees,", font("sans", 36), INK2)
    draw_text_anim(img, t, 1.7, (160, 830), "not what the charger reports. Its own TPM signs every evidence report.", font("sans", 36), INK2)
    return img


def s_hw_boot(t):
    img = card_bg()
    further_header(img, t, 2, "Measured boot on the charger controller")
    d = ImageDraw.Draw(img)
    steps = [("Boot ROM", "immutable"), ("Bootloader", "MCUboot / wolfBoot"), ("Charger firmware", "OCPP + metering"), ("TPM quote", "signed PCR + nonce")]
    for i, (a_, b_) in enumerate(steps):
        al = fade_in(t, 0.5 + i * 0.4, 0.4)
        if al <= 0:
            continue
        x = 160 + i * 410
        box(d, (x, 420, x + 340, 620), a_, b_, fill=CLAY_L if i == 3 else (255, 255, 255), edge=CLAY if i == 3 else LINE,
            tf=font("serifb", 32))
        if i:
            arrow(d, (x - 66, 520), (x - 4, 520))
    draw_text_anim(img, t, 2.3, (160, 690), "PCR  =  SHA-256( PCR  ||  SHA-256(next stage) )", font("serifb", 44), CLAY_D)
    draw_text_anim(img, t, 2.7, (160, 790), "A Cortex-M controller extends each boot stage into its TPM. At every plug-in the node sends a", font("sans", 36), INK2)
    draw_text_anim(img, t, 3.0, (160, 840), "fresh nonce and checks the signed quote: tampered code cannot fake the measurement.", font("sans", 36), INK2)
    return img


def s_hw_llama(t):
    img = card_bg()
    further_header(img, t, 0, "Llama 3.2 explains every verdict, on-device", label="BUILT · RUNNING NOW", fill=GREEN)
    d = ImageDraw.Draw(img)
    a = fade_in(t, 0.5, 0.6)
    if a > 0:
        box(d, (160, 400, 560, 620), "Verified facts", "verdict · failed checks\nCVEs · anomalies", fill=(255, 255, 255))
        box(d, (720, 370, 1200, 650), "Llama 3.2 1B", "SpinQuant 4-bit · 1.08 GB\nExecuTorch · XNNPACK\n~25 tokens/s · 1.8 GB RAM", fill=CLAY_L, edge=CLAY)
        box(d, (1360, 400, 1800, 620), "Checked, then shown", "rejected if it contradicts\nthe evidence", fill=(255, 255, 255))
        arrow(d, (560, 510), (720, 510))
        arrow(d, (1200, 510), (1360, 510))
    draw_text_anim(img, t, 1.4, (160, 740), "Llama writes the explanation; remediation steps stay with grounded rules. An explanation that", font("sans", 36), INK2)
    draw_text_anim(img, t, 1.7, (160, 790), "invents a CVE or calls a phishing link safe is rejected. Next: measure it on the Pi 5's Cortex-A76.", font("sans", 36), INK2)
    return img


def s_why(t):
    img = card_bg()
    draw_text_anim(img, t, 0.1, (160, 130), "Not four tools. One verdict.", font("serifb", 76), INK)
    rows = [("Firmware scanners", "offline, in a lab"), ("Remote attestation", "built for data-centre servers"),
            ("Network IDS", "blind to firmware provenance"), ("Charging backends", "watch uptime, not trust")]
    for i, (a_, b_) in enumerate(rows):
        draw_text_anim(img, t, 0.5 + i * 0.25, (160, 300 + i * 80), a_, font("serifb", 40), INK2)
        draw_text_anim(img, t, 0.6 + i * 0.25, (620, 306 + i * 80), b_, font("sans", 36), INK2)
    draw_text_anim(img, t, 1.8, (160, 680), "Ours: identity + firmware + CVEs + live behaviour + enforcement", font("serifb", 46), CLAY_D)
    draw_text_anim(img, t, 2.1, (160, 750), "+ signed compliance evidence + driver protection, on one Arm node.", font("serifb", 46), CLAY_D)
    return img


def s_end(t):
    img = Image.new("RGB", (W, H), INK)
    draw_text_anim(img, t, 0.2, (W / 2, 430), "Plug in. Know in five seconds.", font("serifb", 92), CREAM, anchor="mm")
    draw_text_anim(img, t, 0.9, (W / 2, 560), "Trust for every EV charger, verified at the edge.", font("serif", 46), (210, 200, 185), anchor="mm")
    draw_text_anim(img, t, 1.5, (W / 2, 680), "ARM EDGE AI  ·  EXECUTORCH  ·  LLAMA 3.2  ·  NO CLOUD", font("sansb", 32), CLAY, anchor="mm")
    return img


def build():
    # Source times come from media/raw/timeline.json of the recording.
    return [
        (6.5, s_open),
        (7.0, s_threats),
        (5.0, s_title),
        footage(8.6, 22.2, 14.0, captions=[
            (0.6, "Identity", "TPM attestation over OCPP: genuine charger", CLAY, 3.3),
            (3.4, "Integrity · Known weaknesses", "Signed firmware, measured boot, CVE audit", CLAY, 6.6),
            (6.7, "Live behaviour", "Traffic matches this charger's baseline", CLAY, 9.4),
            (9.5, "Verdict in 5.0 s", "Green. Charging 7.2 kW, and still watching.", GREEN, None)],
            zoom=(1.0, 1.12), focus=(0.38, 0.45)),
        footage(22.25, 31.25, 8.0, captions=[(1.6, "Tampered firmware", "Genuine device, modified image: charging refused", RED, None)],
                zoom=(1.12, 1.0), focus=(0.38, 0.45)),
        footage(31.28, 39.3, 7.0, captions=[(1.4, "Authentic but vulnerable", "Signed, genuine, and 5 real CVEs: amber + the fix", AMBER, None)]),
        footage(39.3, 46.5, 6.0, captions=[(0.6, "Signed evidence", "Mapped to 5 standards. Ed25519 signature, verified.", CLAY, None)],
                zoom=(1.0, 1.15), focus=(0.5, 0.5)),
        footage(46.55, 66.55, 13.0, captions=[
            (0.4, "Live compromise", "Green at plug-in. Then it starts scanning the LAN...", CLAY, 6.4),
            (6.5, "Mid-session", "Remote stop + quarantine, in under a second", RED, None)]),
        footage(66.58, 75.59, 7.0, captions=[(1.0, "Quishing", "Fake payment QR on the screen: charger isolated", RED, None)]),
        footage(76.4, 79.4, 3.0, zoom=(1.0, 1.6), focus=(0.9, 0.6)),
        (5.0, s_driver),
        (6.5, s_numbers),
        (7.5, s_hw_llama),
        (7.0, s_hw_node),
        (7.5, s_hw_boot),
        (5.5, s_why),
        (4.5, s_end),
    ]


# ── soundtrack ─────────────────────────────────────────────────────────────
def soundtrack(path: Path, total: float, cuts: list[float], sr=48000):
    n = int(total * sr)
    t = np.arange(n) / sr
    out = np.zeros(n)
    chords = [[57, 60, 64, 69], [53, 57, 60, 65], [48, 55, 60, 64], [55, 59, 62, 67]]  # Am F C G
    seg = 8.0
    for k in range(int(total / seg) + 1):
        a, b = int(k * seg * sr), min(n, int((k + 1) * seg * sr + 1.5 * sr))
        if a >= n:
            break
        tt = t[a:b] - k * seg
        env = np.minimum(1, tt / 1.6) * np.exp(-np.maximum(0, tt - seg) * 2.5)
        for m in chords[k % 4]:
            f = 440 * 2 ** ((m - 69) / 12)
            for det in (-0.12, 0.12):
                out[a:b] += 0.035 * env * (np.sin(2 * np.pi * f * (1 + det / 100) * tt) + 0.3 * np.sin(4 * np.pi * f * tt))
        root = 440 * 2 ** ((chords[k % 4][0] - 12 - 69) / 12)
        out[a:b] += 0.06 * env * np.sin(2 * np.pi * root * tt)
    # soft pulse, 96 bpm, after the opening
    beat = 60 / 96
    for bt in np.arange(13.5, total - 4, beat):
        a = int(bt * sr); L = int(0.25 * sr)
        if a + L >= n:
            break
        tt = np.arange(L) / sr
        out[a:a + L] += 0.10 * np.exp(-tt * 18) * np.sin(2 * np.pi * (52 + 40 * np.exp(-tt * 30)) * tt)
        h = int((bt + beat / 2) * sr)
        if h + 2000 < n:
            out[h:h + 2000] += 0.012 * np.random.default_rng(int(bt * 10)).standard_normal(2000) * np.exp(-np.arange(2000) / 300)
    # rising whoosh into each cut
    rng = np.random.default_rng(7)
    for c in cuts:
        L = int(0.6 * sr); a = int(c * sr) - L
        if a < 0 or a + L >= n:
            continue
        noise = np.convolve(rng.standard_normal(L), np.ones(40) / 40, mode="same")
        out[a:a + L] += 0.05 * noise * np.linspace(0, 1, L) ** 2
    out *= np.minimum(1, t / 2.0) * np.minimum(1, (total - t) / 3.0)
    out = out / (np.max(np.abs(out)) + 1e-9) * 0.5
    st = np.stack([out, np.roll(out, 240)], axis=1)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2); w.setsampwidth(2); w.setframerate(sr)
        w.writeframes((st * 32767).astype(np.int16).tobytes())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="deliverables/demo_video.mp4")
    ap.add_argument("--preview", type=float, nargs="*", help="only write PNG stills at these output times")
    a = ap.parse_args()
    scenes = build()
    starts, acc = [], 0.0
    for d_, _ in scenes:
        starts.append(acc); acc += d_
    total = acc
    print(f"total {total:.1f} s, {len(scenes)} scenes")
    XF = 0.4

    def frame_at(T):
        i = max(k for k, s in enumerate(starts) if s <= T + 1e-9) if T < total else len(scenes) - 1
        d_, r = scenes[i]
        img = r(T - starts[i])
        nxt = starts[i] + d_
        if i + 1 < len(scenes) and T > nxt - XF:
            img = Image.blend(img, scenes[i + 1][1](0.0), (T - (nxt - XF)) / XF)
        if T < 0.6:
            img = Image.blend(Image.new("RGB", (W, H), (0, 0, 0)), img, T / 0.6)
        return img

    if a.preview:
        for T in a.preview:
            frame_at(T).save(f"media/preview_{T:05.1f}.png")
        return

    out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    wav = out.with_suffix(".wav")
    soundtrack(wav, total, starts[1:])
    cmd = [imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-v", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
           "-r", str(FPS), "-i", "-", "-i", str(wav), "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-pix_fmt", "yuv420p",
           "-profile:v", "high", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", "-shortest", str(out)]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    nf = int(round(total * FPS))
    for k in range(nf):
        p.stdin.write(frame_at(k / FPS).tobytes())
        if k % 300 == 0:
            print(f"frame {k}/{nf}")
    p.stdin.close(); p.wait()
    wav.unlink()
    print("wrote", out)


if __name__ == "__main__":
    main()
