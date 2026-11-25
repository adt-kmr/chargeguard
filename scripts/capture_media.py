"""
Capture real footage and screenshots of the running system with Chrome (Playwright).

    python scripts/capture_media.py --url http://127.0.0.1:8010 --out media/raw

Produces
  <out>/session.webm            one continuous 1920x1080 recording of every demo act
  <out>/timeline.json           what happened when (seconds from recording start)
  <out>/shots/*.png             1920x1080 screenshots for the report (product name neutralised)

The dashboard, gateway and charger processes must already be running (python main.py).
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

W, H = 1920, 1080
# A real (GPU-accelerated) Chrome window placed off-screen: headless Chrome falls back to
# software WebGL (about 6 fps for the 3D scene), the off-screen window renders at about 45 fps.
LAUNCH = dict(headless=False, args=["--window-position=-2600,0", "--window-size=1920,1160", "--ignore-gpu-blocklist"])
NEUTRAL = """
(() => {
  const w = document.querySelector('.logo-word'); if (w) w.innerHTML = 'EV Charger Trust Node<span>Edge</span>';
  const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n; while ((n = walk.nextNode())) n.nodeValue = n.nodeValue.replace(/ChargeGuard['’]s/g, 'the node\\u2019s').replace(/ChargeGuard/g, 'the node');
  const c = document.querySelector('.scene-credit'); if (c) c.style.display = 'none';
})()
"""


class Timeline:
    def __init__(self):
        self.t0 = time.monotonic()
        self.events: list[dict] = []

    def mark(self, name: str, **kw):
        self.events.append({"t": round(time.monotonic() - self.t0, 2), "event": name, **kw})
        print(f"{self.events[-1]['t']:7.2f}s  {name}")


def run_act(page, tl: Timeline, preset: str | None = None, custom: dict | None = None, hold: float = 9.0):
    js = "document.querySelector('[data-preset=healthy]').click();"
    if preset:
        js = f"document.querySelector('[data-preset={preset}]').click();"
    if custom:
        js += "cfg.preset='custom';" + "".join(f"cfg.{k}={json.dumps(v)};" for k, v in custom.items())
    page.evaluate(js + "startVerification();")
    tl.mark("act_start", preset=preset or "custom", custom=custom)
    page.wait_for_timeout(int(hold * 1000))
    tl.mark("act_end", preset=preset or "custom")


def record(url: str, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", **LAUNCH)
        ctx = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=1,
                                  record_video_dir=str(out / "video"), record_video_size={"width": W, "height": H})
        page = ctx.new_page()
        tl = Timeline()
        page.goto(url)
        page.wait_for_function("window._carReady === true", timeout=60000)
        page.evaluate("window.sceneCtrl.autoRotate(true, 0.55)")
        tl.mark("ready")
        fps = page.evaluate("""() => new Promise(r => { let n=0; const t0=performance.now();
            const f=()=>{ n++; if (performance.now()-t0<2000) requestAnimationFrame(f); else r(n/2); }; requestAnimationFrame(f); })""")
        tl.mark("render_fps", fps=fps)
        page.wait_for_timeout(3000)

        run_act(page, tl, "healthy", hold=13)
        run_act(page, tl, "tampered", hold=9)
        run_act(page, tl, "vulnerable", hold=8)
        page.evaluate("openModal()"); tl.mark("modal_open")
        page.wait_for_timeout(2500)
        page.evaluate("document.querySelector('.modal-body').scrollTo({top: 9999, behavior: 'smooth'})")
        page.wait_for_timeout(2500)
        page.evaluate("checkSignature()"); page.wait_for_timeout(2000)
        page.evaluate("closeModal()"); tl.mark("modal_close")
        run_act(page, tl, "compromised", hold=20)
        run_act(page, tl, None, custom={"payment_qr": "malicious"}, hold=9)
        page.evaluate("document.querySelector('.ti-section').scrollIntoView({behavior:'smooth'})")
        page.evaluate(f"document.getElementById('tiInput').value = TI_EXAMPLES[0]")
        page.wait_for_timeout(800)
        page.evaluate("tiCheck()"); tl.mark("ti_sms")
        page.wait_for_timeout(4000)
        page.evaluate("tiExample(1)"); tl.mark("ti_link")
        page.wait_for_timeout(4000)
        page.evaluate("window.sceneCtrl.autoRotate(true, 1.4)")
        page.wait_for_timeout(5000)
        tl.mark("end")
        video_path = page.video.path()
        ctx.close()
        browser.close()
    Path(video_path).replace(out / "session.webm")
    (out / "timeline.json").write_text(json.dumps(tl.events, indent=2))


def shots(url: str, out: Path):
    d = out / "shots"
    d.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", **LAUNCH)
        page = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=1).new_page()
        page.goto(url)
        page.wait_for_function("window._carReady === true", timeout=60000)
        page.wait_for_timeout(1500)

        def snap(name):
            page.evaluate(NEUTRAL)
            page.wait_for_timeout(300)
            page.screenshot(path=str(d / f"{name}.png"))
            print("shot", name)

        snap("01_idle")

        def act(preset=None, custom=None, wait=7.5):
            js = f"document.querySelector('[data-preset={preset or 'healthy'}]').click();"
            if custom:
                js += "cfg.preset='custom';" + "".join(f"cfg.{k}={json.dumps(v)};" for k, v in custom.items())
            page.evaluate(js + "startVerification();")
            page.wait_for_timeout(int(wait * 1000))

        act("healthy", wait=2.6); snap("02_healthy_verifying")
        page.wait_for_timeout(5000); snap("03_healthy_green_monitoring")
        act("tampered"); snap("04_tampered_red")
        act("vulnerable"); snap("05_vulnerable_amber")
        page.evaluate("openModal()"); page.wait_for_timeout(1500); snap("06_evidence_modal")
        page.evaluate("document.querySelector('.modal-body').scrollTo({top: 9999})")
        page.evaluate("checkSignature()"); page.wait_for_timeout(1500); snap("07_evidence_signature")
        page.evaluate("closeModal()")
        act("compromised", wait=19); snap("08_compromised_isolated")
        act(custom={"payment_qr": "malicious"}, wait=8); snap("09_quishing_isolated")
        page.evaluate("document.querySelector('.ti-section').scrollIntoView()")
        page.evaluate("tiExample(0)"); page.wait_for_timeout(1500); snap("10_driver_safety_sms")
        page.evaluate("tiExample(1)"); page.wait_for_timeout(1500); snap("11_driver_safety_link")
        browser.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8010")
    ap.add_argument("--out", default="media/raw")
    ap.add_argument("--only", choices=["record", "shots"])
    a = ap.parse_args()
    out = Path(a.out)
    if a.only != "shots":
        record(a.url, out)
    if a.only != "record":
        shots(a.url, out)
