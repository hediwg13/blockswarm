# NEXUS MISSION CONTROL demo recorder
# - Edge(headless) + Playwright video capture (1440x900)
# - webm -> mp4 (H.264/yuv420p) via imageio-ffmpeg
import pathlib, subprocess
from playwright.sync_api import sync_playwright
import imageio_ffmpeg

BASE = pathlib.Path(r"C:\anam145\hackerton\front")
REC  = BASE / "_rec"
REC.mkdir(exist_ok=True)
OUT  = BASE / "nexus-demo.mp4"
URL  = (BASE / "index.html").as_uri()

DUR_MS = 25000  # boot(~0.7s) + full 22.1s cycle + next cycle intro

webm_path = None
with sync_playwright() as p:
    browser = p.chromium.launch(
        channel="msedge", headless=True,
        args=["--hide-scrollbars", "--force-color-profile=srgb"],
    )
    ctx = browser.new_context(
        viewport={"width": 1440, "height": 900},
        record_video_dir=str(REC),
        record_video_size={"width": 1440, "height": 900},
    )
    page = ctx.new_page()
    page.goto(URL)
    page.wait_for_timeout(DUR_MS)
    webm_path = pathlib.Path(page.video.path())
    ctx.close()
    browser.close()

print("captured:", webm_path, webm_path.stat().st_size, "bytes")

ff = imageio_ffmpeg.get_ffmpeg_exe()
subprocess.run(
    [ff, "-y", "-i", str(webm_path),
     "-r", "30", "-c:v", "libx264", "-pix_fmt", "yuv420p",
     "-crf", "18", "-preset", "medium", "-movflags", "+faststart", str(OUT)],
    check=True,
)
print("DONE:", OUT, OUT.stat().st_size, "bytes")
