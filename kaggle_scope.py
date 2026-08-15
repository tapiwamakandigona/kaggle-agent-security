import asyncio, sys
sys.path.insert(0,".")
from sdk.utils.browser import get_browser

async def main():
    b = await get_browser("madie", timeout_seconds=3600)
    page = b._require_page()
    url="https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks/code"
    await page.goto(url, wait_until="domcontentloaded", timeout=60000)
    await asyncio.sleep(5)
    print("URL:", page.url)
    print("TITLE:", await page.title())
    # look for a "New Notebook" button
    txt = await page.evaluate("() => document.body.innerText")
    for line in txt.splitlines():
        l=line.strip().lower()
        if any(k in l for k in ["new notebook","create","submit","sign in","log in","join","rules","accept"]):
            print("LINE:", line.strip()[:80])
    await page.screenshot(path="research/kaggle_code_tab.png", full_page=False)
    print("screenshot saved")

asyncio.run(main())
