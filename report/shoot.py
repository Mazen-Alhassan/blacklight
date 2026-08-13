"""Headless screenshot of the report hero panel.

    python report/shoot.py docs/report.html docs/hero.png "#hero"

device_scale_factor=2 gives a retina image; cropping to #hero keeps the README
picture dense instead of mostly whitespace.
"""
import asyncio
import pathlib
import sys

from playwright.async_api import async_playwright

HTML = pathlib.Path(sys.argv[1]).resolve()
OUT = pathlib.Path(sys.argv[2]).resolve()
SEL = sys.argv[3] if len(sys.argv) > 3 else "#hero"


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1400, "height": 900},
                              device_scale_factor=2)
        await pg.goto(HTML.as_uri())
        await pg.wait_for_timeout(1000)
        el = await pg.query_selector(SEL)
        await (el or pg).screenshot(path=str(OUT))
        await b.close()
        print(f"wrote {OUT}")


asyncio.run(main())
