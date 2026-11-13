#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Бот за автоматично следене на цени на уреди само от надеждни магазини с физически обекти в София
и софийски магазини за уреди с транспортни дефекти (Точка 3 от task.txt).

- Проверява цените 2 пъти дневно (сутрин 08:30 и следобед 16:30).
- Работи постоянно в облака (GitHub Actions) независимо дали компютърът е включен.
- Включва автоматично преминаване през Cloudflare Turnstile (за Technovision и Зора).
- Изпраща имейл при ВСЯКА промяна на цената (както намаление ↓, така и покачване ↑).
- Предпазва от лъжливи намаления по Черните петъци чрез сравнение със средните цени от Точка 2.
"""

import argparse
import asyncio
import csv
import datetime
import json
import os
import re
import smtplib
import sys
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    from curl_cffi import requests as cffi_requests
    HAS_CFFI = True
except ImportError:
    HAS_CFFI = False

try:
    import nodriver as uc
    HAS_NODRIVER = True
except ImportError:
    HAS_NODRIVER = False

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
STATE_PATH = BASE_DIR / "price_state.json"
HISTORY_CSV_PATH = BASE_DIR / "price_history.csv"
REPORT_MD_PATH = BASE_DIR / "latest_report.md"
ENV_PATH = BASE_DIR / ".env"

BGN_TO_EUR = 1.95583

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "bg-BG,bg;q=0.9,en;q=0.8",
}

CLOUDFLARE_DOMAINS = ("technovision.bg", "zora.bg")


def load_dotenv_if_present(env_path: Path) -> None:
    """Зарежда променливи от локален .env файл, ако съществува."""
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def _interleave_by_host(urls: list[str]) -> list[str]:
    """Пренарежда URL-ите round-robin по домейн, за да не се натоварва един магазин с поредни/паралелни заявки."""
    buckets: dict[str, deque[str]] = defaultdict(deque)
    seen: set[str] = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        host = urlparse(u).netloc.lower()
        buckets[host].append(u)
    ordered: list[str] = []
    while any(buckets.values()):
        for host in list(buckets.keys()):
            if buckets[host]:
                ordered.append(buckets[host].popleft())
    return ordered


def is_cf_challenge(html: str) -> bool:
    """Проверява дали HTML съдържанието все още е Cloudflare / Turnstile междинна проверка."""
    if not html:
        return False
    low = html.lower()
    return any(
        m in low
        for m in (
            "<title>just a moment",
            "<title>един момент",
            "window._cf_chl_opt",
            "/cdn-cgi/challenge-platform",
            "challenge-platform",
            "cf-browser-verification",
            "cf-turnstile",
            "enable javascript and cookies to continue",
            "verify you are human",
        )
    )


def _extract_title_snippet(html: str) -> str:
    """Връща съкратеното заглавие (<title>) от HTML за диагностика в логовете."""
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:70]


def is_hard_waf_block(html: str) -> bool:
    """Разпознава твърд HTTP/WAF отказ (403/Access Denied/503) без интерактивен Cloudflare Turnstile."""
    if not html:
        return False
    if is_cf_challenge(html):
        return False
    low = html.lower()
    return any(
        marker in low
        for marker in (
            "<title>403 forbidden</title>",
            "<title>access denied</title>",
            "<title>attention required! | cloudflare</title>",
            "<title>emag captcha</title>",
            "access to this page has been denied",
            "sorry, you have been blocked",
            "you don't have permission to access",
            "error 1020",
            "black friday 2026 в emag.bg и шоурум започва сутринта",
        )
    )


async def _read_tab_state(page) -> tuple[str, str, str]:
    """Бързо извлича (href, readyState, html) през CDP Runtime.evaluate без тежка DOM сериализация."""
    try:
        ro_meta, err_meta = await asyncio.wait_for(
            page.send(
                uc.cdp.runtime.evaluate(
                    expression="JSON.stringify({href: location.href || '', ready: document.readyState || ''})",
                    return_by_value=True,
                )
            ),
            timeout=4,
        )
        href = ""
        ready = ""
        if not err_meta and ro_meta and ro_meta.value:
            meta = json.loads(ro_meta.value)
            href = meta.get("href", "")
            ready = meta.get("ready", "")
        ro_html, err_html = await asyncio.wait_for(
            page.send(
                uc.cdp.runtime.evaluate(
                    expression="document.documentElement ? document.documentElement.outerHTML : ''",
                    return_by_value=True,
                )
            ),
            timeout=5,
        )
        if not err_html and ro_html and isinstance(ro_html.value, str):
            return href, ready, ro_html.value
    except Exception:
        pass
    try:
        html_fallback = await asyncio.wait_for(page.get_content(), timeout=5)
        return "", "", html_fallback or ""
    except Exception:
        return "", "", ""


async def _fetch_single_cf_page(browser, u: str) -> str | None:
    """Отваря страница в Chrome, изчаква зареждането на DOM и кликва Cloudflare Turnstile САМО при реален challenge."""
    target_host = urlparse(u).netloc.lower().replace("www.", "")
    before_href = ""
    try:
        first_tab = next((t for t in browser.targets if t.target.type_ == "page"), None)
        if first_tab is not None:
            before_href, _, _ = await _read_tab_state(first_tab)
    except Exception:
        pass

    page = await browser.get(u)
    last_html = None
    complete_without_price_count = 0
    cf_verify_attempts = 0

    for poll_idx in range(10):
        await page.sleep(1.2 if poll_idx == 0 else 1.3)
        cur_href, ready_state, html = await _read_tab_state(page)
        if not html:
            continue

        if cur_href:
            cur_host = urlparse(cur_href).netloc.lower().replace("www.", "")
            if cur_href == "about:blank" or (cur_host and target_host not in cur_host and cur_host not in target_host):
                continue
            if before_href and before_href != u and cur_href == before_href and poll_idx < 4:
                continue

        last_html = html
        if is_hard_waf_block(last_html):
            return last_html

        if is_cf_challenge(last_html):
            complete_without_price_count = 0
            if cf_verify_attempts < 2:
                cf_verify_attempts += 1
                try:
                    await page.sleep(1.0)
                    await asyncio.wait_for(page.verify_cf(), timeout=8)
                    await page.sleep(1.5)
                except Exception:
                    pass
            continue

        p_check, _, _, in_stock, stock_reason = extract_price_and_old_price(last_html, u)
        if (p_check is not None or not in_stock) and stock_reason != "EMAG_PAGE_INCOMPLETE":
            return last_html

        if ready_state == "complete" and len(last_html) > 1000:
            complete_without_price_count += 1
            if complete_without_price_count >= 5:
                return last_html

    if last_html and is_cf_challenge(last_html):
        return None
    return last_html


async def fetch_cloudflare_pages_batch(urls: list[str]) -> dict[str, str]:
    """Отваря защитените страници чрез реален Google Chrome (nodriver + verify_cf())."""
    results = {}
    if not urls or not HAS_NODRIVER:
        return results
    browser = None
    chrome_proc = None
    try:
        linux_chrome = "/usr/bin/google-chrome"
        if sys.platform.startswith("linux") and Path(linux_chrome).exists():
            import socket
            import subprocess
            import tempfile
            import time

            os.environ["DBUS_SESSION_BUS_ADDRESS"] = "/dev/null"
            for launch_attempt in range(1, 3):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", 0))
                    debug_port = s.getsockname()[1]

                profile_dir = tempfile.mkdtemp(prefix="uc_chrome_")
                stderr_path = Path(profile_dir) / "chrome_stderr.log"
                chrome_cmd = [
                    linux_chrome,
                    f"--remote-debugging-port={debug_port}",
                    f"--user-data-dir={profile_dir}",
                    "--remote-allow-origins=*",
                    "--no-first-run",
                    "--no-service-autorun",
                    "--no-default-browser-check",
                    "--homepage=about:blank",
                    "--no-pings",
                    "--password-store=basic",
                    "--disable-infobars",
                    "--disable-breakpad",
                    "--disable-dev-shm-usage",
                    "--disable-session-crashed-bubble",
                    "--disable-search-engine-choice-screen",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-domain-reliability",
                    "--disable-sync",
                    "--metrics-recording-only",
                    "--disable-features=IsolateOrigins,site-per-process,SecretPortalKeyProvider,UseFreedesktopSecretKeyProvider,OptimizationHints,MediaRouter,Translate",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--window-size=1280,960",
                    "about:blank",
                ]
                stderr_handle = open(stderr_path, "wb")
                chrome_proc = subprocess.Popen(
                    chrome_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_handle,
                    env=os.environ.copy(),
                )
                stderr_handle.close()
                ready = False
                for _ in range(40):
                    if chrome_proc.poll() is not None:
                        err_out = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
                        print(f"  ⚠️ Chrome процесът спря преждевременно (опит {launch_attempt}): {err_out[:400]}")
                        break
                    try:
                        r = requests.get(f"http://127.0.0.1:{debug_port}/json/version", timeout=1)
                        if r.status_code == 200:
                            ready = True
                            break
                    except Exception:
                        pass
                    time.sleep(0.5)
                if ready:
                    try:
                        browser = await asyncio.wait_for(
                            uc.start(host="127.0.0.1", port=debug_port),
                            timeout=20,
                        )
                        break
                    except Exception as start_exc:
                        print(f"  ⚠️ Грешка при свързване с Chrome DevTools (опит {launch_attempt}): {start_exc}")
                else:
                    ver_out = ""
                    try:
                        ver_out = subprocess.run(
                            [linux_chrome, "--version"],
                            capture_output=True,
                            text=True,
                            timeout=3,
                        ).stdout.strip()
                    except Exception:
                        pass
                    err_out = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
                    print(
                        f"  ⚠️ Chrome DevTools портът ({debug_port}) не стана активен за 20 сек "
                        f"(опит {launch_attempt}/2, {ver_out}). Лог: {err_out[-350:].strip()}"
                    )
                try:
                    chrome_proc.kill()
                except Exception:
                    pass
                subprocess.run(
                    ["pkill", "-9", "-f", "/opt/google/chrome"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(1.0)

            if browser is None:
                print("  🔄 Проба на резервно стартиране чрез nodriver uc.start()...")
                browser = await asyncio.wait_for(
                    uc.start(
                        browser_executable_path=linux_chrome,
                        headless=False,
                        sandbox=False,
                        browser_args=[
                            "--no-sandbox",
                            "--disable-setuid-sandbox",
                            "--disable-dev-shm-usage",
                            "--disable-gpu",
                            "--password-store=basic",
                            "--window-size=1280,960",
                        ],
                    ),
                    timeout=25,
                )
        else:
            browser = await asyncio.wait_for(
                uc.start(
                    headless=False,
                    sandbox=False,
                    browser_args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--window-size=1280,960",
                    ],
                ),
                timeout=25,
            )
        domain_failures: dict[str, int] = defaultdict(int)
        domain_successes: set[str] = set()
        skipped_domains: set[str] = set()
        cf_retry_candidates: list[str] = []

        async def _try_cf_fetch(target_u: str, timeout_s: int) -> bool:
            host_u = urlparse(target_u).netloc.lower()
            try:
                html = await asyncio.wait_for(_fetch_single_cf_page(browser, target_u), timeout=timeout_s)
                if html:
                    if is_hard_waf_block(html):
                        domain_failures[host_u] += 1
                        snip = _extract_title_snippet(html)
                        print(f"  ⚠️ [Cloudflare Browser] Отказан достъп/профилактика при {target_u} ({snip})")
                        return False
                    p_chk, _, _, stock_chk, stock_reason_chk = extract_price_and_old_price(html, target_u)
                    if (p_chk is None and stock_chk) or stock_reason_chk == "EMAG_PAGE_INCOMPLETE":
                        domain_failures[host_u] += 1
                        snip = _extract_title_snippet(html)
                        print(
                            f"  ⚠️ [Cloudflare Browser] Непълна страница без цена при {target_u} "
                            f"({snip} | len={len(html)} ld={html.count('application/ld+json')} pdp={int('product-pdp__prices' in html)})"
                        )
                        return False
                    results[target_u] = html
                    domain_failures[host_u] = 0
                    domain_successes.add(host_u)
                    return True
                domain_failures[host_u] += 1
            except Exception as exc:
                domain_failures[host_u] += 1
                err_label = str(exc) or type(exc).__name__
                print(f"  ⚠️ [Cloudflare Browser] Таймаут/Грешка при {target_u}: {err_label}")
            return False

        for u in _interleave_by_host(urls):
            host = urlparse(u).netloc.lower()
            if host in skipped_domains:
                print(f"  ⏭️ [Cloudflare Browser] Пропускане на {u} ({host} блокира достъпа от този сървър)")
                continue
            per_page_timeout = 24 if host not in domain_successes else 18
            ok = await _try_cf_fetch(u, per_page_timeout)
            if not ok:
                cf_retry_candidates.append(u)
            max_consecutive_failures = 3 if host in domain_successes else 2
            if domain_failures[host] >= max_consecutive_failures:
                skipped_domains.add(host)
                print(
                    f"  🛑 [Cloudflare Browser] Домейнът {host} отказа достъп {domain_failures[host]} пъти поред; "
                    "прескачане на останалите му линкове."
                )

        for u in cf_retry_candidates:
            host = urlparse(u).netloc.lower()
            if host in domain_successes and u not in results:
                print(f"  🔄 [Cloudflare Browser] Повторен опит след успешно Cloudflare потвърждение: {u}")
                await _try_cf_fetch(u, 18)
    except Exception as exc:
        print(f"  ⚠️ Неуспешно стартиране на браузър за Cloudflare: {exc}")
    finally:
        if browser:
            try:
                browser.stop()
            except Exception:
                pass
        if chrome_proc is not None:
            try:
                chrome_proc.kill()
            except Exception:
                pass
        if sys.platform.startswith("linux"):
            try:
                import subprocess
                subprocess.run(
                    ["pkill", "-9", "-f", "chrome"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
    return results


def fetch_html_fast(url: str, cf_cache: dict[str, str], timeout: int = 15) -> str:
    """Извлича HTML от кеша на Cloudflare браузъра или директно чрез curl_cffi / requests."""
    if url in cf_cache:
        return cf_cache[url]
    if HAS_CFFI:
        try:
            resp = cffi_requests.get(url, headers=HEADERS, impersonate="chrome124", timeout=timeout)
            if resp.status_code == 200 and len(resp.text) > 1000:
                return resp.text
        except Exception as cffi_exc:
            if any(t in str(cffi_exc).lower() for t in ("timed out", "timeout", "operation timed out")):
                raise
    resp = requests.get(url, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def normalize_to_eur(val: float, currency_hint: str = "EUR") -> float:
    """Нормализира цена в евро (ако е в лева, конвертира по фиксинга 1.95583)."""
    curr = (currency_hint or "EUR").upper()
    if curr in ("BGN", "ЛВ", "ЛВ.") or (curr == "EUR" and val > 2200.0):
        return round(val / BGN_TO_EUR, 2)
    return round(val, 2)


def parse_eur_amount_from_text(raw_txt: str, default_curr: str = "EUR", min_val: float = 50.0) -> float | None:
    """Извлича и нормализира към EUR цена от текст (поддържа хиляди с точка/интервал и split <sup> стотинки)."""
    if not raw_txt:
        return None
    patterns = (
        (r"(\d{1,2})[\.\s\u00a0\u202f](\d{3})\s*[,\.]\s*(\d{2})(?!\d)", True),
        (r"(\d{2,4})\s*[,\.]\s*(\d{2})(?!\d)", False),
        (r"(\d{1,2})[\.\s\u00a0\u202f](\d{3})\s+(\d{2})(?!\d)", True),
        (r"(\d{2,4})\s+(\d{2})(?!\d)", False),
    )
    p_val = None
    for pat, has_thousands in patterns:
        m = re.search(pat, raw_txt)
        if m:
            if has_thousands:
                p_val = float(f"{m.group(1)}{m.group(2)}.{m.group(3)}")
            else:
                p_val = float(f"{m.group(1)}.{m.group(2)}")
            break
    if p_val is None or p_val <= min_val:
        return None
    low = raw_txt.lower()
    if "лв" in low or "bgn" in low:
        curr = "BGN"
    elif "€" in raw_txt or "eur" in low:
        curr = "EUR"
    else:
        curr = default_curr
    return normalize_to_eur(p_val, curr)


def check_stock_status(soup: BeautifulSoup, url: str, raw_html: str = "") -> tuple[bool, str]:
    """
    Проверява дали продуктът е в наличност или изчерпан.
    Връща (is_in_stock: bool, stock_reason: str).
    """
    url_low = url.lower()

    # 1. Technovision София (technovision.bg)
    if "technovision.bg" in url_low:
        title_txt = (soup.title.get_text(strip=True).lower() if soup.title else "")
        if any(m in title_txt for m in ("page not found", "страницата не е намерена", "404")):
            return False, "Technovision (Изчерпан / Свален от сайта)"
        h1 = soup.find("h1")
        h1_text = h1.get_text(" ", strip=True).lower() if h1 else ""
        if "just a moment" not in title_txt and h1_text not in ("", "technovision.bg"):
            url_slug = url.strip("/").split("/")[-1].lower()
            generic_tokens = {
                "produkt", "hladilnik", "furna", "pechka", "gotvarska", "kombinirana",
                "uredi", "biala", "tehnika", "mashini", "sadomiyalni", "peralnya",
                "peralnia", "peralnq", "sushilnya", "sushilnia", "sushilnq",
                "sas", "sus", "series", "termopompa",
            }
            slug_tokens = [t for t in re.split(r"[-_]", url_slug) if len(t) > 2 and t not in generic_tokens]
            model_tokens = [t for t in slug_tokens if any(c.isalpha() for c in t) and any(c.isdigit() for c in t) and len(t) >= 5]
            check_tokens = model_tokens or slug_tokens
            if check_tokens and not any(t in h1_text for t in check_tokens):
                return False, "Technovision (Пренасочване към друг модел / Изчерпан)"
        summary = soup.select_one(".summary.entry-summary") or soup.select_one(".single-product-wrapper") or soup
        if summary.select_one("p.stock.out-of-stock") or summary.select_one(".out-of-stock"):
            return False, "Technovision (Изчерпано количество)"

    # 2. Релакс Техно София (relaxbg.org)
    if "relaxbg.org" in url_low:
        if soup.select_one("p.stock.out-of-stock") or soup.select_one(".stock.out-of-stock"):
            return False, "Релакс Техно (Изчерпан)"

    # 3. Schema.org JSON-LD наличност (Зора, Техномикс, Практис, Релакс и др.)
    for script in soup.find_all("script", type="application/ld+json"):
        if not script.string:
            continue
        try:
            data = json.loads(script.string.strip())
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for it in list(items):
            if isinstance(it, dict) and "@graph" in it and isinstance(it["@graph"], list):
                items.extend(it["@graph"])
        for it in items:
            if not isinstance(it, dict):
                continue
            offers = it.get("offers")
            if not offers:
                continue
            offer_list = offers if isinstance(offers, list) else [offers]
            for off in offer_list:
                if not isinstance(off, dict):
                    continue
                avail = str(off.get("availability", "")).lower()
                if any(w in avail for w in ["outofstock", "discontinued", "soldout"]):
                    tag = avail.split("/")[-1]
                    return False, f"JSON-LD ({tag})"
                if any(w in avail for w in ["instock", "in_stock", "preorder"]):
                    tag = avail.split("/")[-1]
                    return True, f"JSON-LD ({tag})"

    # 4. Meta тагове за наличност
    for meta in soup.find_all("meta"):
        prop = (meta.get("property", "") or meta.get("name", "") or meta.get("itemprop", "")).lower()
        if prop in ("product:availability", "og:availability", "availability"):
            val = (meta.get("content") or "").lower()
            if any(w in val for w in ["oos", "out of stock", "outofstock", "изчерпан"]):
                return False, f"META ({val})"
            if any(w in val for w in ["instock", "in stock", "наличен"]):
                return True, f"META ({val})"

    # 5. DOM селектори за изчерпана наличност (Tehnomix, Praktis и др.)
    for sel in (
        ".stock.unavailable",
        ".stock.out-of-stock",
        "p.stock.out-of-stock",
        ".product-info-stock-sku",
        ".product-unavailable",
        ".badge-out-of-stock",
        ".product-out-of-stock",
    ):
        for el in soup.select(sel):
            txt = el.get_text(" ", strip=True).lower()
            if any(w in txt for w in ["изчерпан", "изчерпано", "няма наличност", "не е наличен", "неналичен"]):
                return False, f"DOM ({txt[:30]})"

    # 6. eMAG проверки: Строго 'Предлаган и с доставка от: eMAG', отхвърляне на външни маркетплейс търговци
    if "emag.bg" in url_low:
        if not soup.select_one("h1.page-title") and not soup.select_one(".product-page-pricing, .pricing-block"):
            return True, "EMAG_PAGE_INCOMPLETE"
        seller = None
        for el in soup.select(".highlight-content, .product-highlight, .product-page-pricing, .product-page-vendor-details, .fs-14"):
            txt = el.get_text(" ", strip=True)
            m = re.search(r"Предлаган и с доставка от:?\s*([A-Za-z0-9_.\s-]+?)(?:\s+В наличност|\s+Няма наличност|\s+Гаранция|\s+Други|$)", txt, re.I)
            if m:
                seller = m.group(1).strip()
                break
        if not seller:
            vendor_link = soup.select_one('a[href*="/v?ref=see_vendor_page"], a.dotted-link[href*="/v?"]')
            if vendor_link:
                seller = vendor_link.get_text(strip=True)
        if not seller and raw_html:
            m2 = re.search(r"Предлаган и с доставка от:?\s*(?:<[^>]+>\s*)*([A-Za-z0-9_.\s-]+?)(?:\s*<|\s+В наличност)", raw_html, re.I)
            if m2:
                seller = m2.group(1).strip()

        if seller and seller.lower() != "emag":
            return False, f"eMAG (Маркетплейс търговец: {seller}, игнориран - следи се само директно от eMAG)"

        if soup.select_one(".label-out_of_stock") or soup.select_one(".label-out-of-stock"):
            return False, "eMAG (Изчерпана наличност)"
        pricing_block = soup.select_one(".product-page-pricing") or soup.select_one(".pricing-block")
        if pricing_block and "изчерпана наличност" in pricing_block.get_text(" ", strip=True).lower():
            return False, "eMAG (Изчерпана наличност)"
        if not soup.select_one(".product-new-price") and not soup.select_one(".product-highlight"):
            return False, "eMAG (няма цена/бутон за купуване)"

    return True, "IN_STOCK"


def extract_price_and_old_price(html: str, url: str) -> tuple[float | None, float | None, str, bool, str]:
    """
    Връща (current_price_eur, claimed_old_price_eur, extraction_method, is_in_stock, stock_reason).
    Поддържа всички големи вериги в София + софийските сайтове за транспортни дефекти.
    """
    soup = BeautifulSoup(html, "html.parser")
    url_low = url.lower()
    is_in_stock, stock_reason = check_stock_status(soup, url, raw_html=html)

    # --- Специализирани парсери за софийските магазини за транспортни дефекти и вериги ---

    # 1. Technovision София (technovision.bg)
    if "technovision.bg" in url_low:
        summary = soup.select_one(".summary.entry-summary") or soup.select_one(".single-product-wrapper") or soup
        box = summary.select_one(".single-product-W-price .electro-price, p.price .electro-price, p.price")
        amounts = []
        if box:
            for a_el in box.select(".woocommerce-Price-amount"):
                amt = parse_eur_amount_from_text(a_el.get_text(" ", strip=True), default_curr="EUR", min_val=50.0)
                if amt is not None:
                    amounts.append(amt)
        cur = amounts[0] if amounts else None
        old = amounts[1] if len(amounts) > 1 and amounts[1] > cur else None
        tag = "TECHNOVISION" if is_in_stock else "TECHNOVISION (Изчерпан)"
        return cur, old, tag, is_in_stock, stock_reason

    # 2. Technowelt София (technowelt.bg)
    if "technowelt.bg" in url_low:
        wrap = soup.select_one(".price-wrapper")
        if wrap:
            txt = re.sub(r"[\s\u00a0\u202f]+", "", wrap.get_text(" ", strip=True))
            euros = [float(x.replace(",", ".")) for x in re.findall(r"€(\d+[\.,]\d{2})", txt)]
            if euros:
                cur = min(euros)
                old = max(euros) if len(euros) > 1 and max(euros) > cur else None
                return round(cur, 2), old, "TECHNOWELT", is_in_stock, stock_reason

    # 3. Бяла Мания София (bqlamania.eu) и Вимакс София (vimax.bg)
    if "bqlamania.eu" in url_low or "vimax.bg" in url_low:
        p_el = soup.select_one(".product-price-group .product-price")
        if p_el:
            amt = parse_eur_amount_from_text(p_el.get_text(" ", strip=True), default_curr="EUR", min_val=50.0)
            if amt is not None:
                return amt, None, "PRODUCT_PRICE_GROUP", is_in_stock, stock_reason

    # 4. Tech2Home София (tech2home.bg)
    if "tech2home.bg" in url_low:
        ins_el = soup.select_one("ins .woocommerce-Price-amount")
        del_el = soup.select_one("del .woocommerce-Price-amount")
        if ins_el:
            cur = parse_eur_amount_from_text(ins_el.get_text(" ", strip=True), default_curr="EUR", min_val=50.0)
            old = parse_eur_amount_from_text(del_el.get_text(" ", strip=True), default_curr="EUR", min_val=50.0) if del_el else None
            if cur is not None:
                return cur, old, "TECH2HOME", is_in_stock, stock_reason

    # --- Общи стандартизирани екстрактори (Технополис, Техномаркет, Зора, Техномикс, Техмарт, Практис, JAR, eMAG, Релакс Техно) ---
    current_price = None
    method = "NOT_FOUND"

    # A. OpenGraph / Meta тагове
    meta_price = None
    meta_curr = None
    for meta in soup.find_all("meta"):
        prop = (meta.get("property", "") or meta.get("name", "") or meta.get("itemprop", "")).lower()
        if prop in ("product:price:amount", "og:price:amount", "price"):
            val = (meta.get("content") or "").strip()
            if val:
                try:
                    meta_price = float(re.sub(r"[\s\u00a0\u202f]+", "", val).replace(",", "."))
                except ValueError:
                    pass
        elif prop in ("product:price:currency", "og:price:currency", "pricecurrency"):
            meta_curr = (meta.get("content") or "").strip().upper()

    if meta_price and meta_price > 50:
        current_price = normalize_to_eur(meta_price, meta_curr or "EUR")
        method = f"META ({meta_curr or 'EUR'})"

    # B. Schema.org JSON-LD
    if current_price is None:
        for script in soup.find_all("script", type="application/ld+json"):
            if not script.string:
                continue
            try:
                data = json.loads(script.string.strip())
            except Exception:
                continue

            items = data if isinstance(data, list) else [data]
            for item in list(items):
                if isinstance(item, dict) and "@graph" in item and isinstance(item["@graph"], list):
                    items.extend(item["@graph"])

            for item in items:
                if not isinstance(item, dict):
                    continue
                offers = item.get("offers")
                if not offers:
                    continue
                offer_list = offers if isinstance(offers, list) else [offers]
                for off in offer_list:
                    if not isinstance(off, dict):
                        continue
                    p = off.get("price") or off.get("lowPrice")
                    curr = str(off.get("priceCurrency", "EUR")).upper()
                    if p is not None:
                        try:
                            p_val = float(str(p).replace(",", ".").replace(" ", ""))
                            if p_val > 50:
                                current_price = normalize_to_eur(p_val, curr)
                                method = f"JSON-LD ({curr})"
                                break
                        except ValueError:
                            pass
                if current_price is not None:
                    break
            if current_price is not None:
                break

    # C. Специфични CSS селектори (Технополис PDP, eMAG и др.)
    if current_price is None and "technopolis.bg" in url_low:
        for el in soup.select(".product-pdp__prices .price-value"):
            if el.find_parent(class_="old-price") is not None:
                continue
            price_txt = (el.parent.get_text(" ", strip=True) if el.parent else "") or el.get_text(" ", strip=True)
            amt = parse_eur_amount_from_text(price_txt, default_curr="EUR", min_val=50.0)
            if amt is not None:
                current_price = amt
                method = "CSS (Technopolis PDP)"
                break

    if current_price is None:
        for sel in (".product-new-price", "._product-details-price-new", ".special-price .price"):
            el = soup.select_one(sel)
            if el:
                amt = parse_eur_amount_from_text(el.get_text(" ", strip=True), default_curr="EUR", min_val=50.0)
                if amt is not None:
                    current_price = amt
                    method = f"CSS ({sel})"
                    break

    # D. Търсене на зачеркната "стара" цена за детекция на лъжливи намаления
    claimed_old_price = None
    for old_sel in (".product-old-price", ".old-price", ".price_old", "del", "s.price"):
        el = soup.select_one(old_sel)
        if el:
            norm_old = parse_eur_amount_from_text(el.get_text(" ", strip=True), default_curr="EUR", min_val=100.0)
            if norm_old is not None and current_price and norm_old > current_price:
                claimed_old_price = norm_old
                break

    return current_price, claimed_old_price, method, is_in_stock, stock_reason


def evaluate_black_friday_status(
    current_eur: float,
    claimed_old_eur: float | None,
    baseline: dict,
    store_name: str,
    method: str = "",
    is_in_stock: bool = True,
) -> tuple[str, str]:
    """
    Оценява текущата цена спрямо таблицата от Точка 2 (средна цена от октомври и реална базова цена).
    Ако продуктът е изчерпан, връща състояние OUT_OF_STOCK.
    """
    price_bgn = round(current_eur * BGN_TO_EUR, 2)
    if not is_in_stock:
        return (
            "OUT_OF_STOCK",
            f"⏸️ Изчерпан в момента (последна цена: {current_eur:.2f} € / {price_bgn:.2f} лв. – следи се за наличност)",
        )

    oct_avg = baseline["october_avg_eur"]
    fake_thresh = baseline.get("fake_crossed_out_price_threshold_eur", oct_avg * 1.05)

    is_defect_store = any(
        k in store_name.lower()
        for k in ("дефект", "technovision", "technowelt", "мания", "tech2home", "релакс", "relax")
    )
    deal_trigger = (
        baseline.get("target_deal_trigger_defect_eur", baseline["target_deal_trigger_eur"])
        if is_defect_store
        else baseline["target_deal_trigger_eur"]
    )

    diff_vs_oct = round(current_eur - oct_avg, 2)
    pct_vs_oct = round((diff_vs_oct / oct_avg) * 100, 1)

    if claimed_old_eur and claimed_old_eur >= fake_thresh and not is_defect_store:
        return (
            "FAKE_DISCOUNT",
            f"⚠️ ЛЪЖЛИВО НАМАЛЕНИЕ: Обявена стара цена {claimed_old_eur:.2f} €, "
            f"а средната през октомври беше {oct_avg:.2f} €!",
        )

    if current_eur > oct_avg + 3.0:
        return (
            "ABOVE_OCTOBER",
            f"📈 Над октомврийската средна с +{diff_vs_oct:.2f} € (+{pct_vs_oct}% спрямо {oct_avg:.2f} €)",
        )

    if current_eur <= deal_trigger:
        return (
            "REAL_DEAL",
            f"🔥 ИСТИНСКА ОФЕРТА! Под прага ({deal_trigger:.2f} €) и с {diff_vs_oct:.2f} € ({pct_vs_oct}%) спрямо октомври!",
        )

    return (
        "NORMAL",
        f"Нормална цена ({diff_vs_oct:+.2f} € / {pct_vs_oct:+.1f}% спрямо октомври: {oct_avg:.2f} €)",
    )


def build_email_html(changes: list[dict], all_results: list[dict], timestamp_str: str) -> str:
    """Генерира HTML имейл с всички засечени промени (поевтиняване ↓, поскъпване ↑, наличности 🟢 / ⏸️) + пълна таблица."""
    rows_changes = ""
    for ch in changes:
        ch_type = ch.get("change_type", "PRICE_CHANGE")
        if ch_type == "BACK_IN_STOCK":
            badge = '<span style="color:#16a34a;font-weight:bold;">🟢 ОТНОВО В НАЛИЧНОСТ!</span>'
            diff_text = f"<b>{ch['new_eur']:.2f} € ({ch['new_bgn']:.2f} лв.)</b>"
        elif ch_type == "OUT_OF_STOCK":
            badge = '<span style="color:#d97706;font-weight:bold;">⏸️ ИЗЧЕРПАНО</span>'
            diff_text = '<span style="color:#64748b;">(Следи се за нова бройка)</span>'
        else:
            badge = (
                '<span style="color:#15803d;font-weight:bold;">↓ ПОЕВТИНЯВАНЕ</span>'
                if ch.get("diff_eur", 0) < 0
                else '<span style="color:#b91c1c;font-weight:bold;">↑ ПОСКЪПВАНЕ</span>'
            )
            diff_text = f"{ch['diff_eur']:+.2f} € ({ch['diff_bgn']:+.2f} лв. / {ch['diff_pct']:+.1f}%)"

        rows_changes += f"""
        <tr>
            <td style="padding:8px;border:1px solid #cbd5e1;"><b>{ch['appliance_name']}</b></td>
            <td style="padding:8px;border:1px solid #cbd5e1;"><a href="{ch['url']}">{ch['store']}</a></td>
            <td style="padding:8px;border:1px solid #cbd5e1;">{ch['old_eur']:.2f} € ({ch['old_bgn']:.2f} лв.)</td>
            <td style="padding:8px;border:1px solid #cbd5e1;"><b>{ch['new_eur']:.2f} € ({ch['new_bgn']:.2f} лв.)</b></td>
            <td style="padding:8px;border:1px solid #cbd5e1;">{badge}<br>{diff_text}</td>
            <td style="padding:8px;border:1px solid #cbd5e1;">{ch['bf_note']}</td>
        </tr>
        """

    rows_all = ""
    for r in all_results:
        if r["price_eur"] is None:
            continue
        stock_badge = ""
        if not r.get("is_in_stock", True):
            stock_badge = '<br><span style="color:#b45309;font-size:11px;font-weight:bold;">⏸️ Изчерпан в магазина</span>'
        rows_all += f"""
        <tr>
            <td style="padding:6px;border:1px solid #e2e8f0;">{r['appliance_name']}</td>
            <td style="padding:6px;border:1px solid #e2e8f0;"><a href="{r['url']}">{r['store']}</a></td>
            <td style="padding:6px;border:1px solid #e2e8f0;"><b>{r['price_eur']:.2f} €</b> ({r['price_bgn']:.2f} лв.){stock_badge}</td>
            <td style="padding:6px;border:1px solid #e2e8f0;">{r['october_avg_eur']:.2f} €</td>
            <td style="padding:6px;border:1px solid #e2e8f0;">{r['bf_note']}</td>
        </tr>
        """

    changes_section = (
        f"""
        <h3 style="color:#0f172a;">🔔 Засечени промени в цените в София ({len(changes)} бр.):</h3>
        <table style="border-collapse:collapse;width:100%;font-family:Arial,sans-serif;font-size:14px;">
            <thead style="background:#f1f5f9;">
                <tr>
                    <th style="padding:8px;border:1px solid #cbd5e1;text-align:left;">Уред</th>
                    <th style="padding:8px;border:1px solid #cbd5e1;text-align:left;">Магазин (София)</th>
                    <th style="padding:8px;border:1px solid #cbd5e1;text-align:left;">Предишна цена</th>
                    <th style="padding:8px;border:1px solid #cbd5e1;text-align:left;">Нова цена</th>
                    <th style="padding:8px;border:1px solid #cbd5e1;text-align:left;">Промяна</th>
                    <th style="padding:8px;border:1px solid #cbd5e1;text-align:left;">Черен петък статус (Точка 2)</th>
                </tr>
            </thead>
            <tbody>{rows_changes}</tbody>
        </table>
        """
        if changes
        else "<p><i>Няма промяна спрямо предходното проверяване. (Изпратен пълен контролен отчет)</i></p>"
    )

    return f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#1e293b;line-height:1.5;">
        <h2 style="color:#1e40af;">📊 Известие от Ценовия Бот за София ({timestamp_str})</h2>
        {changes_section}
        <hr style="margin:24px 0;border:none;border-top:1px solid #cbd5e1;">
        <h3 style="color:#0f172a;">📋 Пълна моментна снимка от магазините в София (вкл. транспортни дефекти):</h3>
        <table style="border-collapse:collapse;width:100%;font-family:Arial,sans-serif;font-size:13px;">
            <thead style="background:#f8fafc;">
                <tr>
                    <th style="padding:6px;border:1px solid #e2e8f0;text-align:left;">Уред</th>
                    <th style="padding:6px;border:1px solid #e2e8f0;text-align:left;">Магазин в София</th>
                    <th style="padding:6px;border:1px solid #e2e8f0;text-align:left;">Текуща цена</th>
                    <th style="padding:6px;border:1px solid #e2e8f0;text-align:left;">Средна Октомври</th>
                    <th style="padding:6px;border:1px solid #e2e8f0;text-align:left;">Анализ за лъжливо намаление</th>
                </tr>
            </thead>
            <tbody>{rows_all}</tbody>
        </table>
    </body>
    </html>
    """


def send_email_alert(subject: str, html_body: str) -> bool:
    """Изпраща имейл чрез SMTP."""
    smtp_host = (os.environ.get("SMTP_HOST") or "smtp.gmail.com").strip()
    smtp_port = int((os.environ.get("SMTP_PORT") or "587").strip())
    smtp_user = (os.environ.get("SMTP_USER") or "").strip()
    smtp_pass = (os.environ.get("SMTP_PASS") or "").strip()
    notify_to = (os.environ.get("NOTIFY_EMAIL") or smtp_user).strip()

    if not smtp_user or not smtp_pass or not notify_to:
        print(
            "⚠️ Имейл не беше изпратен: Липсват SMTP_USER / SMTP_PASS / NOTIFY_EMAIL в средата или .env файла."
        )
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = notify_to
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.ehlo()
            server.starttls()
            try:
                server.login(smtp_user, smtp_pass)
            except smtplib.SMTPAuthenticationError:
                if " " in smtp_pass:
                    server.login(smtp_user, smtp_pass.replace(" ", ""))
                else:
                    raise
            server.sendmail(smtp_user, [addr.strip() for addr in notify_to.split(",")], msg.as_string())
        print(f"✅ Успешно изпратено имейл известие до {notify_to}!")
        return True
    except Exception as exc:
        print(f"❌ Грешка при изпращане на имейл чрез {smtp_host}:{smtp_port} за {smtp_user}: {exc}")
        return False


def classify_carryover_reason(err_msg: str, in_ci: bool | None = None) -> str:
    """Формулира ясна причина защо офертата пази предходната цена в отчета."""
    if in_ci is None:
        in_ci = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    low_msg = (err_msg or "").lower()
    if "503" in low_msg or "black friday" in low_msg or "emag_page_incomplete" in low_msg:
        return "сайтът временно връща 503 / профилактика"
    if any(tok in low_msg for tok in ("403", "511", "waf", "forbidden", "denied")):
        if in_ci:
            return "сайтът блокира облачния сървър на GitHub – от България се отваря нормално"
        return "сайтът блокира автоматичната заявка (403/511)"
    if "404" in low_msg:
        return "страницата не е намерена (404)"
    if "no_price" in low_msg:
        return "страницата не върна цена (възможен временен блок/промяна)"
    return "временен проблем с достъпа от този сървър"


def main():
    parser = argparse.ArgumentParser(description="Ценови бот за магазини в София (Точка 3 от task.txt)")
    parser.add_argument("--force-email", action="store_true", help="Изпраща имейл дори да няма промяна в цената")
    parser.add_argument(
        "--simulate-change",
        action="store_true",
        help="Симулира промяна в 1 магазин за тест на системата за известяване",
    )
    args = parser.parse_args()

    load_dotenv_if_present(ENV_PATH)

    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    previous_state = {}
    if STATE_PATH.exists():
        try:
            previous_state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            previous_state = {}

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"🚀 Стартиране на проверка на цените в СОФИЯ ({now_str})...")

    # Стъпка 1: Бърза проверка с curl_cffi / requests за сайтовете без задължителен Cloudflare Turnstile,
    # а всички Cloudflare сайтове или върнали 403/511 от чуждестранен облачен IP адрес отиват към реалния Chrome браузър.
    cf_cache = {}
    cf_domain_urls = []
    non_cf_urls = []
    seen_non_cf = set()
    for app in config["appliances"]:
        for entry in app["urls"]:
            u = entry["url"]
            if any(d in u.lower() for d in CLOUDFLARE_DOMAINS):
                if u not in cf_domain_urls:
                    cf_domain_urls.append(u)
            elif u not in seen_non_cf:
                seen_non_cf.add(u)
                non_cf_urls.append(u)

    def _fast_probe_host(host_urls: list[str]) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        consecutive_http_blocks = 0
        consecutive_timeouts = 0
        for idx, target_url in enumerate(host_urls):
            if consecutive_timeouts >= 2:
                out[target_url] = "__TCP_TIMEOUT__"
                continue
            if consecutive_http_blocks >= 2:
                out[target_url] = None
                continue
            if idx > 0:
                time.sleep(0.45)
            try:
                probe_html = fetch_html_fast(target_url, {}, timeout=8)
                p_test, _, _, in_stock_test, stock_reason_test = extract_price_and_old_price(probe_html, target_url)
                if (p_test is not None or not in_stock_test) and stock_reason_test != "EMAG_PAGE_INCOMPLETE":
                    out[target_url] = probe_html
                    consecutive_http_blocks = 0
                    consecutive_timeouts = 0
                    continue
            except Exception as exc:
                msg = str(exc)
                if "404" in msg:
                    out[target_url] = "__HTTP_404__"
                    continue
                if any(t in msg.lower() for t in ("timed out", "timeout", "operation timed out")):
                    consecutive_timeouts += 1
                    out[target_url] = "__TCP_TIMEOUT__"
                    continue
                if any(code in msg for code in ("403", "511", "503")):
                    consecutive_http_blocks += 1
            out[target_url] = None
        return out

    browser_fallback_urls = []
    fast_results: dict[str, str | None] = {}
    if non_cf_urls:
        host_groups: dict[str, list[str]] = defaultdict(list)
        for u in non_cf_urls:
            host_groups[urlparse(u).netloc.lower()].append(u)
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(_fast_probe_host, urls_for_host) for urls_for_host in host_groups.values()]
            for fut in as_completed(futures):
                fast_results.update(fut.result())
        for u in non_cf_urls:
            val = fast_results.get(u)
            if val in ("__HTTP_404__", "__TCP_TIMEOUT__"):
                continue
            elif val:
                cf_cache[u] = val
            else:
                browser_fallback_urls.append(u)

    browser_urls = cf_domain_urls + browser_fallback_urls

    if browser_urls and HAS_NODRIVER:
        print(f"🔓 Отваряне на защитени сайтове през реален Chrome браузър ({len(browser_urls)} линка)...")
        browser_results = uc.loop().run_until_complete(fetch_cloudflare_pages_batch(browser_urls))
        cf_cache.update(browser_results)

    def _append_carried_over_if_exists(
        state_key: str,
        app_id: str,
        app_name: str,
        store: str,
        url: str,
        baseline: dict,
        reason_note: str = "временен проблем с достъпа от този сървър",
    ) -> None:
        if state_key not in previous_state or not isinstance(previous_state[state_key], dict):
            return
        prev = previous_state[state_key]
        new_state[state_key] = prev
        if prev.get("price_eur") is None:
            return
        prev_ts = prev.get("last_checked", "предишна проверка")
        all_results.append(
            {
                "timestamp": now_str,
                "appliance_id": app_id,
                "appliance_name": app_name,
                "store": store,
                "url": url,
                "price_eur": prev["price_eur"],
                "price_bgn": prev.get("price_bgn", round(prev["price_eur"] * BGN_TO_EUR, 2)),
                "october_avg_eur": baseline["october_avg_eur"],
                "bf_status": prev.get("bf_status", "NORMAL"),
                "bf_note": f"⏳ Последна проверка от {prev_ts} ({reason_note})",
                "is_in_stock": prev.get("is_in_stock", True),
                "method": "CACHED_PREVIOUS",
                "carried_over": True,
            }
        )

    new_state = {}
    all_results = []
    detected_changes = []

    for app in config["appliances"]:
        app_id = app["id"]
        app_name = app["name"]
        baseline = app["step2_baseline"]
        print(f"\n🔎 Модел: {app_name} (Октомври средна: {baseline['october_avg_eur']:.2f} €)")

        for entry in app["urls"]:
            store = entry["store"]
            url = entry["url"]
            state_key = f"{app_id}::{store}"

            try:
                if url not in cf_cache:
                    probe_flag = fast_results.get(url)
                    if probe_flag == "__HTTP_404__":
                        raise RuntimeError(f"404 Client Error: Not Found for url: {url}")
                    if probe_flag == "__TCP_TIMEOUT__":
                        raise ConnectionError(f"ConnectTimeoutError: Connection to {urlparse(url).netloc} timed out")
                html = fetch_html_fast(url, cf_cache)
                price_eur, claimed_old_eur, method, is_in_stock, stock_reason = extract_price_and_old_price(html, url)
            except Exception as exc:
                print(f"  ❌ [{store}] Грешка при достъп: {exc} (запазва се предходният запис).")
                _append_carried_over_if_exists(
                    state_key, app_id, app_name, store, url, baseline, reason_note=classify_carryover_reason(str(exc))
                )
                continue

            if price_eur is None:
                if not is_in_stock and state_key in previous_state:
                    price_eur = previous_state[state_key].get("price_eur", 298.65)
                elif not is_in_stock:
                    price_eur = baseline.get("target_deal_trigger_defect_eur", baseline["target_deal_trigger_eur"])
                else:
                    print(f"  ⚠️ [{store}] Не бе открита числова цена на страницата (запазва се предходният запис).")
                    _append_carried_over_if_exists(
                        state_key,
                        app_id,
                        app_name,
                        store,
                        url,
                        baseline,
                        reason_note=classify_carryover_reason(stock_reason if stock_reason == "EMAG_PAGE_INCOMPLETE" else "NO_PRICE"),
                    )
                    continue

            price_bgn = round(price_eur * BGN_TO_EUR, 2)
            bf_status, bf_note = evaluate_black_friday_status(
                price_eur, claimed_old_eur, baseline, store, method, is_in_stock=is_in_stock
            )

            old_record = previous_state.get(state_key) if isinstance(previous_state.get(state_key), dict) else {}
            prev_eur = old_record.get("price_eur")
            if "is_in_stock" in old_record:
                prev_in_stock = bool(old_record["is_in_stock"])
            elif old_record.get("bf_status") == "OUT_OF_STOCK":
                prev_in_stock = False
            else:
                prev_in_stock = True

            if args.simulate_change and prev_eur is not None and not detected_changes:
                prev_eur = round(price_eur + 15.00, 2)

            if prev_in_stock and not is_in_stock:
                change_str = "⏸️ ИЗЧЕРПАНО КОЛИЧЕСТВО"
                detected_changes.append(
                    {
                        "appliance_id": app_id,
                        "appliance_name": app_name,
                        "store": store,
                        "url": url,
                        "change_type": "OUT_OF_STOCK",
                        "old_eur": prev_eur or price_eur,
                        "old_bgn": round((prev_eur or price_eur) * BGN_TO_EUR, 2),
                        "new_eur": price_eur,
                        "new_bgn": price_bgn,
                        "diff_eur": 0.0,
                        "diff_bgn": 0.0,
                        "diff_pct": 0.0,
                        "bf_status": "OUT_OF_STOCK",
                        "bf_note": f"⏸️ ИЗЧЕРПАНО КОЛИЧЕСТВО (Последна цена: {price_eur:.2f} € / {price_bgn:.2f} лв.)",
                    }
                )
                print(f"  ⏸️ [{store:<48}] {price_eur:6.2f} € ({price_bgn:6.2f} лв.) | {change_str} | {bf_note}")
            elif not prev_in_stock and is_in_stock:
                change_str = "🟢 ОТНОВО В НАЛИЧНОСТ!"
                diff_eur = round(price_eur - prev_eur, 2) if prev_eur else 0.0
                diff_bgn = round(diff_eur * BGN_TO_EUR, 2)
                diff_pct = round((diff_eur / prev_eur) * 100, 2) if prev_eur else 0.0
                detected_changes.append(
                    {
                        "appliance_id": app_id,
                        "appliance_name": app_name,
                        "store": store,
                        "url": url,
                        "change_type": "BACK_IN_STOCK",
                        "old_eur": prev_eur or price_eur,
                        "old_bgn": round((prev_eur or price_eur) * BGN_TO_EUR, 2),
                        "new_eur": price_eur,
                        "new_bgn": price_bgn,
                        "diff_eur": diff_eur,
                        "diff_bgn": diff_bgn,
                        "diff_pct": diff_pct,
                        "bf_status": bf_status,
                        "bf_note": f"🟢 ОТНОВО В НАЛИЧНОСТ! ({price_eur:.2f} € / {price_bgn:.2f} лв.)",
                    }
                )
                print(f"  🟢 [{store:<48}] {price_eur:6.2f} € ({price_bgn:6.2f} лв.) | {change_str} | {bf_note}")
            elif is_in_stock:
                if prev_eur is not None:
                    diff_eur = round(price_eur - prev_eur, 2)
                    if abs(diff_eur) >= 0.05:
                        diff_bgn = round(diff_eur * BGN_TO_EUR, 2)
                        diff_pct = round((diff_eur / prev_eur) * 100, 2)
                        arrow = "↓ НАМАЛЕНИЕ" if diff_eur < 0 else "↑ ПОКАЧВАНЕ"
                        change_str = f"{arrow} ({diff_eur:+.2f} € / {diff_bgn:+.2f} лв.)"
                        detected_changes.append(
                            {
                                "appliance_id": app_id,
                                "appliance_name": app_name,
                                "store": store,
                                "url": url,
                                "change_type": "PRICE_CHANGE",
                                "old_eur": prev_eur,
                                "old_bgn": round(prev_eur * BGN_TO_EUR, 2),
                                "new_eur": price_eur,
                                "new_bgn": price_bgn,
                                "diff_eur": diff_eur,
                                "diff_bgn": diff_bgn,
                                "diff_pct": diff_pct,
                                "bf_status": bf_status,
                                "bf_note": bf_note,
                            }
                        )
                    else:
                        change_str = "Без промяна"
                else:
                    change_str = "Първо записване"
                print(f"  ✅ [{store:<48}] {price_eur:6.2f} € ({price_bgn:6.2f} лв.) | {change_str} | {bf_note}")
            else:
                change_str = "Изчерпан (следи се)"
                print(f"  ⏸️ [{store:<48}] {price_eur:6.2f} € ({price_bgn:6.2f} лв.) | {change_str} | {bf_note}")

            new_state[state_key] = {
                "appliance_id": app_id,
                "appliance_name": app_name,
                "store": store,
                "url": url,
                "price_eur": price_eur,
                "price_bgn": price_bgn,
                "claimed_old_eur": claimed_old_eur,
                "bf_status": bf_status,
                "is_in_stock": is_in_stock,
                "stock_reason": stock_reason,
                "last_checked": now_str,
            }

            all_results.append(
                {
                    "timestamp": now_str,
                    "appliance_id": app_id,
                    "appliance_name": app_name,
                    "store": store,
                    "url": url,
                    "price_eur": price_eur,
                    "price_bgn": price_bgn,
                    "october_avg_eur": baseline["october_avg_eur"],
                    "bf_status": bf_status,
                    "bf_note": bf_note,
                    "is_in_stock": is_in_stock,
                    "method": method,
                }
            )

    STATE_PATH.write_text(json.dumps(new_state, ensure_ascii=False, indent=2), encoding="utf-8")

    write_header = not HISTORY_CSV_PATH.exists()
    with HISTORY_CSV_PATH.open("a", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(
                ["Timestamp", "Appliance", "Store", "Price_EUR", "Price_BGN", "October_Avg_EUR", "BF_Status", "URL"]
            )
        for r in all_results:
            if r.get("carried_over"):
                continue
            writer.writerow(
                [
                    r["timestamp"],
                    r["appliance_name"],
                    r["store"],
                    r["price_eur"],
                    r["price_bgn"],
                    r["october_avg_eur"],
                    r["bf_status"],
                    r["url"],
                ]
            )

    fresh_count = sum(1 for r in all_results if not r.get("carried_over"))
    carried_count = len(all_results) - fresh_count
    scope_note = (
        f"{fresh_count} актуални + {carried_count} запазени от предходна проверка"
        if carried_count
        else f"{len(all_results)} магазина (физически вериги + транспортни дефекти в София)"
    )

    md_lines = [
        f"# Последен отчет от Ценовия Бот – Магазини в София ({now_str})",
        "",
        f"- **Проверени оферти в София:** {scope_note}",
        f"- **Засечени промени в цените / наличностите (спрямо предходната проверка):** {len(detected_changes)}",
        "",
        "| Уред | Магазин в София | Текуща цена | Средна Октомври (Т.2) | Статус / Наличност (Черен Петък) |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for r in all_results:
        stock_tag = " <br>*(⏸️ Изчерпан в магазина)*" if not r.get("is_in_stock", True) else ""
        md_lines.append(
            f"| **{r['appliance_name']}** | [{r['store']}]({r['url']}) | **{r['price_eur']:.2f} €** *({r['price_bgn']:.2f} лв.)*{stock_tag} | {r['october_avg_eur']:.2f} € | {r['bf_note']} |"
        )
    REPORT_MD_PATH.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if detected_changes or args.force_email:
        if detected_changes:
            drops = sum(1 for c in detected_changes if c.get("diff_eur", 0) < 0 and c.get("change_type") == "PRICE_CHANGE")
            jumps = sum(1 for c in detected_changes if c.get("diff_eur", 0) > 0 and c.get("change_type") == "PRICE_CHANGE")
            back_stock = sum(1 for c in detected_changes if c.get("change_type") == "BACK_IN_STOCK")
            oos = sum(1 for c in detected_changes if c.get("change_type") == "OUT_OF_STOCK")

            parts = []
            if back_stock:
                parts.append(f"{back_stock} отново налични 🟢")
            if drops:
                parts.append(f"{drops} намаления ↓")
            if jumps:
                parts.append(f"{jumps} покачвания ↑")
            if oos:
                parts.append(f"{oos} изчерпани ⏸️")
            subject = f"🔔 Промяна в цените/наличностите на уредите в София ({', '.join(parts)}) - {now_str}"
        else:
            subject = f"📊 Контролен отчет за цените на уредите в София ({now_str})"

        html_body = build_email_html(detected_changes, all_results, now_str)
        preview_path = BASE_DIR / "latest_email_preview.html"
        preview_path.write_text(html_body, encoding="utf-8")
        print(f"📧 Генериран е HTML имейл отчет: {preview_path}")
        sent = send_email_alert(subject, html_body)
        if not sent and args.force_email:
            print("❌ Неуспешно принудително изпращане на имейл (--force-email).")
            sys.exit(1)
    else:
        print("\nℹ️ Няма промяна в цените спрямо последната проверка. Имейл не е необходим.")


if __name__ == "__main__":
    main()
