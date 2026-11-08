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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

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


async def _fetch_single_cf_page(browser, u: str) -> str | None:
    """Отваря единична Cloudflare страница с 25-секунден таймаут."""
    page = await browser.get(u)
    for _attempt in range(2):
        await page.sleep(4)
        html = await page.get_content()
        title = await page.evaluate("document.title")
        if (
            "just a moment" in str(title).lower()
            or "security verification" in (html or "").lower()
            or not title
        ):
            try:
                await asyncio.wait_for(page.verify_cf(), timeout=10)
                await page.sleep(4)
                html = await page.get_content()
            except Exception:
                pass
        if html and len(html) > 5000 and "security verification" not in html.lower():
            return html
    return None


async def fetch_cloudflare_pages_batch(urls: list[str]) -> dict[str, str]:
    """Отваря Cloudflare-защитените страници (Technovision, Зора) чрез nodriver + verify_cf()."""
    results = {}
    if not urls or not HAS_NODRIVER:
        return results
    browser = None
    try:
        browser = await asyncio.wait_for(
            uc.start(
                headless=False,
                sandbox=False,
                browser_args=["--disable-dev-shm-usage", "--disable-gpu", "--window-size=1280,960"],
            ),
            timeout=20,
        )
        for u in urls:
            try:
                html = await asyncio.wait_for(_fetch_single_cf_page(browser, u), timeout=25)
                if html:
                    results[u] = html
            except Exception as exc:
                print(f"  ⚠️ [Cloudflare Browser] Таймаут/Грешка при {u}: {exc}")
    except Exception as exc:
        print(f"  ⚠️ Неуспешно стартиране на браузър за Cloudflare: {exc}")
    finally:
        if browser:
            try:
                browser.stop()
            except Exception:
                pass
        if sys.platform.startswith("linux"):
            try:
                import subprocess
                subprocess.run(["pkill", "-9", "-f", "chrome"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
    return results


def fetch_html_fast(url: str, cf_cache: dict[str, str], timeout: int = 10) -> str:
    """Извлича HTML от кеша на Cloudflare браузъра или директно чрез curl_cffi / requests."""
    if url in cf_cache:
        return cf_cache[url]
    if HAS_CFFI:
        try:
            resp = cffi_requests.get(url, headers=HEADERS, impersonate="chrome124", timeout=timeout)
            if resp.status_code == 200 and len(resp.text) > 1000:
                return resp.text
            if resp.status_code in (403, 404, 503):
                resp.raise_for_status()
        except Exception as exc:
            if any(d in url.lower() for d in CLOUDFLARE_DOMAINS):
                raise exc
    resp = requests.get(url, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def normalize_to_eur(val: float, currency_hint: str = "EUR") -> float:
    """Нормализира цена в евро (ако е в лева, конвертира по фиксинга 1.95583)."""
    curr = (currency_hint or "EUR").upper()
    if curr in ("BGN", "ЛВ", "ЛВ.") or val > 620.0:
        return round(val / BGN_TO_EUR, 2)
    return round(val, 2)


def extract_price_and_old_price(html: str, url: str):
    """
    Връща (current_price_eur, claimed_old_price_eur, extraction_method).
    Поддържа всички големи вериги в София + софийските сайтове за транспортни дефекти.
    """
    soup = BeautifulSoup(html, "html.parser")
    url_low = url.lower()

    # --- Специализирани парсери за софийските магазини за транспортни дефекти и вериги ---

    # 1. Технохит София (technohit.bg)
    if "technohit.bg" in url_low:
        h4 = soup.select_one("h4.price")
        if h4:
            txt = h4.get_text(" ", strip=True)
            m = re.search(r"(\d+[\.,]\d{2})\s*€", txt)
            m_save = re.search(r"спести\s*(\d+[\.,]\d{2})\s*€", txt, re.IGNORECASE)
            if m:
                cur = float(m.group(1).replace(",", "."))
                old = round(cur + float(m_save.group(1).replace(",", ".")), 2) if m_save else None
                return round(cur, 2), old, "TECHNOHIT_H4"

    # 2. Technovision София (technovision.bg)
    if "technovision.bg" in url_low:
        summary = soup.select_one(".single-product-wrapper") or soup.select_one(".product") or soup
        out_of_stock = summary.select_one("p.stock.out-of-stock") is not None
        box = summary.select_one(".single-product-W-price .electro-price, p.price .electro-price, p.price")
        if box:
            amounts = []
            for a_el in box.select(".woocommerce-Price-amount"):
                m = re.search(r"(\d+[\.,]\d{2})", a_el.get_text(" ", strip=True).replace(" ", ""))
                if m:
                    amounts.append(float(m.group(1).replace(",", ".")))
            if amounts:
                cur = round(amounts[0], 2)
                old = round(amounts[1], 2) if len(amounts) > 1 and amounts[1] > cur else None
                tag = "TECHNOVISION (Изчерпан)" if out_of_stock else "TECHNOVISION"
                return cur, old, tag
        if out_of_stock:
            return None, None, "OUT_OF_STOCK"

    # 3. Technowelt София (technowelt.bg)
    if "technowelt.bg" in url_low:
        wrap = soup.select_one(".price-wrapper")
        if wrap:
            txt = wrap.get_text(" ", strip=True)
            euros = [float(x.replace(",", ".")) for x in re.findall(r"€\s*(\d+[\.,]\d{2})", txt)]
            if euros:
                cur = min(euros)
                old = max(euros) if len(euros) > 1 and max(euros) > cur else None
                return round(cur, 2), old, "TECHNOWELT"

    # 4. Бяла Мания София (bqlamania.eu) и Вимакс София (vimax.bg)
    if "bqlamania.eu" in url_low or "vimax.bg" in url_low:
        p_el = soup.select_one(".product-price-group .product-price")
        if p_el:
            txt = p_el.get_text(" ", strip=True).replace(" ", "")
            m = re.search(r"(\d+[\.,]\d{2})", txt)
            if m:
                return round(float(m.group(1).replace(",", ".")), 2), None, "PRODUCT_PRICE_GROUP"

    # 5. Tech2Home София (tech2home.bg)
    if "tech2home.bg" in url_low:
        ins_el = soup.select_one("ins .woocommerce-Price-amount")
        del_el = soup.select_one("del .woocommerce-Price-amount")
        if ins_el:
            m_cur = re.search(r"(\d+[\.,]\d{2})", ins_el.get_text(" ", strip=True).replace(" ", ""))
            m_old = re.search(r"(\d+[\.,]\d{2})", del_el.get_text(" ", strip=True).replace(" ", "")) if del_el else None
            if m_cur:
                cur = round(float(m_cur.group(1).replace(",", ".")), 2)
                old = round(float(m_old.group(1).replace(",", ".")), 2) if m_old else None
                return cur, old, "TECH2HOME"

    # --- Общи стандартизирани екстрактори (Технополис, Техномаркет, Зора, Техномикс, Техмарт, Практис, JAR, eMAG) ---
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
                    meta_price = float(val.replace(",", ".").replace(" ", ""))
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

    # C. Специфични CSS селектори (eMAG и др.)
    if current_price is None:
        for sel in (".product-new-price", "._product-details-price-new", ".special-price .price"):
            el = soup.select_one(sel)
            if el:
                raw_txt = el.get_text(" ", strip=True)
                m = re.search(r"(\d{3})\s*[\.,\s]\s*(\d{2})", raw_txt)
                if m:
                    p_val = float(f"{m.group(1)}.{m.group(2)}")
                    if p_val > 50:
                        current_price = normalize_to_eur(p_val, "EUR" if "€" in raw_txt else "BGN")
                        method = f"CSS ({sel})"
                        break

    # D. Търсене на зачеркната "стара" цена за детекция на лъжливи намаления
    claimed_old_price = None
    for old_sel in (".product-old-price", ".old-price", ".price_old", "del", "s.price"):
        el = soup.select_one(old_sel)
        if el:
            raw_old = el.get_text(" ", strip=True)
            m = re.search(r"(\d{3,4})\s*[\.,\s]\s*(\d{2})", raw_old)
            if m:
                old_val = float(f"{m.group(1)}.{m.group(2)}")
                if old_val > 100:
                    norm_old = normalize_to_eur(old_val, "EUR" if "€" in raw_old else "EUR")
                    if current_price and norm_old > current_price:
                        claimed_old_price = norm_old
                        break

    return current_price, claimed_old_price, method


def evaluate_black_friday_status(
    current_eur: float,
    claimed_old_eur: float | None,
    baseline: dict,
    store_name: str,
    method: str = "",
) -> tuple[str, str]:
    """
    Оценява текущата цена спрямо таблицата от Точка 2 (средна цена от октомври и реална базова цена).
    """
    oct_avg = baseline["october_avg_eur"]
    fake_thresh = baseline.get("fake_crossed_out_price_threshold_eur", oct_avg * 1.05)

    is_defect_store = any(
        k in store_name.lower()
        for k in ("дефект", "technovision", "технохит", "technowelt", "мания", "tech2home", "релакс", "relax")
    )
    deal_trigger = (
        baseline.get("target_deal_trigger_defect_eur", baseline["target_deal_trigger_eur"])
        if is_defect_store
        else baseline["target_deal_trigger_eur"]
    )

    diff_vs_oct = round(current_eur - oct_avg, 2)
    pct_vs_oct = round((diff_vs_oct / oct_avg) * 100, 1)
    stock_suffix = " [Изчерпан в момента]" if "Изчерпан" in method else ""

    if claimed_old_eur and claimed_old_eur >= fake_thresh and not is_defect_store:
        return (
            "FAKE_DISCOUNT",
            f"⚠️ ЛЪЖЛИВО НАМАЛЕНИЕ: Обявена стара цена {claimed_old_eur:.2f} €, "
            f"а средната през октомври беше {oct_avg:.2f} €!{stock_suffix}",
        )

    if current_eur > oct_avg + 3.0:
        return (
            "ABOVE_OCTOBER",
            f"📈 Над октомврийската средна с +{diff_vs_oct:.2f} € (+{pct_vs_oct}% спрямо {oct_avg:.2f} €){stock_suffix}",
        )

    if current_eur <= deal_trigger:
        return (
            "REAL_DEAL",
            f"🔥 ИСТИНСКА ОФЕРТА! Под прага ({deal_trigger:.2f} €) и с {diff_vs_oct:.2f} € ({pct_vs_oct}%) спрямо октомври!{stock_suffix}",
        )

    return (
        "NORMAL",
        f"Нормална цена ({diff_vs_oct:+.2f} € / {pct_vs_oct:+.1f}% спрямо октомври: {oct_avg:.2f} €){stock_suffix}",
    )


def build_email_html(changes: list[dict], all_results: list[dict], timestamp_str: str) -> str:
    """Генерира HTML имейл с всички засечени промени (поевтиняване ↓ и поскъпване ↑) + пълна таблица."""
    rows_changes = ""
    for ch in changes:
        direction_badge = (
            '<span style="color:#15803d;font-weight:bold;">↓ ПОЕВТИНЯВАНЕ</span>'
            if ch["diff_eur"] < 0
            else '<span style="color:#b91c1c;font-weight:bold;">↑ ПОСКЪПВАНЕ</span>'
        )
        rows_changes += f"""
        <tr>
            <td style="padding:8px;border:1px solid #cbd5e1;"><b>{ch['appliance_name']}</b></td>
            <td style="padding:8px;border:1px solid #cbd5e1;"><a href="{ch['url']}">{ch['store']}</a></td>
            <td style="padding:8px;border:1px solid #cbd5e1;">{ch['old_eur']:.2f} € ({ch['old_bgn']:.2f} лв.)</td>
            <td style="padding:8px;border:1px solid #cbd5e1;"><b>{ch['new_eur']:.2f} € ({ch['new_bgn']:.2f} лв.)</b></td>
            <td style="padding:8px;border:1px solid #cbd5e1;">{direction_badge}<br>{ch['diff_eur']:+.2f} € ({ch['diff_bgn']:+.2f} лв. / {ch['diff_pct']:+.1f}%)</td>
            <td style="padding:8px;border:1px solid #cbd5e1;">{ch['bf_note']}</td>
        </tr>
        """

    rows_all = ""
    for r in all_results:
        if r["price_eur"] is None:
            continue
        rows_all += f"""
        <tr>
            <td style="padding:6px;border:1px solid #e2e8f0;">{r['appliance_name']}</td>
            <td style="padding:6px;border:1px solid #e2e8f0;"><a href="{r['url']}">{r['store']}</a></td>
            <td style="padding:6px;border:1px solid #e2e8f0;"><b>{r['price_eur']:.2f} €</b> ({r['price_bgn']:.2f} лв.)</td>
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
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS", "").strip()
    notify_to = os.environ.get("NOTIFY_EMAIL", smtp_user).strip()

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

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [addr.strip() for addr in notify_to.split(",")], msg.as_string())

    print(f"✅ Успешно изпратено имейл известие до {notify_to}!")
    return True


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

    # Предварително зареждане на Cloudflare-защитените страници (Technovision и Зора)
    cf_urls = [
        entry["url"]
        for app in config["appliances"]
        for entry in app["urls"]
        if any(d in entry["url"].lower() for d in CLOUDFLARE_DOMAINS)
    ]
    cf_cache = {}
    if cf_urls and HAS_NODRIVER:
        print(f"🔓 Отваряне на Cloudflare-защитени сайтове ({len(cf_urls)} линка: Зора, Technovision)...")
        cf_cache = uc.loop().run_until_complete(fetch_cloudflare_pages_batch(cf_urls))

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
                html = fetch_html_fast(url, cf_cache)
                price_eur, claimed_old_eur, method = extract_price_and_old_price(html, url)
            except Exception as exc:
                print(f"  ❌ [{store}] Грешка при достъп: {exc} (запазва се предходният запис).")
                if state_key in previous_state:
                    new_state[state_key] = previous_state[state_key]
                continue

            if price_eur is None:
                print(f"  ⚠️ [{store}] Не бе открита числова цена на страницата (запазва се предходният запис).")
                if state_key in previous_state:
                    new_state[state_key] = previous_state[state_key]
                continue

            price_bgn = round(price_eur * BGN_TO_EUR, 2)
            bf_status, bf_note = evaluate_black_friday_status(price_eur, claimed_old_eur, baseline, store, method)

            old_record = previous_state.get(state_key)
            prev_eur = old_record.get("price_eur") if isinstance(old_record, dict) else None

            if args.simulate_change and prev_eur is not None and not detected_changes:
                prev_eur = round(price_eur + 15.00, 2)

            change_str = "Първо записване"
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

            print(f"  ✅ [{store:<48}] {price_eur:6.2f} € ({price_bgn:6.2f} лв.) | {change_str} | {bf_note}")

            new_state[state_key] = {
                "appliance_id": app_id,
                "appliance_name": app_name,
                "store": store,
                "url": url,
                "price_eur": price_eur,
                "price_bgn": price_bgn,
                "claimed_old_eur": claimed_old_eur,
                "bf_status": bf_status,
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

    md_lines = [
        f"# Последен отчет от Ценовия Бот – Магазини в София ({now_str})",
        "",
        f"- **Проверени оферти в София:** {len(all_results)} магазина (физически вериги + транспортни дефекти в София)",
        f"- **Засечени промени в цените (спрямо предходната проверка):** {len(detected_changes)}",
        "",
        "| Уред | Магазин в София | Текуща цена | Средна Октомври (Т.2) | Статус Черен Петък |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for r in all_results:
        md_lines.append(
            f"| **{r['appliance_name']}** | [{r['store']}]({r['url']}) | **{r['price_eur']:.2f} €** *({r['price_bgn']:.2f} лв.)* | {r['october_avg_eur']:.2f} € | {r['bf_note']} |"
        )
    REPORT_MD_PATH.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if detected_changes or args.force_email:
        if detected_changes:
            drops = sum(1 for c in detected_changes if c["diff_eur"] < 0)
            jumps = sum(1 for c in detected_changes if c["diff_eur"] > 0)
            subject = f"🔔 Промяна в цените на фурните в София ({drops} намаления ↓, {jumps} покачвания ↑) - {now_str}"
        else:
            subject = f"📊 Контролен отчет за цените на фурните в София ({now_str})"

        html_body = build_email_html(detected_changes, all_results, now_str)
        send_email_alert(subject, html_body)
    else:
        print("\nℹ️ Няма промяна в цените спрямо последната проверка. Имейл не е необходим.")


if __name__ == "__main__":
    main()
