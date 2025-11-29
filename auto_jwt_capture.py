#!/usr/bin/env python3
"""
auto_jwt_capture.py

Objetivo: CAPTURAR APENAS O RTOKEN (Google reCAPTCHA v2) de
https://admin.aff.esportesdasorte.com/login (ou outra URL), salvar em /tmp/rtoken_valido.txt
e mostrar infos de contexto extraídas dos arquivos locais (tokens.txt, endpoints.txt).

NÃO faz login. Depois que tiver o rtoken real, você pode manualmente chamar o endpoint
de autenticação (ex: https://boapi.smartico.ai/api-auth) usando curl.

Uso dentro da VM (pasta /vagrant sincroniza com este diretório):
    vagrant ssh -c "python3 /vagrant/data/esporte-da-sorte/infos/auto_jwt_capture.py"

Opções:
  --login-url URL        (default: https://admin.aff.esportesdasorte.com/login)
  --timeout-seconds INT  (default: 180) tempo máximo esperando o rtoken
  --proxy-socks5 HOST:PORT (default: 127.0.0.1:9050)
  --headless             Usa modo headless (não recomendado para captcha manual)
  --show-sitekey         Apenas mostra sitekeys encontradas e sai

Depois de rodar e capturar rtoken:
  vagrant ssh -c "RTOKEN=$(cat /tmp/rtoken_valido.txt); curl --socks5 127.0.0.1:9050 -s -X POST https://boapi.smartico.ai/api-auth -H 'Content-Type: application/json' -d '{\"username\":\"USERNAME\",\"password\":\"PASSWORD\",\"rtoken\":\"'$RTOKEN'\"}' | jq ."

IMPORTANTE: Necessário autorização legal para qualquer teste. Este script é puramente
operacional para o laboratório interno.
"""

import argparse
import os
import sys
import time
from typing import Optional, List

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException

# ---------------------------------------------------------------------------
# Parsing de argumentos
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Captura rtoken reCAPTCHA v2 (manual)")
    p.add_argument("--login-url", default=os.getenv("LOGIN_URL", "https://admin.aff.esportesdasorte.com/login"))
    p.add_argument("--timeout-seconds", type=int, default=int(os.getenv("RTOKEN_TIMEOUT", "180")))
    p.add_argument("--proxy-socks5", default=os.getenv("PROXY_SOCKS5", "127.0.0.1:9050"))
    p.add_argument("--headless", action="store_true", help="Executa navegador em modo headless")
    p.add_argument("--show-sitekey", action="store_true", help="Somente mostra sitekeys e sai")
    p.add_argument("--user-agent", default=os.getenv("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"), help="User-Agent para reduzir detecção")
    return p.parse_args()

# ---------------------------------------------------------------------------
# Utilidades para ler arquivos locais de info
# ---------------------------------------------------------------------------

BASE_INFO_DIR = os.path.abspath(os.path.dirname(__file__))

def read_file_lines(name: str) -> List[str]:
    path = os.path.join(BASE_INFO_DIR, name)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []

def extract_sitekeys() -> List[str]:
    keys = []
    for fname in ("tokens.txt", "endpoints.txt", "jwt.txt"):
        for line in read_file_lines(fname):
            line=line.strip()
            if len(line) >= 30 and ("6L" in line) and ("AAAA" in line or "AA" in line):  # heurística simples
                # Evitar duplicados
                if line not in keys:
                    keys.append(line)
    # Limpar ruído (se a linha tiver espaços, pegar só o token tipo key)
    cleaned = []
    for k in keys:
        if ' ' in k:
            parts = [p for p in k.split() if p.startswith('6L')]
            cleaned.extend(parts)
        else:
            cleaned.append(k)
    # Deduplicar final
    uniq = []
    for k in cleaned:
        if k not in uniq:
            uniq.append(k)
    return uniq

# ---------------------------------------------------------------------------
# Browser
# ---------------------------------------------------------------------------

def start_browser(proxy: str, headless: bool, user_agent: str) -> webdriver.Chrome:
    opts = Options()
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--lang=pt-BR')
    opts.add_argument(f'--proxy-server=socks5://{proxy}')
    opts.add_argument(f'--user-agent={user_agent}')
    # Reduz indicadores de automação
    opts.add_experimental_option("excludeSwitches", ["enable-automation"]) 
    opts.add_experimental_option('useAutomationExtension', False)
    opts.add_argument('--disable-blink-features=AutomationControlled')
    if headless:
        opts.add_argument('--headless=new')
    try:
        driver = webdriver.Chrome(options=opts)
        try:
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            })
        except Exception:
            pass
        return driver
    except WebDriverException:
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=opts)
            try:
                driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                    "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                })
            except Exception:
                pass
            return driver
        except Exception as e:
            print(f'[-] Falha ao iniciar Chrome: {e}')
            raise

# ---------------------------------------------------------------------------
# Captura rtoken
# ---------------------------------------------------------------------------

def _try_execute_invisible_recaptcha(driver) -> bool:
        try:
                return bool(driver.execute_script(
                        """
                        try {
                            if (typeof grecaptcha !== 'undefined' && grecaptcha.execute) {
                                // tenta obter sitekeys conhecidos em elementos
                                var sitekey = null;
                                var el = document.querySelector('[data-sitekey]');
                                if (el) { sitekey = el.getAttribute('data-sitekey'); }
                                // fallback: busca por iframe src com k
                                if (!sitekey) {
                                    var ifr = document.querySelector('iframe[src*="recaptcha"]');
                                    if (ifr) {
                                        var m = /[?&]k=([^&]+)/.exec(ifr.src);
                                        if (m) { sitekey = decodeURIComponent(m[1]); }
                                    }
                                }
                                // se tiver sitekey, executa; senão, executa padrão
                                if (sitekey) {
                                    grecaptcha.execute(sitekey, {action: 'login'});
                                } else {
                                    grecaptcha.execute();
                                }
                                return true;
                            }
                        } catch (e) {}
                        return false;
                        """
                ))
        except Exception:
                return False

def capture_rtoken(driver, timeout: int) -> Optional[str]:
    print(f"[*] Aguardando rtoken (timeout {timeout}s)...")
    print("[*] Tentando detectar e interagir com elementos de login para forçar captcha...")
    
    # Tenta preencher campos (pode trigger captcha invisível)
    try:
        username_field = driver.find_element(By.CSS_SELECTOR, "input[type='email'], input[name='username'], input[id*='user'], input[placeholder*='mail'], input[placeholder*='user']")
        username_field.click()
        username_field.send_keys("test@example.com")
        print("[*] Campo username preenchido (teste)")
    except Exception:
        print("[!] Campo username não encontrado")
    
    try:
        password_field = driver.find_element(By.CSS_SELECTOR, "input[type='password'], input[name='password']")
        password_field.click()
        password_field.send_keys("TestPassword123")
        print("[*] Campo password preenchido (teste)")
    except Exception:
        print("[!] Campo password não encontrado")
    
    # Procura iframes de captcha
    try:
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        captcha_found = False
        for iframe in iframes:
            src = iframe.get_attribute("src") or ""
            if "recaptcha" in src.lower():
                captcha_found = True
                print(f"[+] iframe reCAPTCHA detectado: {src[:80]}...")
                break
        if not captcha_found:
            print("[!] Nenhum iframe reCAPTCHA visível ainda. Pode ser invisible ou carregar após submit.")
    except Exception:
        pass
    
    print("[*] Observando campo g-recaptcha-response...")
    print("[*] Se captcha checkbox aparecer, CLIQUE NELE.")
    print("[*] Detectando botão submit para triggerar captcha invisible...")
    
    # Tenta clicar no submit para forçar invisible captcha
    try:
        time.sleep(2)
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit'], button[type='button'], input[type='submit'], button")
        submit_btn.click()
        print("[+] Botão submit clicado - aguardando captcha invisible...")
        time.sleep(3)
    except Exception as e:
        print(f"[!] Não encontrou botão submit: {e}")

    # Força execução do grecaptcha.execute() se disponível
    forced = _try_execute_invisible_recaptcha(driver)
    if forced:
        print("[+] Tentativa de grecaptcha.execute() disparada.")
    else:
        print("[!] grecaptcha.execute() não disponível nesta página ou bloqueado.")
    
    rtoken = None
    for i in range(timeout):
        try:
            val = driver.execute_script(
                """
                var el = document.getElementById('g-recaptcha-response');
                if (!el) { el = document.querySelector('textarea[name="g-recaptcha-response"]'); }
                return el ? el.value : '';
                """
            )
            if val and len(val) > 350:
                rtoken = val
                print(f"[+] rtoken capturado (len={len(rtoken)}) parcial: {rtoken[:60]}...")
                break
            # A cada 10s mostra status
            if i > 0 and i % 10 == 0:
                print(f"[*] Ainda aguardando... ({i}/{timeout}s)")
        except Exception:
            pass
        time.sleep(1)
    if not rtoken:
        print("[-] rtoken não apareceu. Possíveis causas:")
        print("    - Captcha não foi resolvido/clicado")
        print("    - Captcha invisible não foi trigado (tente submit/login)")
        print("    - Página usa outro mecanismo de proteção")
    return rtoken
    return rtoken

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    sitekeys = extract_sitekeys()
    if sitekeys:
        print("[i] Sitekeys detectadas nos arquivos locais:")
        for k in sitekeys:
            print(f"    - {k}")
    else:
        print("[i] Nenhuma sitekey extraída dos arquivos locais.")

    if args.show_sitekey:
        print("[✓] Encerrando (--show-sitekey).")
        return

    try:
        driver = start_browser(args.proxy_socks5, headless=args.headless, user_agent=args.user_agent)
    except Exception:
        print("[-] Abortando: não foi possível iniciar navegador.")
        sys.exit(1)

    print(f"[*] Abrindo página de login: {args.login_url}")
    driver.get(args.login_url)
    time.sleep(6)

    rtoken = capture_rtoken(driver, args.timeout_seconds)
    if not rtoken:
        driver.quit()
        sys.exit(2)

    with open('/tmp/rtoken_valido.txt', 'w') as f:
        f.write(rtoken)
    print('[+] rtoken salvo em /tmp/rtoken_valido.txt')
    print('[*] Use agora manualmente:')
    print("    vagrant ssh -c \"RTOKEN=$(cat /tmp/rtoken_valido.txt); curl --socks5 127.0.0.1:9050 -s -X POST https://boapi.smartico.ai/api-auth -H 'Content-Type: application/json' -d '{\\\"username\\\":\\\"USERNAME\\\",\\\"password\\\":\\\"PASSWORD\\\",\\\"rtoken\\\":\\\"'$RTOKEN'\\\"}' | jq .\"")

    print('[*] Fechando navegador em 5s...')
    time.sleep(5)
    driver.quit()
    print('[✓] Concluído.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n[!] Interrompido.')
        sys.exit(130)














<!DOCTYPE HTML><html dir="ltr" lang="en"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>reCAPTCHA</title>
<style type="text/css">
/* cyrillic-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu72xKOzY.woff2) format('woff2');
  unicode-range: U+0460-052F, U+1C80-1C8A, U+20B4, U+2DE0-2DFF, U+A640-A69F, U+FE2E-FE2F;
}
/* cyrillic */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu5mxKOzY.woff2) format('woff2');
  unicode-range: U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116;
}
/* greek-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7mxKOzY.woff2) format('woff2');
  unicode-range: U+1F00-1FFF;
}
/* greek */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4WxKOzY.woff2) format('woff2');
  unicode-range: U+0370-0377, U+037A-037F, U+0384-038A, U+038C, U+038E-03A1, U+03A3-03FF;
}
/* vietnamese */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7WxKOzY.woff2) format('woff2');
  unicode-range: U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;
}
/* latin-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu7GxKOzY.woff2) format('woff2');
  unicode-range: U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;
}
/* latin */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4mxK.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
/* cyrillic-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCRc4EsA.woff2) format('woff2');
  unicode-range: U+0460-052F, U+1C80-1C8A, U+20B4, U+2DE0-2DFF, U+A640-A69F, U+FE2E-FE2F;
}
/* cyrillic */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fABc4EsA.woff2) format('woff2');
  unicode-range: U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116;
}
/* greek-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCBc4EsA.woff2) format('woff2');
  unicode-range: U+1F00-1FFF;
}
/* greek */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBxc4EsA.woff2) format('woff2');
  unicode-range: U+0370-0377, U+037A-037F, U+0384-038A, U+038C, U+038E-03A1, U+03A3-03FF;
}
/* vietnamese */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fCxc4EsA.woff2) format('woff2');
  unicode-range: U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;
}
/* latin-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fChc4EsA.woff2) format('woff2');
  unicode-range: U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;
}
/* latin */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmEU9fBBc4.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
/* cyrillic-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 900;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCRc4EsA.woff2) format('woff2');
  unicode-range: U+0460-052F, U+1C80-1C8A, U+20B4, U+2DE0-2DFF, U+A640-A69F, U+FE2E-FE2F;
}
/* cyrillic */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 900;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfABc4EsA.woff2) format('woff2');
  unicode-range: U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116;
}
/* greek-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 900;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCBc4EsA.woff2) format('woff2');
  unicode-range: U+1F00-1FFF;
}
/* greek */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 900;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfBxc4EsA.woff2) format('woff2');
  unicode-range: U+0370-0377, U+037A-037F, U+0384-038A, U+038C, U+038E-03A1, U+03A3-03FF;
}
/* vietnamese */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 900;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfCxc4EsA.woff2) format('woff2');
  unicode-range: U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;
}
/* latin-ext */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 900;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfChc4EsA.woff2) format('woff2');
  unicode-range: U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;
}
/* latin */
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 900;
  src: url(//fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmYUtfBBc4.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}

</style>
<link rel="stylesheet" type="text/css" href="https://www.gstatic.com/recaptcha/releases/TkacYOdEJbdB_JjX802TMer9/styles__ltr.css">
<script nonce="EoKZftVtmBRFuuW3nC6C3g" type="text/javascript">window['__recaptcha_api'] = 'https://www.google.com/recaptcha/api2/';</script>
<script type="text/javascript" src="https://www.gstatic.com/recaptcha/releases/TkacYOdEJbdB_JjX802TMer9/recaptcha__en.js" nonce="EoKZftVtmBRFuuW3nC6C3g">
      
    </script></head>
<body><div id="rc-anchor-alert" class="rc-anchor-alert"></div>
<input type="hidden" id="recaptcha-token" value="03AFcWeA5O4staSQLXjRb742eix7bJhelDsCbLQp1jQukLNVWMJ6es4cAN0A16DCBUzxoEHpktGK9Oy_AJcF31FeqZZs1K38sYEwQ1qsP9uEF65fNKJn2Ud2pV-0WbcgyGDStWTBTLxefkFrW9E5rpSXmWnOGAXut_eXwgcLUtqpOCAkGz9FxfnWz01YrY1M5alYwtyLkUwsau0T2Vq7vk15wgT4NVjY1zwXSJ76CERDvFESWGe5gAxNoeW-qnts3VMPcKbvlzppwv0-GOgbMIB8Y5IgeWJ-rLNMQgY9n1xStp8QkajciOTd4bBQiAQaGVt2P10N-zEcnq1KBTFULjiuZrUHyPjoI3IhmPZ6djunbOtJ9QOyrnJY6sdc94qgkLOybBCWuF8OTtfKLRR4tcMIvDJj3QW5t-Pv4tKipbq96GzAcTXuoqaFA163ASPx3-yazyBEZssgdT0oOX15beowejuecyPkAzwRMjYEJ3-k6QskLJtLIK_m5rRCKWLdSGwFM83tLOh47lVqXAHFwrTCxQGHqeOLyUnh6oObP3MpjylNNKuyFSSrjeob9pGMufEh-vu4p8S2DcjXs6D9IxiJrDU3BCrTaz8Q9nNKgDDgZLRm-pJlAtaVV1mGTLRKGVCIw6wcai1trmqwF1D50F5q0KLfiA6ifcfFaXDc8fvAJoWbDqvOKzQmCSz-J3U9vxFNu1Bz4RT00rnR1Xh0JwOoJ7Ai731rEqCy1K8XlezdOf32ubZ6G9UESAg-1vcqRccrqlVTfmg_Ub4htd2wptDsq1YBX92GTK83OcRTOOsOU06VzzPmX1V6dmedyTGbUKF4C26PuONJZfSW9wv0i3mLQJcXWteOSf_cBUHTi1DvHtVzAHe4TtGm0CHCfQKSW_Pj8YQm8mkujjeMvlCD-NB8_aT75AFF0tReYlMtuuQxZVeqIuWVjZFXshiwWDvbSbPD0gNxOGJlLv9V4x-iDUY0i5owrSW_0doKMET5JAer6tO06-yQZqbzcC79KLQnnN-WfiS7w-c-RkhoLgYgRFvZLog189HlYUC714RNLJzFU1SR3rxFCantj3hYo7Qrbzzen90eh9QwfsPvnbxPqgLOmXylF_jPuv7V9Bp33KlKKEPQFcmHEgE0LtWGokXKHPDUeACXvOu7K0j76oiKGS1sJX72Zy3xA9QJy5tSopp8Oj4a725EFWQiWFHlKd0HcPEEgVTBhQL0moJaC_kcbTXikz1q8Qpn_t2YiykKOa8BAs_fBQT246TodyRWfgIN9ZTDbwvc2IThxc5mX_2vWUaHRHBnKk8ja9aTFLGcw3rdiq18MpyHOFOUOuR1IPj43wUVtMAFHd_HM2zLiLD6mPMkv_a-004AfJHVKPEfILMMNKWUdJxL_UkP8sXthlnWAjvntev9-ZcZ1NiWl1A533f-Uadk7v97oUgB9wfoxbcj-nu7tx846TSo4ZzazHKULWrvID7gYwEDfFCvbxbMmi0MTkM660AIKi2xQ02LYVcuV6Y5Qnaq0gwSwjkyu2Wde5k6eMYzK-cuf1eSX7ro7miScPcxTj-eM1E5Y1yK-Dffe6Pdk0_AUxIOMAlTE2iEYWL47NH4uEY8yA42SiKu8agWUPDZ_DlvIJqoIZWK63aCXrJ8fkXaPM_rzgZwFJiO7c4flqQDKR0PKfgiLCuKqLQGPspNNa1ReC7Q">
<script type="text/javascript" nonce="EoKZftVtmBRFuuW3nC6C3g">
      recaptcha.anchor.Main.init("[\x22ainput\x22,[\x22bgdata\x22,\x22\x22,\x22LyogQW50aS1zcGFtLiBXYW50IHRvIHNheSBoZWxsbz8gQ29udGFjdCAoYmFzZTY0KSBZbTkwWjNWaGNtUXRZMjl1ZEdGamRFQm5iMjluYkdVdVkyOXQgKi8gKGZ1bmN0aW9uKCl7dmFyIFQ9ZnVuY3Rpb24oZSxhKXtpZigoZT0oYT1udWxsLFYpLnRydXN0ZWRUeXBlcywhZSl8fCFlLmNyZWF0ZVBvbGljeSlyZXR1cm4gYTt0cnl7YT1lLmNyZWF0ZVBvbGljeSgiYmciLHtjcmVhdGVIVE1MOnQsY3JlYXRlU2NyaXB0OnQsY3JlYXRlU2NyaXB0VVJMOnR9KX1jYXRjaChnKXtWLmNvbnNvbGUmJlYuY29uc29sZS5lcnJvcihnLm1lc3NhZ2UpfXJldHVybiBhfSx0PWZ1bmN0aW9uKGUpe3JldHVybiBlfSxWPXRoaXN8fHNlbGY7KDAsZXZhbCkoZnVuY3Rpb24oZSxhKXtyZXR1cm4oYT1UKCkpJiZlLmV2YWwoYS5jcmVhdGVTY3JpcHQoIjEiKSk9PT0xP2Z1bmN0aW9uKGcpe3JldHVybiBhLmNyZWF0ZVNjcmlwdChnKX06ZnVuY3Rpb24oZyl7cmV0dXJuIiIrZ319KFYpKEFycmF5KE1hdGgucmFuZG9tKCkqNzgyNHwwKS5qb2luKCJcbiIpK1snKGZ1bmN0aW9uKCl7LyonLAonJywKJyBDb3B5cmlnaHQgR29vZ2xlIExMQycsCicgU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IEFwYWNoZS0yLjAnLAonKi8nLAondmFyIGVZPWZ1bmN0aW9uKGUsYSl7ZnVuY3Rpb24gZygpe3RoaXMubj0odGhpcy5oPVtdLDApfXJldHVybiBlPW5ldyAoYT0oZy5wcm90b3R5cGUuZmI9ZnVuY3Rpb24oKXtpZih0aGlzLm49PT0wKXJldHVyblswLDBdO3JldHVybiB0aGlzLmguc29ydChmdW5jdGlvbih0LFQpe3JldHVybiB0LVR9KSxbdGhpcy5uLHRoaXMuaFt0aGlzLmgubGVuZ3RoPj4xXV19LGcucHJvdG90eXBlLlRGPWZ1bmN0aW9uKHQsVCl7KHRoaXMubisrLHRoaXMuaCkubGVuZ3RoPDUwP3RoaXMuaC5wdXNoKHQpOihUPU1hdGguZmxvb3IoTWF0aC5yYW5kb20oKSp0aGlzLm4pLFQ8NTAmJih0aGlzLmhbVF09dCkpfSxuZXcgZyksZyksW2Z1bmN0aW9uKHQpeyhhLlRGKHQpLGUpLlRGKHQpfSxmdW5jdGlvbih0KXtyZXR1cm4gZT1uZXcgKHQ9YS5mYigpLmNvbmNhdChlLmZiKCkpLGcpLHR9XX0sYVI9ZnVuY3Rpb24oZSxhLGcsdCl7bSgodD0oZz1CKGUpLEIoZSkpLHQpLEQoYSx4KGUsZykpLGUpfSxvUj1mdW5jdGlvbihlLGEpe3JldHVybihhPUkoZSksYSkmMTI4JiYoYT1hJjEyN3xJKGUpPDw3KSxhfSxjPXRoaXN8fHNlbGYsZ1U9ZnVuY3Rpb24oZSxhKXsoKGEucHVzaChlWzBdPDwyNHxlWzFdPDwxNnxlWzJdPDw4fGVbM10pLGEpLnB1c2goZVs0XTw8MjR8ZVs1XTw8MTZ8ZVs2XTw8OHxlWzddKSxhKS5wdXNoKGVbOF08PDI0fGVbOV08PDE2fGVbMTBdPDw4fGVbMTFdKX0sQT17cGFzc2l2ZTp0cnVlLGNhcHR1cmU6dHJ1ZX0sVlA9ZnVuY3Rpb24oZSxhLGcsdCl7Zm9yKGc9KHQ9QihlKSwwKTthPjA7YS0tKWc9Zzw8OHxJKGUpO3IoZSx0LGcpfSxUTT1mdW5jdGlvbihlLGEsZyx0LFQsQyxaLEUseSl7cmV0dXJuKHk9cVtlLnN1YnN0cmluZygwLDMpKyJfIl0pP3koZS5zdWJzdHJpbmcoMyksYSxnLHQsVCxDLFosRSk6dGwoZSxhKX0sVTU9ZnVuY3Rpb24oZSxhKXtmdW5jdGlvbiBnKCl7dGhpcy5HPXRoaXMuTGI9dGhpcy5uPTB9cmV0dXJuW2Z1bmN0aW9uKHQpeyhhLm1BKHQpLGUpLm1BKHQpfSwoZT1uZXcgKGE9KChnLnByb3RvdHlwZS5CZD1mdW5jdGlvbigpe3JldHVybiB0aGlzLm49PT0wPzA6TWF0aC5zcXJ0KHRoaXMuTGIvdGhpcy5uKX0sZy5wcm90b3R5cGUpLm1BPWZ1bmN0aW9uKHQsVCl7dGhpcy5MYis9KHRoaXMuRys9KFQ9dC10aGlzLkcsdGhpcy5uKyssVC90aGlzLm4pLFQpKih0LXRoaXMuRyl9LG5ldyBnKSxnKSxmdW5jdGlvbih0KXtyZXR1cm4gZT0odD1bYS5CZCgpLGUuQmQoKSxhLkcsZS5HXSxuZXcgZyksdH0pXX0sTzU9ZnVuY3Rpb24oZSxhLGcsdCxUKXtmdW5jdGlvbiBDKCl7fXJldHVybiB0PShnPShlPVRNKChUPXZvaWQgMCxlKSxmdW5jdGlvbihaKXtDJiYoYSYmczUoYSksVD1aLEMoKSxDPXZvaWQgMCl9LCEhYSksZSlbMF0sZVsxXSkse2ludm9rZTpmdW5jdGlvbihaLEUseSxkKXtmdW5jdGlvbiBWKCl7VChmdW5jdGlvbihVKXtzNShmdW5jdGlvbigpe1ooVSl9KX0seSl9aWYoIUUpcmV0dXJuIEU9Zyh5KSxaJiZaKEUpLEU7VD9WKCk6KGQ9QyxDPWZ1bmN0aW9uKCl7KGQoKSxzNSkoVil9KX0scGU6ZnVuY3Rpb24oWil7dCYmdChaKX19fSxtPWZ1bmN0aW9uKGUsYSxnLHQsVCxDKXtpZihnLkw9PWcpZm9yKEM9eChnLGUpLGU9PTQzMHx8ZT09MzR8fGU9PTE2ND8oZT1mdW5jdGlvbihaLEUseSxkKXtpZigoZD0oKHk9Qy5sZW5ndGgseSl8MCktND4+MyxDKS52ZCE9ZCl7RT1bMCwoZD0oQy52ZD1kLGQ8PDMpLTQsMCksVFsxXSxUWzJdXTt0cnl7Qy5zVT1ZUyhFLGlfKGQsQyksaV8oKGR8MCkrNCxDKSl9Y2F0Y2goVil7dGhyb3cgVjt9fUMucHVzaChDLnNVW3kmN11eWil9LFQ9eChnLDgzKSk6ZT1mdW5jdGlvbihaKXtDLnB1c2goWil9LHQmJmUodCYyNTUpLGc9YS5sZW5ndGgsdD0wO3Q8Zzt0KyspZShhW3RdKX0sQ3E9ZnVuY3Rpb24oZSxhKXtpZighKGU9KGE9bnVsbCxjLnRydXN0ZWRUeXBlcyksZSl8fCFlLmNyZWF0ZVBvbGljeSlyZXR1cm4gYTt0cnl7YT1lLmNyZWF0ZVBvbGljeSgiYmciLHtjcmVhdGVIVE1MOmpZLGNyZWF0ZVNjcmlwdDpqWSxjcmVhdGVTY3JpcHRVUkw6all9KX1jYXRjaChnKXtjLmNvbnNvbGUmJmMuY29uc29sZS5lcnJvcihnLm1lc3NhZ2UpfXJldHVybiBhfSxyPWZ1bmN0aW9uKGUsYSxnKXtpZihhPT0zNDJ8fGE9PTUxMCllLlhbYV0/ZS5YW2FdLmNvbmNhdChnKTplLlhbYV09JFMoZyxlKTtlbHNle2lmKGUuQ2ImJmEhPTgpcmV0dXJuO2E9PTE2OHx8YT09NDMwfHxhPT0zOTZ8fGE9PTE2NHx8YT09NTZ8fGE9PTE5MXx8YT09MTE1fHxhPT04M3x8YT09MzR8fGE9PTEwNj9lLlhbYV18fChlLlhbYV09QngoZSw2MixnLGEpKTplLlhbYV09QngoZSwxMjksZyxhKX1hPT04JiYoZS5vPUwoZSwzMixmYWxzZSksZS5pPXZvaWQgMCl9LHEsWmQ9ZnVuY3Rpb24oZSxhKXtyZXR1cm4gYT0wLGZ1bmN0aW9uKCl7cmV0dXJuIGE8ZS5sZW5ndGg/e2RvbmU6ZmFsc2UsdmFsdWU6ZVthKytdfTp7ZG9uZTp0cnVlfX19LEJ4PWZ1bmN0aW9uKGUsYSxnLHQsVCxDLFosRSl7cmV0dXJuKFo9KEU9RTUsZz1bLTIxLDI4LDgwLC0oVD1hJjcsNyksLTgwLC05MyxnLC02Niw5Nyw1N10sSClbZS5TXShlLlE5KSxaW2UuU109ZnVuY3Rpb24oeSl7VCs9NisoQz15LDcpKmEsVCY9N30sWikuY29uY2F0PWZ1bmN0aW9uKHkpe3JldHVybih5PSh5PSh5PXQlMTYrMSwyNzcyKkMtOTI0KnQqQytnW1QrNTEmN10qdCp5KSsoRSgpfDApKnkrMSp0KnQqeS15KkMrMzMqQypDK1QtMzMqdCp0KkMsZ1t5XSksQz12b2lkIDAsZ1soVCsxMyY3KSsoYSYyKV09eSxnKVtUKyhhJjIpXT0yOCx5fSxafSxsPWZ1bmN0aW9uKGUsYSxnKXtyKGcsZSxhKSxhW21qXT0yNzk2fSxNaz1mdW5jdGlvbihlLGEsZyx0LFQsQyl7aWYoQz1hWzBdLEM9PXlQKXtpZih0PWUuVyhhKSl0LldkPWMuc2V0VGltZW91dChmdW5jdGlvbihaKXsodigoWj0hKHQuY2Q9dHJ1ZSxlLlkpLmxlbmd0aCYmIWUuUix0Lm95KSxlKSx2KSh0LmVZLGUpLFomJkoodHJ1ZSxlLHRydWUpfSx0LnRpbWVvdXQpLGUuSi5wdXNoKHQpfWVsc2UgaWYoQz09bnEpZS5GPXRydWUsZS5SeT0yNSxlLlVVPWUuSSgpLWFbMl0sZS5XKGEpO2Vsc2UgaWYoQz09dSl7Zz1hWzFdWzNdO3RyeXtUPWUuS3x8ZS5XKGEpfWNhdGNoKFope0RkKGUsWiksVD1lLkt9KGcoKGE9ZS5IKCksVCkpLGUpLkMrPWUuSCgpLWF9ZWxzZSBpZihDPT1kVSlhWzNdJiYoZS52PXRydWUpLGFbNF0mJihlLkY9dHJ1ZSksZS5XKGEpO2Vsc2UgaWYoQz09Yl8pZS52PXRydWUsZS5XKGEpO2Vsc2UgaWYoQz09eFMpe3RyeXtmb3IoVD0wO1Q8ZS5Yby5sZW5ndGg7VCsrKXRyeXtnPWUuWG9bVF0sZ1swXVtnWzFdXShnWzJdKX1jYXRjaChaKXt9fWNhdGNoKFope30oKDAsYVsxXSkoZnVuY3Rpb24oWixFKXtlLkVVKFosdHJ1ZSxFKX0sKFQ9KGUuWG89W10sZS5IKCkpLGZ1bmN0aW9uKFope3YoW0txXSwoWj0hZS5ZLmxlbmd0aCYmIWUuUixlKSksWiYmSih0cnVlLGUsZmFsc2UpfSksZnVuY3Rpb24oWil7cmV0dXJuIGUuYnAoWil9LGZ1bmN0aW9uKFosRSx5KXtyZXR1cm4gZS55OShaLEUseSl9KSxlKS5DKz1lLkgoKS1UfWVsc2V7aWYoQz09SVIpcmV0dXJuIFQ9YVsyXSxyKGUsMTIzLGFbNl0pLHIoZSwzNDYsVCksZS5XKGEpO0M9PUtxPyhlLlg9bnVsbCxlLnU9W10sZS5IZD1bXSk6Qz09bWomJmMuZG9jdW1lbnQucmVhZHlTdGF0ZT09PSJsb2FkaW5nIiYmKGUuVT1mdW5jdGlvbihaLEUpe2Z1bmN0aW9uIHkoKXtFfHwoRT10cnVlLFooKSl9Yy5kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCJET01Db250ZW50TG9hZGVkIix5LChFPWZhbHNlLEEpKSxjLmFkZEV2ZW50TGlzdGVuZXIoImxvYWQiLHksQSl9KX19LFB4PWZ1bmN0aW9uKGUsYSxnKXtpZihlLmxlbmd0aD09Myl7Zm9yKGc9MDtnPDM7ZysrKWFbZ10rPWVbZ107Zm9yKGc9KGU9WzEzLDgsMTMsMTIsMTYsNSwzLDEwLDE1XSwwKTtnPDk7ZysrKWFbM10oYSxnJTMsZVtnXSl9fSxEPWZ1bmN0aW9uKGUsYSxnLHQpe2Zvcih0PShlfDApLTEsZz1bXTt0Pj0wO3QtLSlnWyhlfDApLTEtKHR8MCldPWE+PnQqOCYyNTU7cmV0dXJuIGd9LEw9ZnVuY3Rpb24oZSxhLGcsdCxULEMsWixFLHksZCxWLFUsTyxZKXtpZigoRT14KGUsMzQyKSxFKT49ZS5CKXRocm93W1gsMzFdO2Zvcih0PUUseT1hLFU9ZS53Ui5sZW5ndGgsQz0wO3k+MDspTz10JTgsVD04LShPfDApLFQ9VDx5P1Q6eSxkPXQ+PjMsVj1lLnVbZF0sZyYmKFo9ZSxaLmkhPXQ+PjYmJihaLmk9dD4+NixZPXgoWiw4KSxaLlNZPVlTKFswLDAsWVsxXSxZWzJdXSxaLm8sWi5pKSksVl49ZS5TWVtkJlVdKSxDfD0oVj4+OC0oT3wwKS0oVHwwKSYoMTw8VCktMSk8PCh5fDApLShUfDApLHktPVQsdCs9VDtyZXR1cm4gcigoZz1DLGUpLDM0MiwoRXwwKSsoYXwwKSksZ30seD1mdW5jdGlvbihlLGEpe2lmKChlPWUuWFthXSxlKT09PXZvaWQgMCl0aHJvd1tYLDMwLGFdO2lmKGUudmFsdWUpcmV0dXJuIGUuY3JlYXRlKCk7cmV0dXJuKGUuY3JlYXRlKGEqMSphKzI4KmErLTg0KSxlKS5wcm90b3R5cGV9LGpZPWZ1bmN0aW9uKGUpe3JldHVybiBlfSxyVT1mdW5jdGlvbihlLGEsZyx0KXtyZXR1cm4geChhLChyKGEsMzQyLChBbCgoKHQ9eChhLDM0MiksYS51KSYmdDxhLkI/KHIoYSwzNDIsYS5CKSxjeChhLGcpKTpyKGEsMzQyLGcpLGUpLGEpLHQpKSwzNDYpKX0sUVA9ZnVuY3Rpb24oZSxhLGcsdCxUKXtmb3IodD0oVD0oZT1lLnJlcGxhY2UoL1xcclxcbi9nLCJcXG4iKSxhPTAsW10pLDApO3Q8ZS5sZW5ndGg7dCsrKWc9ZS5jaGFyQ29kZUF0KHQpLGc8MTI4P1RbYSsrXT1nOihnPDIwNDg/VFthKytdPWc+PjZ8MTkyOigoZyY2NDUxMik9PTU1Mjk2JiZ0KzE8ZS5sZW5ndGgmJihlLmNoYXJDb2RlQXQodCsxKSY2NDUxMik9PTU2MzIwPyhnPTY1NTM2KygoZyYxMDIzKTw8MTApKyhlLmNoYXJDb2RlQXQoKyt0KSYxMDIzKSxUW2ErK109Zz4+MTh8MjQwLFRbYSsrXT1nPj4xMiY2M3wxMjgpOlRbYSsrXT1nPj4xMnwyMjQsVFthKytdPWc+PjYmNjN8MTI4KSxUW2ErK109ZyY2M3wxMjgpO3JldHVybiBUfSxobD1mdW5jdGlvbihlLGEsZyx0LFQpeyhUPXgoYSwoZz1CKChUPUIoKGUmPSh0PWUmNCwzKSxhKSksYSkpLFQpKSx0KSYmKFQ9UVAoIiIrVCkpLGUmJm0oZyxEKDIsVC5sZW5ndGgpLGEpLG0oZyxULGEpfSxKbD1mdW5jdGlvbihlLGEsZyx0LFQsQyxaLEUseSxkKXtmb3IoeT0oZS54Nj0oZS5ROT1McSgoZS5rNj1GVyxlLndSPShlLkptPXFrLGVbdV0pLGUuUykse2dldDpmdW5jdGlvbigpe3JldHVybiB0aGlzLmNvbmNhdCgpfX0pLEhbZS5TXShlLlE5LHt2YWx1ZTp7dmFsdWU6e319fSkpLGQ9MCxbXSk7ZDwzOTA7ZCsrKXlbZF09U3RyaW5nLmZyb21DaGFyQ29kZShkKTtpZigoKGUudG09KGUuRGI9KGUuaT12b2lkIDAsZS5VPW51bGwsZS5SPWZhbHNlLFtdKSxlLmRSPShlLlQ9KGUuWXI9dCxlLlhvPVtdLHZvaWQgMCksZS5LPShlLlVVPTAsdm9pZCAwKSxlLlA9KGUuRj1mYWxzZSxlLlo9dm9pZCAwLFtdKSwhKChlLlk9W10sKGUuTz0xLGUpLlY9dm9pZCAwLGUpLnY9ZmFsc2UsKChlLkhkPVtdLGUpLnU9W10sZSkubz12b2lkIDAsZS5OPTAsZS5YPShlLktiPXZvaWQgMCxbXSksZS5qPTAsZS5uYj0oZS5SeT0yNSxlLmhtPVtdLGZ1bmN0aW9uKFYpe3RoaXMuTD1WfSksZD0oZS5DYj1mYWxzZSx3aW5kb3cucGVyZm9ybWFuY2V8fHt9KSxlLlNZPShlLnpGPWcsZS5xUT0hKGUuTVE9MCwxKSxlLmc9MCwoZS5DPTAsZSkubD0wLGUuVjk9MCx2b2lkIDApLGUuSj0oZS5MPWUsZS5CPTAsZS5BPTAsW10pLDEpKSwxMDAwMSksZSkuRm89ZC50aW1lT3JpZ2lufHwoZC50aW1pbmd8fHt9KS5uYXZpZ2F0aW9uU3RhcnR8fDAsVCYmVC5sZW5ndGg9PTIpJiYoZS5EYj1UWzFdLGUuaG09VFswXSksRSl0cnl7ZS5LYj1KU09OLnBhcnNlKEUpfWNhdGNoKFYpe2UuS2I9e319Sih0cnVlLCh2KCgobCg1MDcsKGwoMzM3LGZ1bmN0aW9uKCl7fSwobCgzOTUsKChyKGUsNDgzLChyKGUsNDkyLChyKGUsMzk2LChyKGUsKGwoNDg4LGZ1bmN0aW9uKFYsVSxPLFksbil7cihWLChPPXgoViwoVT14KFYsKG49eChWLChPPShVPUIoKG49QigoWT1CKFYpLFYpKSxWKSksQihWKSksbikpLFUpKSxPKSksWSksbF8oVSxPLFYsbikpfSwocihlLDM0LChsKDE4LChsKDk4LGZ1bmN0aW9uKFYpe2FSKFYsNCl9LChsKDE4NSxmdW5jdGlvbihWLFUsTyxZLG4sYixLKXtmb3Iobj0oVT14KFYsKEs9KE89b1IoKGI9QihWKSxWKSksIiIpLDEwMikpLFUubGVuZ3RoKSxZPTA7Ty0tOylZPSgoWXwwKSsob1IoVil8MCkpJW4sSys9eVtVW1ldXTtyKFYsYixLKX0sKHIoZSw1NiwoKHIoKCgocihlLDE2NCwobCgyMDcsKGwoMjM1LGZ1bmN0aW9uKFYsVSxPLFkpe3IoViwoVT0oTz0oWT1CKFYpLEIoVikpLEIoVikpLFUpLHgoVixZKXx8eChWLE8pKX0sKGwoMzIsKGwoNDIsKHIoZSw0NjgsKChsKDQxMCwobCg3MiwobCg0NTksZnVuY3Rpb24oVixVLE8pe3goViwoTz14KChPPUIoKFU9QihWKSxWKSksViksTyksVSkpIT0wJiZyKFYsMzQyLE8pfSwobCgyNzYsKGwoNDc4LGZ1bmN0aW9uKFYsVSxPLFksbil7KFk9eChWLChVPXgoViwoTz14KFYsKG49eCgoTz0obj1CKFYpLFU9QihWKSxCKFYpKSxZPUIoViksVikuTCxuKSxPKSksVSkpLFkpKSxuIT09MCkmJihZPWxfKFksMSxWLE8sbixVKSxuLmFkZEV2ZW50TGlzdGVuZXIoVSxZLEEpLHIoViwxMjIsW24sVSxZXSkpfSwocihlLDEyMiwobCg0NiwoZS5scD0ocihlLChsKDQ3OSxmdW5jdGlvbihWKXtobCg0LFYpfSwocihlLChyKGUsKGwoOSxmdW5jdGlvbihWLFUsTyxZKXtyKChVPXgoKE89KFk9QigoVT1CKFYpLFYpKSxCKFYpKSxZPXgoVixZKSxWKSxVKT09WSxWKSxPLCtVKX0sKGwoNDcyLGZ1bmN0aW9uKFYsVSxPLFkpe1k9KFU9QihWKSxJKShWKSxPPUIoVikscihWLE8seChWLFUpPj4+WSl9LChsKDE2NixmdW5jdGlvbihWKXtobCgzLFYpfSwobCg0MDEsKHIoZSwobCgocihlLChsKDQzLChsKDM0OSwoKHIoZSwocihlLDM0MiwwKSw1MTApLDApLGwoMTk5LGZ1bmN0aW9uKFYpe2FSKFYsMSl9LGUpLGwpKDQ5NixmdW5jdGlvbihWLFUsTyxZKXtmb3IoWSBpbiBkZWxldGUgKE89eChWLChVPUkoViksNDY4KSksTylbVV0sTylpZihZIT09InQiJiZPYmplY3QuaGFzT3duKE8sWSkpcmV0dXJuO2ZvcihVPTA7VTxWLkoubGVuZ3RoO1UrKylPPVYuSltVXSxPLmNkfHwoYy5jbGVhclRpbWVvdXQoTy5XZCksdihPLm95LFYpLHYoTy5lWSxWKSk7Vi5KLmxlbmd0aD0wfSxlKSxmdW5jdGlvbihWLFUsTyl7cigoTz0oVT1CKFYpLEIoVikpLFYpLE8sIiIreChWLFUpKX0pLGUpLGZ1bmN0aW9uKFYsVSxPLFksbil7Zm9yKG49KFU9QihWKSxPPW9SKFYpLFk9W10sMCk7bjxPO24rKylZLnB1c2goSShWKSk7cihWLFUsWSl9KSxlKSwyMyksMCksNTAzKSxmdW5jdGlvbihWLFUsTyl7SHgoVSx0cnVlLFYsZmFsc2UpfHwoVT1CKFYpLE89QihWKSxyKFYsTyxmdW5jdGlvbihZKXtyZXR1cm4gZXZhbChZKX0od1UoeChWLkwsVSkpKSkpfSxlKSw4MyksWzAsMCwwXSksZnVuY3Rpb24oVixVLE8sWSl7cihWLChPPXgoViwoWT0oVT0oWT0oTz1CKFYpLEIoVikpLEIpKFYpLHgpKFYsWSksTykpLFUpLE9bWV0pfSksZSksZSkpLGUuTHA9MCxlKSksZSkpLDM0Nikse30pLDI2NyksYyksZSkpLHIoZSwxNjgsWzE2MCwwLDBdKSwxNTgpLGUpLDApLGZ1bmN0aW9uKFYsVSxPLFksbixiKXtIeChVLHRydWUsVixmYWxzZSl8fChPPWZxKFYuTCksVT1PLnBiLG49Ty5yUixZPU8uaXAsTz1PLkQsYj1PLmxlbmd0aCxuPWI9PTA/bmV3IFlbbl06Yj09MT9uZXcgWVtuXShPWzBdKTpiPT0yP25ldyBZW25dKE9bMF0sT1sxXSk6Yj09Mz9uZXcgWVtuXShPWzBdLE9bMV0sT1syXSk6Yj09ND9uZXcgWVtuXShPWzBdLE9bMV0sT1syXSxPWzNdKToyKCkscihWLFUsbikpfSksZSksMCkpLGUpKSxmdW5jdGlvbihWLFUsTyxZLG4sYixLLFAsUSxGLFMsayl7ZnVuY3Rpb24gZihNLHcpe2Zvcig7bjxNOylGfD1JKFYpPDxuLG4rPTg7cmV0dXJuIEY+Pj0odz1GJihuLT1NLCgxPDxNKS0xKSxNKSx3fWZvcihVPShGPShPPUIoViksbj0wKSxTPShmKDMpfDApKzEsWT1mKDUpLFtdKSxLPVA9MDtLPFk7SysrKVE9ZigxKSxVLnB1c2goUSksUCs9UT8wOjE7Zm9yKGI9KFA9KChQfDApLTEpLnRvU3RyaW5nKDIpLmxlbmd0aCxLPTAsW10pO0s8WTtLKyspVVtLXXx8KGJbS109ZihQKSk7Zm9yKFA9MDtQPFk7UCsrKVVbUF0mJihiW1BdPUIoVikpO2ZvcihrPVtdO1MtLTspay5wdXNoKHgoVixCKFYpKSk7bChPLGZ1bmN0aW9uKE0sdyxoLFIsRyl7Zm9yKFI9KEc9W10sdz0wLFtdKTt3PFk7dysrKXtpZighVVtoPWJbd10sd10pe2Zvcig7aD49Ui5sZW5ndGg7KVIucHVzaChCKE0pKTtoPVJbaF19Ry5wdXNoKGgpfU0uWj0kUygoTS5UPSRTKGsuc2xpY2UoKSxNKSxHKSxNKX0sVil9KSxlKSxlKSksZnVuY3Rpb24oVixVLE8sWSl7aWYoVT1WLlAucG9wKCkpe2ZvcihPPUkoVik7Tz4wO08tLSlZPUIoViksVVtZXT1WLlhbWV07Vi5YPShVWzEwNl09KFVbNTZdPVYuWFs1Nl0sVi5YKVsxMDZdLFUpfWVsc2UgcihWLDM0MixWLkIpfSksZSksbCgxNzksZnVuY3Rpb24oVil7VlAoViw0KX0sZSksZnVuY3Rpb24oVixVKXsoVT14KFYsQihWKSksY3gpKFYuTCxVKX0pLGUpLGwpKDE4MSxmdW5jdGlvbihWLFUsTyxZKXshSHgoVSx0cnVlLFYsZmFsc2UpJiYoVT1mcShWKSxPPVUuaXAsWT1VLnJSLFYuTD09Vnx8WT09Vi5uYiYmTz09VikmJihyKFYsVS5wYixZLmFwcGx5KE8sVS5EKSksVi5nPVYuSCgpKX0sZSkse30pKSxmdW5jdGlvbihWLFUpe3IoViwoVT1CKFYpLFUpLFtdKX0pLGUpLGZ1bmN0aW9uKFYsVSxPLFkpe3IoKFU9eChWLChZPShPPUIoKFU9KFk9QihWKSxCKFYpKSxWKSkseChWLFkpKSxVKSksViksTyxZIGluIFV8MCl9KSxlKSxlKSksZnVuY3Rpb24oVixVLE8sWSxuLGIsSyl7aWYoIUh4KFUsdHJ1ZSxWLHRydWUpKXtpZihZPShiPShLPXgoKFU9eCgoWT0oSz0oYj0oVT1CKFYpLEIpKFYpLEIoVikpLEIpKFYpLFYpLFUpLFYpLEspLHgoVixiKSkseChWLFkpKSx2eChVKT09Im9iamVjdCIpe2ZvcihuIGluIE89W10sVSlPLnB1c2gobik7VT1PfWlmKFYuTD09Vilmb3IoSz1LPjA/SzoxLFY9MCxuPVUubGVuZ3RoO1Y8bjtWKz1LKWIoVS5zbGljZShWLChWfDApKyhLfDApKSxZKX19KSxlKSxwKDQpKSksZSkuUGQ9MCxyKShlLDEwNixbMjA0OF0pLGUpLDExNSxbXSkscikoZSwxOTEsW10pLFtdKSksZSkpLGUpKSxmdW5jdGlvbihWLFUsTyxZLG4peyhVPUIoKG49KE89QihWKSxCKShWKSxWKSksVikuTD09ViYmKG49eChWLG4pLFk9eChWLE8pLFU9eChWLFUpLFlbbl09VSxPPT04JiYoVi5pPXZvaWQgMCxuPT0yJiYoVi5vPUwoViwzMixmYWxzZSksVi5pPXZvaWQgMCkpKX0pLGUpLHAoNCkpKSxlKSksNDMwKSxwKDQpKSxbXSkpLFtdKSksODI1KSksbCkoMTYzLGZ1bmN0aW9uKFYsVSxPKXtyKFYsKFU9eChWLChPPShVPUIoViksQihWKSksVSkpLFU9dngoVSksTyksVSl9LGUpLGZ1bmN0aW9uKFYsVSxPLFkpe3IoKE89KFU9KFU9QihWKSxZPUIoVikseChWLFUpKSx4KFYsWSkpLFYpLFksTytVKX0pLGUpLGUpKSxmdW5jdGlvbihWLFUpe1Y9KFU9QihWKSx4KFYuTCxVKSksVlswXS5yZW1vdmVFdmVudExpc3RlbmVyKFZbMV0sVlsyXSxBKX0pLGUpLGF8fHYoW21qXSxlKSx2KShbYl8sWl0sZSksW3hTLENdKSxlKSxlKSx0cnVlKX0sej1mdW5jdGlvbihlLGEsZyx0LFQsQyxaLEUpe0U9dGhpczt0cnl7SmwodGhpcyxlLGcsVCxaLHQsQyxhKX1jYXRjaCh5KXtEZCh0aGlzLHkpLHQoZnVuY3Rpb24oZCl7ZChFLkspfSl9fSxmcT1mdW5jdGlvbihlLGEsZyx0LFQsQyl7Zm9yKEM9KGc9QigoVD0oKGE9QigodD1lW1NZXXx8e30sZSkpLHQucGI9QihlKSx0KS5EPVtdLGUuTD09ZT8oSShlKXwwKS0xOjEpLGUpKSwwKTtDPFQ7QysrKXQuRC5wdXNoKEIoZSkpO2Zvcih0LmlwPXgoZSxnKSx0LnJSPXgoZSxhKTtULS07KXQuRFtUXT14KGUsdC5EW1RdKTtyZXR1cm4gdH0sSHg9ZnVuY3Rpb24oZSxhLGcsdCxULEMsWixFKXtpZigoZy5MPSgoZy5PKz0oVD0oRT0oQz0oWj0oYXx8Zy5WKyssZy5BPjAmJmcuUiYmZy5kUiYmZy5sPD0xJiYhZy5UJiYhZy5VJiYoIWF8fGcudG0tZT4xKSYmZG9jdW1lbnQuaGlkZGVuPT0wKSxnKS5WPT00KXx8Wj9nLkgoKTpnLmcsRS1nLmcpLFQpPj4xND4wLGcpLm8mJihnLm9ePShnLk8rMT4+MikqKFQ8PDIpKSxnLk8rMT4+MiE9MCl8fGcuTCxDKXx8WilnLmc9RSxnLlY9MDtpZighWilyZXR1cm4gZmFsc2U7aWYoRS0oZy5BPmcuTiYmKGcuTj1nLkEpLGcpLmo8Zy5BLSh0PzI1NTphPzU6MikpcmV0dXJuIGZhbHNlO3JldHVybiBnLlU9KChyKGcsMzQyLCh0PShnLnRtPWUseChnLGE/NTEwOjM0MikpLGcuQikpLGcpLlkucHVzaChbZFUsdCxhP2UrMTplLGcudixnLkZdKSxzNSksdHJ1ZX0sUlI9ZnVuY3Rpb24oZSxhLGcsdCl7Zm9yKDthLlkubGVuZ3RoOyl7dD0oYS5VPW51bGwsYSkuWS5wb3AoKTt0cnl7Zz1NayhhLHQpfWNhdGNoKFQpe0RkKGEsVCl9aWYoZSYmYS5VKXtlPWEuVSxlKGZ1bmN0aW9uKCl7Sih0cnVlLGEsdHJ1ZSl9KTticmVha319cmV0dXJuIGd9LFc9ZnVuY3Rpb24oZSxhLGcsdCxULEMsWixFKXtpZighZy5DYiYmKEM9dm9pZCAwLGUmJmVbMF09PT1YJiYoYT1lWzFdLEM9ZVsyXSxlPXZvaWQgMCksdD14KGcsNTYpLHQubGVuZ3RoPT0wJiYoRT14KGcsNTEwKT4+Myx0LnB1c2goYSxFPj44JjI1NSxFJjI1NSksQyE9dm9pZCAwJiZ0LnB1c2goQyYyNTUpKSxhPSIiLGUmJihlLm1lc3NhZ2UmJihhKz1lLm1lc3NhZ2UpLGUuc3RhY2smJihhKz0iOiIrZS5zdGFjaykpLGU9eChnLDEwNiksZVswXT4zKSl7Zy5MPShlPShhPShhPWEuc2xpY2UoMCwoZVswXXwwKS0zKSxlWzBdLT0oYS5sZW5ndGh8MCkrMyxRUChhKSksZykuTCxnKTt0cnl7Zy5xUT8oWj0oWj14KGcsMTkxKSkmJlpbWi5sZW5ndGgtMV18fDk1LChUPXgoZywxMTUpKSYmVFtULmxlbmd0aC0xXT09Wnx8bSgxMTUsW1omMjU1XSxnKSk6bSgxOTEsWzk1XSxnKSxtKDQzMCxEKDIsYS5sZW5ndGgpLmNvbmNhdChhKSxnLDkpfWZpbmFsbHl7Zy5MPWV9fX0sWVM9ZnVuY3Rpb24oZSxhLGcsdCxUKXtmb3IoZT0oVD0odD0wLGVbMl0pfDAsZSlbM118MDt0PDE0O3QrKylnPWc+Pj44fGc8PDI0LGU9ZT4+Pjh8ZTw8MjQsZys9YXwwLGE9YTw8M3xhPj4+MjksZ149VCszMDI3LGUrPVR8MCxUPVQ8PDN8VD4+PjI5LGFePWcsZV49dCszMDI3LFRePWU7cmV0dXJuW2E+Pj4yNCYyNTUsYT4+PjE2JjI1NSxhPj4+OCYyNTUsYT4+PjAmMjU1LGc+Pj4yNCYyNTUsZz4+PjE2JjI1NSxnPj4+OCYyNTUsZz4+PjAmMjU1XX0sdj1mdW5jdGlvbihlLGEpe2EuWS5zcGxpY2UoMCwwLGUpfSxCPWZ1bmN0aW9uKGUsYSl7aWYoZS5UKXJldHVybiBrUyhlLlosZSk7cmV0dXJuIGE9TChlLDgsdHJ1ZSksYSYxMjgmJihhXj0xMjgsZT1MKGUsMix0cnVlKSxhPShhPDwyKSsoZXwwKSksYX0sTiwkUz1mdW5jdGlvbihlLGEsZyl7cmV0dXJuKChnPUhbYS5TXShhLng2KSxnKVthLlNdPWZ1bmN0aW9uKCl7cmV0dXJuIGV9LGcpLmNvbmNhdD1mdW5jdGlvbih0KXtlPXR9LGd9LHZ4PWZ1bmN0aW9uKGUsYSxnKXtpZihnPXR5cGVvZiBlLGc9PSJvYmplY3QiKWlmKGUpe2lmKGUgaW5zdGFuY2VvZiBBcnJheSlyZXR1cm4iYXJyYXkiO2lmKGUgaW5zdGFuY2VvZiBPYmplY3QpcmV0dXJuIGc7aWYoYT1PYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwoZSksYT09IltvYmplY3QgV2luZG93XSIpcmV0dXJuIm9iamVjdCI7aWYoYT09IltvYmplY3QgQXJyYXldInx8dHlwZW9mIGUubGVuZ3RoPT0ibnVtYmVyIiYmdHlwZW9mIGUuc3BsaWNlIT0idW5kZWZpbmVkIiYmdHlwZW9mIGUucHJvcGVydHlJc0VudW1lcmFibGUhPSJ1bmRlZmluZWQiJiYhZS5wcm9wZXJ0eUlzRW51bWVyYWJsZSgic3BsaWNlIikpcmV0dXJuImFycmF5IjtpZihhPT0iW29iamVjdCBGdW5jdGlvbl0ifHx0eXBlb2YgZS5jYWxsIT0idW5kZWZpbmVkIiYmdHlwZW9mIGUucHJvcGVydHlJc0VudW1lcmFibGUhPSJ1bmRlZmluZWQiJiYhZS5wcm9wZXJ0eUlzRW51bWVyYWJsZSgiY2FsbCIpKXJldHVybiJmdW5jdGlvbiJ9ZWxzZSByZXR1cm4ibnVsbCI7ZWxzZSBpZihnPT0iZnVuY3Rpb24iJiZ0eXBlb2YgZS5jYWxsPT0idW5kZWZpbmVkIilyZXR1cm4ib2JqZWN0IjtyZXR1cm4gZ30sRGQ9ZnVuY3Rpb24oZSxhKXtlLks9KChlLks/ZS5LKyJ+IjoiRToiKSthLm1lc3NhZ2UrIjoiK2Euc3RhY2spLnNsaWNlKDAsMjA0OCl9LGlfPWZ1bmN0aW9uKGUsYSl7cmV0dXJuIGFbZV08PDI0fGFbKGV8MCkrMV08PDE2fGFbKGV8MCkrMl08PDh8YVsoZXwwKSszXX0sR009ZnVuY3Rpb24oZSxhLGcpe3JldHVybiBlLkVVKGZ1bmN0aW9uKHQpe2c9dH0sZmFsc2UsYSksZ30sdGw9ZnVuY3Rpb24oZSxhKXtyZXR1cm5bZnVuY3Rpb24oKXtyZXR1cm4gZX0sKGEoZnVuY3Rpb24oZyl7ZyhlKX0pLGZ1bmN0aW9uKCl7fSldfSxsXz1mdW5jdGlvbihlLGEsZyx0LFQsQyl7ZnVuY3Rpb24gWigpe2lmKGcuTD09Zyl7aWYoZy5YKXt2YXIgRT1bSVIsdCxlLHZvaWQgMCxULEMsYXJndW1lbnRzXTtpZihhPT0yKXZhciB5PUooKHYoRSxnKSxmYWxzZSksZyxmYWxzZSk7ZWxzZSBpZihhPT0xKXt2YXIgZD0hZy5ZLmxlbmd0aCYmIWcuUjsodihFLGcpLGQpJiZKKGZhbHNlLGcsZmFsc2UpfWVsc2UgeT1NayhnLEUpO3JldHVybiB5fVQmJkMmJlQucmVtb3ZlRXZlbnRMaXN0ZW5lcihDLFosQSl9fXJldHVybiBafSxBbD1mdW5jdGlvbihlLGEsZyx0LFQsQyl7aWYoIWEuSyl7YS5sKys7dHJ5e2ZvcihnPTAsVD1hLkIsdD12b2lkIDA7LS1lOyl0cnl7aWYoQz12b2lkIDAsYS5UKXQ9a1MoYS5ULGEpO2Vsc2V7aWYoKGc9eChhLDM0MiksZyk+PVQpYnJlYWs7dD0ocihhLDUxMCxnKSxDPUIoYSkseCkoYSxDKX1IeCgodCYmdFtLcV0mMjA0OD90KGEsZSk6VyhbWCwyMSxDXSwwLGEpLGUpLGZhbHNlLGEsZmFsc2UpfWNhdGNoKFope3goYSw0ODMpP1coWiwyMixhKTpyKGEsNDgzLFopfWlmKCFlKXtpZihhLlpiKXtBbCg2NzYxNzA2NTAzMDQsKGEubC0tLGEpKTtyZXR1cm59VyhbWCwzM10sMCxhKX19Y2F0Y2goWil7dHJ5e1coWiwyMixhKX1jYXRjaChFKXtEZChhLEUpfX1hLmwtLX19LHA9ZnVuY3Rpb24oZSxhKXtmb3IoYT1bXTtlLS07KWEucHVzaChNYXRoLnJhbmRvbSgpKjI1NXwwKTtyZXR1cm4gYX0sSj1mdW5jdGlvbihlLGEsZyx0LFQsQyl7aWYoYS5ZLmxlbmd0aCl7KGEuUiYmIjpUUVI6VFFSOiIoKSxhLlI9dHJ1ZSxhKS5kUj1lO3RyeXt0PWEuSCgpLGEuaj10LGEuVj0wLGEuZz10LGEuTj0wLEM9UlIoZSxhKSxlPWc/MDoxMCxUPWEuSCgpLWEuaixhLk1RKz1ULGEuekYmJmEuekYoVC1hLkMsYS52LGEuRixhLk4pLGEuQz0wLGEuRj1mYWxzZSxhLnY9ZmFsc2UsVDxlfHxhLlJ5LS08PTB8fChUPU1hdGguZmxvb3IoVCksYS5IZC5wdXNoKFQ8PTI1ND9UOjI1NCkpfWZpbmFsbHl7YS5SPWZhbHNlfXJldHVybiBDfX0sY3g9ZnVuY3Rpb24oZSxhKXtlLlAubGVuZ3RoPjEwND9XKFtYLDM2XSwwLGUpOihlLlAucHVzaChlLlguc2xpY2UoKSksZS5YWzM0Ml09dm9pZCAwLHIoZSwzNDIsYSkpfSxzNT1jLnJlcXVlc3RJZGxlQ2FsbGJhY2s/ZnVuY3Rpb24oZSl7cmVxdWVzdElkbGVDYWxsYmFjayhmdW5jdGlvbigpe2UoKX0se3RpbWVvdXQ6NH0pfTpjLnNldEltbWVkaWF0ZT9mdW5jdGlvbihlKXtzZXRJbW1lZGlhdGUoZSl9OmZ1bmN0aW9uKGUpe3NldFRpbWVvdXQoZSwwKX0sST1mdW5jdGlvbihlKXtyZXR1cm4gZS5UP2tTKGUuWixlKTpMKGUsOCx0cnVlKX0sa1M9ZnVuY3Rpb24oZSxhKXtyZXR1cm4oZT1lLmNyZWF0ZSgpLnNoaWZ0KCksYS5ULmNyZWF0ZSgpLmxlbmd0aCl8fGEuWi5jcmVhdGUoKS5sZW5ndGh8fChhLlo9dm9pZCAwLGEuVD12b2lkIDApLGV9LExxPWZ1bmN0aW9uKGUsYSl7cmV0dXJuIEhbZV0oSC5wcm90b3R5cGUse3N0YWNrOmEsY29uc29sZTphLGNhbGw6YSxyZXBsYWNlOmEscGFyZW50OmEsZG9jdW1lbnQ6YSxzcGxpY2U6YSxwcm9wZXJ0eUlzRW51bWVyYWJsZTphLHBvcDphLGZsb29yOmEscHJvdG90eXBlOmEsbGVuZ3RoOmF9KX0sdV89ZnVuY3Rpb24oZSxhLGcsdCl7dHJ5e3Q9ZVsoKGF8MCkrMiklM10sZVthXT0oZVthXXwwKS0oZVsoKGF8MCkrMSklM118MCktKHR8MCleKGE9PTE/dDw8Zzp0Pj4+Zyl9Y2F0Y2goVCl7dGhyb3cgVDt9fSxTWT0oIkFSVElDTEUgU0VDVElPTiBOQVYgQVNJREUgSDEgSDIgSDMgSDQgSDUgSDYgSEVBREVSIEZPT1RFUiBBRERSRVNTIFAgSFIgUFJFIEJMT0NLUVVPVEUgT0wgVUwgTEggTEkgREwgRFQgREQgRklHVVJFIEZJR0NBUFRJT04gTUFJTiBESVYgRU0gU1RST05HIFNNQUxMIFMgQ0lURSBRIERGTiBBQkJSIFJVQlkgUkIgUlQgUlRDIFJQIERBVEEgVElNRSBDT0RFIFZBUiBTQU1QIEtCRCBTVUIgU1VQIEkgQiBVIE1BUksgQkRJIEJETyBTUEFOIEJSIFdCUiBOT0JSIElOUyBERUwgUElDVFVSRSBQQVJBTSBUUkFDSyBNQVAgVEFCTEUgQ0FQVElPTiBDT0xHUk9VUCBDT0wgVEJPRFkgVEhFQUQgVEZPT1QgVFIgVEQgVEggU0VMRUNUIERBVEFMSVNUIE9QVEdST1VQIE9QVElPTiBPVVRQVVQgUFJPR1JFU1MgTUVURVIgRklFTERTRVQgTEVHRU5EIERFVEFJTFMgU1VNTUFSWSBNRU5VIERJQUxPRyBTTE9UIENBTlZBUyBGT05UIENFTlRFUiBBQ1JPTllNIEJBU0VGT05UIEJJRyBESVIgSEdST1VQIFNUUklLRSBUVCIuc3BsaXQoIiAiKS5jb25jYXQoWyJCVVRUT04iLCJJTlBVVCJdKSxTdHJpbmcuZnJvbUNoYXJDb2RlKDEwNSwxMTAsMTE2LDEwMSwxMDMsNjcsMTA0LDEwMSw5OSwxMDcsNjYsMTIxLDExMiw5NywxMTUsMTE1KSksdT1bXSxucT1bXSxiXz0oei5wcm90b3R5cGUuWTY9KHoucHJvdG90eXBlLlhNPXZvaWQgMCwidG9TdHJpbmciKSxbXSkseFM9KHoucHJvdG90eXBlLlpiPWZhbHNlLHoucHJvdG90eXBlLk1aPXZvaWQgMCxbXSkseVA9W10sSVI9W10sZFU9W10sS3E9W10sWD17fSxtaj1bXSxIPSgoKCgoKCgoZ1UsZnVuY3Rpb24oKXt9KShwKSx1XyxmdW5jdGlvbigpe30pKFB4KSxmdW5jdGlvbigpe30pKGVZKSxVNSx2b2lkIDAsZnVuY3Rpb24oKXt9KSh2b2lkIDApLGZ1bmN0aW9uKCl7fSkodm9pZCAwKSxmdW5jdGlvbigpe30pKHZvaWQgMCkseikucHJvdG90eXBlLlM9ImNyZWF0ZSIsWCkuY29uc3RydWN0b3IsRTU9KCgoTj16LnByb3RvdHlwZSxOLk5RPTAsTikuST1mdW5jdGlvbigpe3JldHVybiBNYXRoLmZsb29yKHRoaXMuSCgpKX0sTi5JeT1mdW5jdGlvbihlLGEsZyx0LFQsQyl7Zm9yKEM9KGc9dD0wLFtdKTt0PGUubGVuZ3RoO3QrKylmb3IoVD1UPDxhfGVbdF0sZys9YTtnPjc7KWctPTgsQy5wdXNoKFQ+PmcmMjU1KTtyZXR1cm4gQ30sTikuSD0od2luZG93LnBlcmZvcm1hbmNlfHx7fSkubm93P2Z1bmN0aW9uKCl7cmV0dXJuIHRoaXMuRm8rd2luZG93LnBlcmZvcm1hbmNlLm5vdygpfTpmdW5jdGlvbigpe3JldHVybituZXcgRGF0ZX0sTi5FVT1mdW5jdGlvbihlLGEsZyx0KXtpZigoZz12eChnKT09PSJhcnJheSI/ZzpbZ10sdGhpcykuSyllKHRoaXMuSyk7ZWxzZSB0cnl7dD0hdGhpcy5ZLmxlbmd0aCYmIXRoaXMuUix2KFt5UCxbXSxnLGUsYV0sdGhpcyksYSYmIXR8fEooYSx0aGlzLHRydWUpfWNhdGNoKFQpe0RkKHRoaXMsVCksZSh0aGlzLkspfX0sTi5PVT1mdW5jdGlvbihlLGEsZyl7cmV0dXJuKChhPSgoYV49YTw8MTMsYV49YT4+MTcsYSleYTw8NSkmZyl8fChhPTEpLGUpXmF9LHZvaWQgMCksRlc9KE4uQW09ZnVuY3Rpb24oZSxhLGcsdCxUKXtmb3IodD1UPTA7dDxlLmxlbmd0aDt0KyspVCs9ZS5jaGFyQ29kZUF0KHQpLFQrPVQ8PDEwLFRePVQ+PjY7cmV0dXJuKFQ9KGU9KFQrPVQ8PDMsVF49VD4+MTEsVCsoVDw8MTUpPj4+MCksbmV3IE51bWJlcihlJigxPDxhKS0xKSksVClbMF09KGU+Pj5hKSVnLFR9LE4ualk9ZnVuY3Rpb24oKXtyZXR1cm4gTWF0aC5mbG9vcih0aGlzLk1RKyh0aGlzLkgoKS10aGlzLmopKX0sTj16LnByb3RvdHlwZSxOLlc9ZnVuY3Rpb24oZSxhKXtyZXR1cm4gYT0oRTU9KGU9e30sZnVuY3Rpb24oKXtyZXR1cm4gYT09ZT8tODQ6LTMxfSkse30pLGZ1bmN0aW9uKGcsdCxULEMsWixFLHksZCxWLFUsTyxZLG4sYixLLFAsUSxGLFMsayxmLE0sdyxoLFIpe0M9YSxhPWU7dHJ5e2lmKEY9Z1swXSxGPT1iXyl7dz1nWzFdO3RyeXtmb3IoWj0oTz1bXSxhdG9iKSgoVD0wLHcpKSxnPTA7VDxaLmxlbmd0aDtUKyspaD1aLmNoYXJDb2RlQXQoVCksaD4yNTUmJihPW2crK109aCYyNTUsaD4+PTgpLE9bZysrXT1oO3IodGhpcywodGhpcy5CPSh0aGlzLnU9Tyx0aGlzKS51Lmxlbmd0aDw8Myw4KSxbMCwwLDBdKX1jYXRjaChHKXtXKEcsMTcsdGhpcyk7cmV0dXJufUFsKDEwMDAxLHRoaXMpfWVsc2UgaWYoRj09eVApe1o9KGg9MCx7fSk7dHJ5e1o9eCh0aGlzLDQ2OCl8fHt9LGg9Wi50fDB9ZmluYWxseXtpZighZ1tQPShUPVtucSxnLHRoaXMuSSgpXSxbdSxnXSksNF0pe3RoaXMuWS5wdXNoKFApLHRoaXMuWS5wdXNoKFQpO3JldHVybn1mb3IoTyBpbiBnPWZhbHNlLFopaWYoTyE9PSJ0IiYmT2JqZWN0Lmhhc093bihaLE8pKXtnPXRydWU7YnJlYWt9aWYoIWcpeyh0aGlzLlkucHVzaChQKSx0aGlzLlkpLnB1c2goVCk7cmV0dXJufXJldHVybntveTpULGVZOlAsdGltZW91dDpoLGNkOmZhbHNlLFdkOjB9fX1lbHNlIGlmKEY9PW5xKVY9Z1sxXSxWWzFdLnB1c2goeCh0aGlzLDE2OCkubGVuZ3RoLHgodGhpcywxMTUpLmxlbmd0aCx4KHRoaXMsMzQpLmxlbmd0aCx4KHRoaXMsNDMwKS5sZW5ndGgseCh0aGlzLDEwNilbMF0seCh0aGlzLDE5MSkubGVuZ3RoLHgodGhpcywxNjQpLmxlbmd0aCx4KHRoaXMsMzk2KS5sZW5ndGgpLHIodGhpcywzNDYsVlsyXSksdGhpcy5YWzM3OF0mJnJVKDEwMDAxLHRoaXMseCh0aGlzLDM3OCkpO2Vsc2V7aWYoRj09dSl7dGhpcy5MPSh0PUQoMiwoRT1nWzFdWzFdLCh4KHRoaXMsMTY4KS5sZW5ndGh8MCkrMikpLGI9dGhpcy5MLHRoaXMpO3RyeXtTPXgodGhpcyw1NiksUy5sZW5ndGg+MCYmbSgxNjgsRCgyLFMubGVuZ3RoKS5jb25jYXQoUyksdGhpcywxMCksbSgxNjgsRCgxLHRoaXMuTysxPj4xKSx0aGlzLDEwOSksbSgxNjgsRCgxLHRoaXNbdV0ubGVuZ3RoKSx0aGlzKSxmPXRoaXMucVE/eCh0aGlzLDExNSk6eCh0aGlzLDE5MSksZi5sZW5ndGg+MCYmbSgxNjQsRCgyLGYubGVuZ3RoKS5jb25jYXQoZiksdGhpcywxMjIpLG49eCh0aGlzLDE2NCksbi5sZW5ndGg+NCYmbSgxNjgsRCgyLG4ubGVuZ3RoKS5jb25jYXQobiksdGhpcywxMjMpLFQ9MCxUKz14KHRoaXMsMjMpJjIwNDcsVC09KHgodGhpcywxNjgpLmxlbmd0aHwwKSs1LFk9eCh0aGlzLDQzMCksWS5sZW5ndGg+NCYmKFQtPShZLmxlbmd0aHwwKSszKSxUPjAmJm0oMTY4LEQoMixUKS5jb25jYXQocChUKSksdGhpcywxNSksWS5sZW5ndGg+NCYmKFkubGVuZ3RoPjFFNiYmKFk9WS5zbGljZSgwLDFFNiksbSgxNjgsW10sdGhpcywyNTUpLG0oMTY4LFtdLHRoaXMsMzApKSxtKDE2OCxEKDIsWS5sZW5ndGgpLmNvbmNhdChZKSx0aGlzLDE1NikpfWZpbmFsbHl7dGhpcy5MPWJ9aWYoZD0oKChRPXAoMikuY29uY2F0KHgodGhpcywxNjgpKSxRKVsxXT1RWzBdXjYsUSlbM109UVsxXV50WzBdLFFbNF09UVsxXV50WzFdLHRoaXMpLkdGKFEpKWQ9IiEiK2Q7ZWxzZSBmb3IoZD0iIixUPTA7VDxRLmxlbmd0aDtUKyspeT1RW1RdW3RoaXMuWTZdKDE2KSx5Lmxlbmd0aD09MSYmKHk9IjAiK3kpLGQrPXk7cmV0dXJuIHgodGhpcywoeCh0aGlzLCh4KHRoaXMsKCgoeCh0aGlzLCgoeCh0aGlzLChQPWQsMTY4KSkubGVuZ3RoPUUuc2hpZnQoKSx4KHRoaXMsMTE1KSkubGVuZ3RoPUUuc2hpZnQoKSwzNCkpLmxlbmd0aD1FLnNoaWZ0KCkseCkodGhpcyw0MzApLmxlbmd0aD1FLnNoaWZ0KCkseCh0aGlzLDEwNikpWzBdPUUuc2hpZnQoKSwxOTEpKS5sZW5ndGg9RS5zaGlmdCgpLDE2NCkpLmxlbmd0aD1FLnNoaWZ0KCksMzk2KSkubGVuZ3RoPUUuc2hpZnQoKSxQfWlmKEY9PWRVKXJVKGdbMl0sdGhpcyxnWzFdKTtlbHNle2lmKEY9PUlSKXJldHVybiByVSgxMDAwMSx0aGlzLGdbMV0pO2lmKEY9PUtxKXtpZihrPShNPXgodGhpcyw0OTIpLHR5cGVvZiBTeW1ib2whPSJ1bmRlZmluZWQiJiZTeW1ib2wuaXRlcmF0b3IpJiZNW1N5bWJvbC5pdGVyYXRvcl0pVT1rLmNhbGwoTSk7ZWxzZSBpZih0eXBlb2YgTS5sZW5ndGg9PSJudW1iZXIiKVU9e25leHQ6WmQoTSl9O2Vsc2UgdGhyb3cgRXJyb3IoU3RyaW5nKE0pKyIgaXMgbm90IGFuIGl0ZXJhYmxlIG9yIEFycmF5TGlrZSIpO2ZvcihUPVUsSz1ULm5leHQoKTshSy5kb25lO0s9VC5uZXh0KCkpe1I9Sy52YWx1ZTt0cnl7UigpfWNhdGNoKEcpe319TS5sZW5ndGg9MH19fX1maW5hbGx5e2E9Q319fSgpLE4ueTk9ZnVuY3Rpb24oKXtyZXR1cm4odGhpc1t0aGlzKyIiXT10aGlzLFByb21pc2UpLnJlc29sdmUoKX0sTi5INz0wLC8uLyk7Ti51cD0oTi5HRj0oTi5icD1mdW5jdGlvbigpe3RoaXNbdGhpcysiIl09dGhpc30sZnVuY3Rpb24oZSxhLGcsdCl7aWYodD13aW5kb3cuYnRvYSl7Zm9yKGE9KGc9MCwiIik7ZzxlLmxlbmd0aDtnKz04MTkyKWErPVN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCxlLnNsaWNlKGcsZys4MTkyKSk7ZT10KGEpLnJlcGxhY2UoL1xcKy9nLCItIikucmVwbGFjZSgvXFwvL2csIl8iKS5yZXBsYWNlKC89L2csIiIpfWVsc2UgZT12b2lkIDA7cmV0dXJuIGV9KSwwKTt2YXIgcWssWFc9Yl8ucG9wLmJpbmQoKHoucHJvdG90eXBlW3hTXT1bMCwwLDEsMSwwLDEsMV0seikucHJvdG90eXBlW25xXSksd1U9ZnVuY3Rpb24oZSxhKXtyZXR1cm4oYT1DcSgpKSYmZS5ldmFsKGEuY3JlYXRlU2NyaXB0KCIxIikpPT09MT9mdW5jdGlvbihnKXtyZXR1cm4gYS5jcmVhdGVTY3JpcHQoZyl9OmZ1bmN0aW9uKGcpe3JldHVybiIiK2d9fSgoKHFrPUxxKChGV1t6LnByb3RvdHlwZS5ZNl09WFcsei5wcm90b3R5cGUpLlMse2dldDpYV30pLHopLnByb3RvdHlwZS5nUj12b2lkIDAsYykpOyhxPWMuYm90Z3VhcmR8fChjLmJvdGd1YXJkPXt9KSxxLm0+NDApfHwocS5tPTQxLHEuYmc9TzUscS5hPVRNKSxxLnZKb189ZnVuY3Rpb24oZSxhLGcsdCxULEMsWixFLHkpe3JldHVyblsoeT1uZXcgeihFLFosVCxhLHQsZSxDKSxmdW5jdGlvbihkKXtyZXR1cm4gR00oeSxkKX0pLGZ1bmN0aW9uKGQpe3kuYnAoZCl9XX07fSkuY2FsbCh0aGlzKTsnXS5qb2luKCdcbicpKSk7fSkuY2FsbCh0aGlzKTs\\u003d\x22,\x22dkpvczFhUm9jZnRYRVU2T3l3b1RUM3lFQnVzWDcreEdkK3EwMEttV3FDcDhUbnRmSU9wV3Q0NlcvYzIzVXBOTEVTRy9TV0tpellBUUdxZWhkLzBKbGgxS2IxV0pBN0pNODA2YnNIdmcrbGVEY21LQ3N5ZEFtWUp1RUo3SWNHUzUrbDZwdU8ydXZLNFY0eVVMRWxHUklQRjJnSGJCVlpkM3FubzJNM3JMQjBVZzVBdUVFUWJPVUxrT1JNZEsxZzl0NzVpR1lWRE5rdlZwOFR4NFp4Zm9wSlNxTVA0bVhrN3B6MXcxMW5sU3Q5UjNnemlaWWhuVDhqMi9POFQyZ0pEYTdncnVUUlBSM2lvUUJTd0RwWTRFMGlrY0RielR2aW81OEE4NkVYYTZnTDJMKyt5aGpxSmlXQWNkbk5qY2wwVkdPVG5QelNrSVBaS2xPTytjWTdFaXNNaTBUd0ROL0pRWFlUa2NndFEwS2dSUXNwUGdydkNwREtERXB3cmtpZEVCV3ljdnUrS1lha3lJVXRJMmtXSDJIK3JpemJYTW9VcVNtSi9zaGZRQzh3eGVoQStHT3hMSFlqYVhBMkdTYmZOcFBCRHZvbWhNblpNc0RrSzhZSkp1SWRydlVQZ1U0aktLSCt2Z0dtUFR3c2IzUk13MEI2N01XWVFOdXMvLzV6NjE5SlMwR3M3a0dSZlJEaklzeTFOeGNMSDhQUTVET1U5VXNjV09wa0hkQ3dDTUF4WVByWW9yQnJTVFEwbUpxSEJqQ01iRmFVOEtxeWxjRHVpNXdVbGhOUUQra3FDVlhha01ibVF4NlBBM2FkUmlRSE9hMzhnRHhOc2FSdkNFRi9OK2NVVzJRUTNUWXRCU0paL3NDWk1XTCtLZUttMStxRU5LTEV2YW1ZVWJpUTBpVThmNEY2aEJITTc5NFllVEg5RDV5K0h1bWxsNnZETVFkYzdFQitGUS9ad0tUYjU0c2U0a3lSaHRMVVBkSytGS09YamRTN1lCVFNocDFtUjNFUVV0OXdmeHlHM3F4S1Ztbi9BYlc2OUFRSzNWYzdOR0VJRkV0UURqMFVWbllBeC9MTW1zZElERTdYQW9nbkZ5cGloeGNDQzQwSUlRSzd1ckJsUXI2eUkwQTdLMUJzMUFkd21kVmtnMWR4aXVJWXVzQWJsOTZ1cUozOXkvSXo0OTlIdUdGc3ExaXhlSDNsYlliOVZxaHdmV2lTTWFPaTJhMkJrUGFCanVVT0dtVWIvbTBLREQ0WmJDcmtFSlh4bjFnYmlaUGVhQ25oWWY1REhTbEFGMWlRZXgvcWYyNEliZktpTnJxUW9jVzRPRFI5dFVkQWJ4RFRqRC9aRjcwcHcybjhQalRvRFM5NkwzZ25XS0JUSk9rL21jRzNBT24rYm8wQnhUYWNKR21hZCtONWl2SVJ2Q1hUWExtMStsc1BYNlZQRTFGNWQ2dGdNK0hYRTM3ZGx5RmRKRnN5OWRTYlVxQ3haSHhuOXh1REg3S0dMY0Evc3NmVTdIbVU3blB5THhFN1d5SWNaRTVUZTNEZkF6Z0o5YTgraFZJN09WV3JtdkxMOUpMMy9JdjJFVVNSdXkvRmNEQnVsYitXR3p4RHpveDVYUWlyd3ZycjZFcDJvMzJzeVE4SUx5VEdkSExleENNQmM3RWkyN2ZEL1Vwc2FXT00yQ1FBSGJPbGZNMFBaS0h6NGJ4VXQwcldDZHQ2TXpORTczMEpiNndpRlFLMlgycVhtMThIcTNJbkx0eXhCU21PMHR4Z2xTZVpJNjhXenBpSEd3UTlneUVVNTlEZTNMTUxwdzM4aENhSVRGY1JsMXV1TW1zNTY0d200dUFuUEZOWHRLV1hPWWpDcWR6Y051ZERDSjVyVDMvTUV0SkNHRWZSNFZJN1RaSlhGMmVLVVBQYUpuU1ZhbWlDRXh6dXU3dVFQY2ZzeDRKSzRJN29MSHR2ZG9UUTN3czd3WWZjSHp2Yjl2czZUTEZPc21TRkswVFlzNjBzQWRLeFl3a1JsTVlUeFJrd3ZpQ0R0Ky9Ed0ZqV1BLWHArciswbHJqRkdEZVFwNjBFUUhaQ2lvZkFqeC9Va0NaR084Y1dxd1l2d1BXcnNULzNIaHNrZ0Z1b2pmSEp1N20xbEkrSDVOMlAwaFBDbTVyeDhkN0tHRWR2ejA2MmJwN1NMZ0xRR1ZnSWEvaFo4VVBVMy9RcFBORzhhbkt3L3hvcEVraHNGaTljeFhTTGdvYTZvQmo5aVF6K25UWGh3eXdqSVVjcmJ2ZjdGRnh5RUxEV3BNdU54Z0Z4emp0OWR6MjREWVo4RUZWWldEYTRsZnVIcmwvTGo2Rnc1SDY5UEZDSzhkSCswTmRMK1E0YjJIaU9GWFloTHdEUlRwQnY3WFdndDV1M0VFOW9MV2MzQ2RuM1dBVzZKam9nSExiOXZiejg5dnJPYTRINjRFMGZ4VXBWSndvVnl4YkhTRnFDanEwRDNONEJLM3FSU3RwNytmSnpMRVU1UGNPMGlmNmc2Zmkxa3dsdnZRL3dFNGw1TUtCM2s0VzJlRlhzdUpLcTZONyt1dHNkc0cwSGRkUjdBKzdTT2VsQkorUDk0S0g3ejg4MEh4eXNvME9Dbm5BSkMrL2Z3RUtCeVVNUkIwTDUyVTBocDNmMzRQNndHV3p1WmswU1B4NkpDRjRmeGkwSGFGNWhNZzZQa0h6NTlST1ovTU9WMXBaeWFpamFZMTVkZTJMc25ScHhVMDdGVDZoYzJmb284MHovTHJwMUVtS2g1SHVzVlNEdVo2QzhCbHU0cld5QncyZHFZVmNKUS9jWGw5TDBSSFpBeXFicFVjcmw2OHdLQTc0dzJqd1pwZXdEU2w3ZTg4bFRLeGFGYVhCRHpmTElDSmM2VC9vbHJ4SHNhNDRIUzZoNjN2ZnR2aHJLa3lYUW05d0FqVDIvcXI1VmJhOWpBb3Q3SUxjNkluZ016a1RsZk5NVm5aWVJuQUhkWUlOMHRjd1p5L0dpV082Qm1rNzJOOG9UNXVMM21ramtNSHRRUW14dHp2cHZ3MmtoLzMwMmhobEtjVllUYzRHa01jemNhb2Fwa0RBc2lCWWE2amlYZzRIeEc5TFFscWQzbFgrZ2VaZEhkWEVIN3l0UzRXQW4yTFZZUmNjaWJPd21uWmdJV1dOaEo2Q1NiUEVIdC8yTXJoK0pvOXc0NWQxdk8zcHJELzc1T1dQakczUXdqK0Mvc1djcUlnNVZYYTd3TlhnVE8rZzlxWGZWZk1RQUM5RFRFb3VPYWFhS1ROUUI5TE80MWNFdThPaGQycFRSR0lIZVBuNUxMV0ZpNGtUVGVRSjFPaDQwaklCeVU1U1dJL0J5bHZRRlc5K0g3dmVNTzA4OVhzSTVVdTRsbmh3eVEreklrOEd1ekNpU2pZbDhYV09HYzVUYXpJN3NWbzA4SEJ0Y0ZYN2tKZDV4c1hjdzFzbXV1SzBEMWFJVk1MUkMxcEp3R2RiYkIyNitzMXNWMHEwTFVYdVdhSVlaVEx6NmhNaDVJYTI1SnBMWEpOeEtMTVZyV2FhbzdnRjJmWVZrUnVIeU1QOGI1S2o1WXpSalNYOEllUmh3TWd1cGlTYXZEQXdQdW9wNlNydFZBYW9rNDdRUFhxVEx6K0xYLzVaWHpSMmY0bCtkYWsrQkc4ajR0MnpNM3laSCtHZ2FWZy9PRDRXR25uaW9PZWtJbjRUUEIwSDZ0NGxXc0pTZk1UVFUvTHNjSzc1RTBaTzFvMHVBYlZNalk2L3M2bHFzZUhweFprOEJCQmg2R0ZscHBDSmVybzdSdDZnWjVLcmx1VVpVM0hhQ0llWTdLRHpSMHhyMHUwcTRvRkV4UzlCY2orR2p0YzhUdFNsUmdOSk9GSVVFVGNHc0k2dHkzQXpwTXRUQmc0WkdDbzRPODVQRHRsU3hkc1p3bjZLN3dVWnd4NnFaUVUxWkRuVXRVTDRQbktwQXowRmx1RUJXUzRRYmd1SmU0RnNEZmJqRUpGSWJINXgvRXlpaDUwTCtQdk1LMW9va3NGbU9mQVR3OGtXdmJkdnFUYllzY1lqd2JOclN4UjNTdjhmTVFpdVlLblBab0lIb3JKUnpSNXZMeHhjR040WjNlRjd6cWYxV3I3VUk1WGJabncycjVGRXlvQmhnREh4QXF5V015aUdIbHIyejJCSE8wbVJtano4NHA2cHJxMXlwV3ZLVGw0Wlk5aENOZ0VVZk5Jd0dUVDJuWGlWNkd4TmtsWjN1c2dNdHBJOFVTcjdRQkRzVGw4blhncWE3Z0Q1elh6bTdSRExkWWsxb08zWnJxMyt4dlhqSnJ2WWQ3c01JQS85ODNoWUgrOFVLREpHdjlFekdpUlVubW1QRlRYVEsxMHA2Z2twNWpFdWw3YmxqNnBNMlhxQjgvcEVNQTV2bzB5Qk1QN3IyNmdmbHUwMGhKUmNKUlV4ZDNmYkNzK0hXRzZsZVR4VmdBUlhzQ3lPRGYxUHYvVitPSzlvdnp1dGxYKzlLa1FKN0Y4a1BhRFE3U3VWQWJLeDRBc1h4em1EWU5wc2NuV2t5dWRPMS9HamwrYkU1Uk1iejMwTGZ4UjU0a3RnZDZRRE1QK25RR2VHRTVWRWFBeFNmdERIaTlJZjU2MlN3aGEybGNBcHlyeklqTTlGR0tWRmJlZjFZcGFFY0FGQWp3cktJUFd5UXA5TDlad1c2ZGF6cCs2N2dHS3IvZzU0eThNVDNHTnVRcStTaDJpVWhYZFhRSXVEWVQvU2lncFRsaEpveGZtRllXbC9hazdhdkJSY3pGYkpYWW81RDRoc0w0cU5Zbm9VV2Vwd1FkSFkwNmdLMWVmQ3BaRU42MHo0ODhwNGIwK1hwbEpjSHVVK2lKek1TbmgvSjR0OHQzLzhxNnJFcFFtTXgzR1hWQ1dZUnE3TWMwZW9DMTFzNGxEcXB0dlcwM0pLNGsyYW1KSnBDOTBjL0Z3L2FuMEhjOFlVcmtQcWE1UG1pbWkrY01EUjlndi9MMUZvY2xuRU5DODQ5ajNuSFRvVFdDUityUUNXNzdKM3NwOENwWGVFOWQ2UDBiQi9XVnF1cFFPSmxsWU9US1EvR1dNRkovRytVZUNMVFJCclhNYWRFSWFOb0RDUDJCQ3pCWmRWQmEvZ0c5cUVpdW55TkY1VVhVZEg1Vk12UGZMRGVyY1FCeVU3dFhNN3dkdnJrRHY2NDAwZ3kxU0F5Vm1rdnNQa3lxRjFQbktnbytDMlFOK1FaTUtlaE5sM2JrQ210WHBYSTRFdHdiZGpRcEdwMVgwS2Fka0dXK1RwdEFRY2o1dXhjcjhEWDluRW4xWFZoR0hSTXQxYUNBY0diZVFsbE94blRvcTExajlTNjJCNVV1TUphelR4c3RPQzJoUXJnemxSQTgzZU5iaWlEaG5RcGxONlJmdTJFaWVTUWhQTjM5Wkx0QlNKQVErYjdXMm5sTGlPRWFQOE12NS84Q2RWQ3RZV0dhTDhMZForSDBVdlhJSnRBNkN4dFhmUjFxRUZ1NVJjeDZqeEpuQ2lEaVZlamp5SHVSZVd6Q2NmVjRObjhubXp3WDJmQzhlMHRaN2pTeXdFWGJPazRnVVpJUkxvTGN3RHZ4bGlJclZvcVk1RGpYUTdJZCtZcnp1MVZEQlBqS2ZPaWNDbHJ4bmlDTXl5N1Nnak0yc0JTdmxXMWdKYm5CSDBsQ1luU29zUm1xNG1Nd3N4NHNqTjhDSkRHNm9LYjkyTFFwZHhZN3RZS0x4TzhMSXdta250OFV5NUZxVjA4RmpKbmhudGVHTGxSYlNsY2ZwNHdiNW5tRlZPL1RyMlUxVkNiRG05VFZ0d2ZGMG9KcDNNbFNuZ1pyb3FPa3hNTlRNNk1vbnZ1UVIvS1ZqdjJSd1g2a3lIVEh5cU5SM25QZ0g2UnoyVVJFWW1GazQycVRLUFp4RDN5dEV6MmVTV2xBdFpESkM5WGUrM0w1enNIem1GZnZEeDNGRGxNTnU2TlJhTUlISTBDTXE5ZFp1ektIaWp4eW1QWUFXL2lFbHVMdzl1ZmFVaWQ3YzJTdnR6K2JiaW9FZ1BMc2VrVDFCUVAvdUZXTE1CTGZ2NjNsOFdLd01jWEtzUnJlT1FpcFExYXR1RGdyNzZEY2RldUtXN1NmNGhUWnVOWGZiZHZTODFUUUxRWG8zUm14M0tHU0h4OXU4SDkrQjJGa1VPWHVaaEV0cmptSnZMdC9VbVBCVk1QeENjY3BXaTgvTFdaL2lxK3FWV2dDcFRHbzlzNE55cDdSeGR4T1lsbnloelMrSHpDNGpodS9vUlI2OUg1VzUwRWNLTjYrdEZzU2ZhdVdORnBPS3VxdDdyWEVTMXhoa3djcE5JL1RlQXBXYUJQb3dyaHpsNGZpZE91Q0Y3TU0wS2ZWWFd1ZU5EeTdrQSs3Y2hlMk9wQ0prckcwMUEvQU80SlpNS00yelFKMks3VWhhcDZ0aGxLYnd3MHJsVHgyc0FOTFBoS0tvYktuSnJzY0xLcm1od1JTTWc1UDJyWXIwUE5IWGJ5UytGeCtCTi9MU0dEWldUdDZ2SHpsRXpVaEFGdDdnWndnSGVmT1ZEb3BPYURUTkZGYmtOVXM5RDBFQ05xb25McDk2U3dkSDJsOGFINzVrSzBlajJNeTd4b05sZmNHTzRURWgvL0tlelI3emNCYVdRYTRqWXo2ak5zcmpMVnh6Y2dzUHIvRGZLRTZsYmlzY1c5bXV0MHQ0cWRKblBjeHlzVE5LR0plMlJwajNaeHl4WmJnSkQ3aWZvbkQrQlJOSVMzdS9Qdy9pSFh0NDlHR0FET2dwZ1g2NlVqSWRnaUpJSmVrZkFhdWhIOFI3VkNZMldycWU4TU1PSjlhRU1FWWlkNUs2ZGVmRGgxWFEvWmJndXVISWRFQy8yamhPYys0RXhTNWY1OVdKMEQxQStjS0lvMHkzRzRJbjBjc3RjaVNVS1VPUkFIclhrRVdWOEZLb05DUFowU0JaM2t5cGhLbFFFd0NLdGJuY0hYenZ6SnNoRFlhNkpFOXpFZ1dpNEQ4YWtYTWVnWjNnd01RNzQyTmY0RWNHUXJ5TjE4STAreGIrY3hjdkJtQlBtWnlVSUg1MDczd2QzTWQ4djI0U2t2YUd6b0pEK1RmZnZHRXdaWHN5aTVieVI1WXhBUVlteFZUVkZRWldUUnZsbkZpNVkvRW52ck9XWURpVUZEVGk3YTBCT0xyQjhlYkZoV0d0QXFaRVlDS3NNdFVhcVlaSGsxRUtuMVN3dXRtcDBVOUc5LzBYUEN1c1JLcDFrbnFISGpMd2VHK2NkdjhkZGxsaEE5S1VBbHNocVRFNlFlckZ3VFU0SURIbkFCVU92b2NFNG9tVlh5R2p0cmZ2dk9qb1dSK3lTOWhIMVJRSm40bVhhejdFT3JYQnp6WU9uZ1VqcFFzQnRkRVhCY3BhdVU3L3RVYW9Rdi9saDhiRGxYaE1SWXpqMzkxSzY2Z2g2YXE5aFRxaHd6L2x2LzVtUU15L25RK003TTNxOXNyNXl4UEljTzhaMkxXZlYrS2xlTVh4Y1dja0taYmh6YWVsZjdZOUMrbmUrWlAwUHFUN2w1V2RJWTh5RFdQZjR1N2JVd0VPSEQ2MXdIQ0lZcEQzdE1uS3l0ajlLN0wvYjRId2tqU0dWZHExb0c4dXRRcjNIa1phM3R1VWgyeUJpVGd0R0g0QXNPeEQ5ZVdnRzlHUXQzSVVzWGhHRFBGaktrZGN2Ri9RazN3UWxCNTcwT2V2SHBySUFuYm1wRVFQbTIwQjVwK1M1MzNWSWNUUDc1eUozVGEvQm1VZGtRNUxuKytEK0tscXF3a2Ixb3hVUUp0NUpiMmhNSDZwc2Z3MlJ3OHBGMFIvcjlzMDBEdVBzY3A4bWg5QUk1NTVJbXRhVTYrbjhYVkh5Qnc4RUdnK203MnQ5azBKc1UwTUxUS0pYSnkyNS8yZW5kUHhGQzdzVG90ejhteS90OEV3NXdPTE16a3NwWVJlRExIOG9GZ0VqRUdmcTBOWllGemJIKzVqU1RORkZZamxYVGZxeGErN1FlQ09ab041elhNcnBBRXlET0lEVkFDcUY5UmNjY2RHbmVXUVVRVHRJMU5mS1Zyc0pXYWRnbnlBOGVtbE9Fd2VWVEdGRXN5Yzhld29IT1p5ekpia2FlZk0xZkZudUZIVDN2MTlrcDNQd1BSOUN1dGpsS0p4Vm5PSUR3Mi8zS2RZN2dZMkJ1UldqOWVERFVBc3lKWFJkR2VHNlFjNEVoWEU3d1RZNS82Y3FMbFdWMUo0VUhLUDV2cTdaNEJkZ0ZSWUlGanh1UUtCN0s1aUtuMWhPRE53amtwc0VhUUEyM1NDeDl6cmFaTnNaa3RLb1ltbndoL3orTld3blZEVWIvZ1hXTnRiL242Mk0zcjY4NHluSGpnbzJWUHkzeW1OTmU3WmJyZ3Zrejc3UjBtWU5wR2pnZHNhb3VGeTV4SFV4SVQrOVQ1RUZSZTFLeURkTGZpQVJNTGtxTVE2YVcwZWlCRlp0a0kxeE8ycVlWYVBsWFNUT0J1dW9JM3k2LzRSc2F5ZnFEOXUrNHFUWlU4UnBmK0ZyVlk5QWNINE9UMVBxZmFubnovS1Q5WnlZSGcvUXNRQytLOFFITDZGU3o2SUVodkRvYVhmWDh0K0NMaWx2aXFjVzdsZVdnZEtLQ1c3d05xUWV5SldSMGduMFZwZkNoYVRzdytKRkp3S05aZ0JHSjdKcEtYcy9aNFhLSjJFZEF2NnJWODA4T1AwY3ZjSTVNbVdOa05Tblg2MlZOSVU0NjBIMVhzTlZCaWxLbUJ5ajdlb282aG50ZzdiYzYzZjNwWWhqdHRiSHMzSkR0NFB4YS80Yy8wSFRiRkZIL1JkVjQrdEdScTB4YnluS1FjNFBWVWxIcTZkWXFuLy9lQVBWUlNVYXRLd0ZFaVI5TEh6MENMVm1NUG05TFBoTitPd0hSU25OU0tqQnVjZ1A0M1ZhRWl0YjBrUmtSYmNIM3FRUktwRkM0eVo1SlVJcHlCRG12eG1hSVYzaXQzVHNETVJoTHdxTlQ0VFllM2UrNzI3VjNLSHhUWWtSUnZBV3VGNkNiSWNNeHp1RDk4SnE1eFdBL1ZXVFZGMlBoSGFTN25LU3FMY28xRHV4VFZpZW1qZitndlVaa3Ixc2NTUXNMYzJiVUk3a3l0Tm9VVGp4YVlQRkpvaE1jblVTTnhWNlQ5WEduTkRxbEg3ZmJlcCtoOG5lTVNiREFvWjRKOWgvaFUxUWZwRzA2ZS95RU5qVnVna1BsUmhHczdYQWNLUFd3cGRwMCtUZU9TRE14cVJ2bzNNQ2pNaGZkWFBlbkhHZll1bXRBZWZqNW5ES1Zrdlgwd1ZsVGUwU2Z5NzRVUG1XZld4TkpVeVRoa1grUHgrdkJVaTVUQlIvRXN0eUloNFlOV0t2dmxGM2QxOUJVT1hLVW4zekthK1JSTS9nRS9PSkdLZDg0NE45ZllLR2Rhd2ZaQit4aDloaDdjdXlUNkFRZkloRXJZb2JOMTNsZUxRVFdmWWdjOXkyUmtRMGdwVU9ycFkyU0E1eUt6c25qdUptWTVIUWpxZWx0aC9XL084eE5sQjZFVFU3WVlXZzl4d3A1aU5ScWNlcFpaYVpjYXc1TTFGa1BKZ1ovWGhCblNqa1J6dTEyMUVBT2RUKzZCbm5WT0hJbjV0VmpoWjdQV3hDbUwzaU1nTVdUd2NzSTFjQkdWWnJnQ2hkZE5MZ2RKNE9MZkZhY29VMXg5VG90bndaWTlLU2QwREFSb2x6YVVXditpYVl5YWpZNGZDSGx4YmxKN1VLSGxzTy9sWnlmSThGVTZDbStFRTE0SWZkZ1FXUXZCZFc5SnFFMzM5a3NKbDRWNkJYV0dHMlREd3VMaC9GcWhaUEpOMDVNMVh2TmhpVUs1cHlja2NrcUpEcXY3Y1pVdW1HTCtNVGNrcVk3bGtuamFqOVRMd0NpVjBWSjdZclJvSzZzYU5Ia0tsSW1DQXpFK0EyTG9iVmtEdnZzUzUxNnZNR2ZoZkZ2SVV5R1F6cHZqb0E3Mm5mT2lPL0J2MFlUNHdpNzRFbXZYRDRFZ2tlZ09DZDJHeHJwNWw1NEFqZ0d1VzBnb2R4aEhsdHBVZVBOVWlQalc1NXVGZE1VMklEbGZXcjZMbWVCM09semtRZ1g0Wm02RFlzTG93UWdtOWtBbitrQUtPTDF6cEdKT1JrRVNDRHBhVnBwL2FIc0ZmUUpBRy9CNW9VWW5waGRUUm1FWlVwcTd6MnBuckxEMG9SZEYvaXRiOXNTVFhjZTJWNTZNb2ZNc0FWbWpTN2dyTFFiTld3aC9sMEZqclFCUzk0L3lNcTdIRStvZEQ4dmVldXc0OXl1NlV1NjlxeVVGSzJPRENYcTdlYjREdk5HaytRUnVDcitCcDhYQm10bmsxRmRHT3VpWEhLdVZKWExzZ1U5RUFJNUx5Ri9lOTQzSm82SndCUXdjM1VqQmgwRjcyTEZEbWdjQmZGYjhXWGQyU0FBcXhUS0FxdjZnL005QkNOUFBkNDhHT29DbUh5dU8waVNPUXYrVXFVRXpNOGxEY3R2N2ZyUGhtMFJycFZPU0ozQjV1bU02VitGeVFnaTlLZEdXendKNWRwOWtvK1VkVXNOVWVXNWtFdE8xMlhyQmZ1TkdtWTZlVmFVc1VRVWF4d0FKdkthV0l5aEtkb0pOR2Q5L04vS002WkpZUDAwUFBZc0pZKzNBUHl5bFRXcnhrTWNqQ09rRngyL3ZHbHBTRmF1aEtJRmhSZmdNWGZ1UmhLODViQ2hKODFUSk9HVHFLaWl2SUNZT3FnQ2Z2Nzg5Vk9oeWF5YWhSam9nNWpBMTZlVkR4Ulh5YWFLN3daNE5aRnBTTXUzeUF0NS9VZk1nQWl1c3ptM2xEdXkrdXc5dTdoU2MrSjhITFkyL3FkY3k4bkNJVnVScmZPb3lmSUlwanF2OTVkaFM0dFZWdDcvRlE4Q2NDTWhIUngzOW12bUJaTlV5d1FSVjROaXhIYXFQSm1BbUFFcGcwMi9BM0VSeldRQ1BtUHlIeUhkTEo5Nkl1OWRKaVpieC9TeTJUTnZSOFp0SHVwUExBMUt1YXdpWWlYY2t0MHgxNTk4SzZrZmNJNVAxVlVBUHNvOGtBVkUxdm5VeXNKYldIc1I5NkpaMHlHSUx0YzIwM1dVVGdjUDBjcTZrZEh3V3ROUW1yVTRLb3NjaGNFaS9rNFpqM1VnYlZ0dEpOVm9JSmJhSUFuK1hqMktvcUMvb1FEMTdGeTM0ZWF4Y25QUTI3WWFXRkVYRGF2SWlHVkF2NU9yeEJGNGE1QmxOWWowaDcyNzdHcWZhNE96VGdGb3BrZEdEVC9pNWdpckhvQjhEK28zZXZyeWYxck5naUJidTV3MnlvQis3RnBJQUVHdUNJQ09LTy9USVZEazZpU1BOMnpwTnRsNG1ObG03SG44RlZISXdWZTExWlc5NzNOQjNESSt5V0VkSXFIZjI3VGwyL0ErOHN3K1pYVmxwckIrT1N2MXJRTVJDNmR6MHd1d2phbHdFSWdaWjBrYW1KMEd6QXNyeEEzcFo0SElQQ2VXT1hlUWE1KytaYnFza2UzZXJsNVUzNGlCdURnaCs1SENsOEVxa3J6Z202Z2J1QlJ0MEYrY3lCOU5iV3ZERjcyRlhwZHNXc2k1SkRwTkJvZk9qeC9IRFZZVkEzT1RWcTlHdEM0SFVvbWtXeU53VXN6dUdlSi80Tmw5UEkxd28vYVV3YXd6cFo2d3FIbGFXZ1I3RUUxU0Q1TEVRcW85QWIvcTB5UlpBTFZIcXdxYjlWL0gvRTJPQm5kYVlOVFc2dXlRTSs1dTNsYWJQOWl1RFRYRFBFY1pJSXNBNU1FalVORlZFbUNiQlQxOTVlVEZsdnlQZ1ZJcGNqK1ZqcU1OVjFQRGNjaGd2eHRJL3h1b05pbVIrV2xHTksvN1kwWXF5NzBTV0hhUlh2aGV6ajZzVC85SVdrY0VxelFYWnQ3RW0vbWpWZ21pT0YwZ0gyZllkaC9mV0EvSGNLaE1uVDAxc21rMVRPWWNPZy9WTTJyV0t6ejdpeXZ0SEhOSi9vcTUwZ1dDVnhBQnh3dkZEMlIraXRjdmRUYUVFc0pTMWJRVEZJYnRaVERpZkR0Yis3d2lDbkVRTnNOWTVYdUVtVXNzQjQwall6REl5UWlOdUhrT0loQ3o5VHVUZkxIYnREQkVCaG1vbzhtTzNWT1F6N3dvbTVWcVZlVjdJc1NuL2gwMzByUlFZZkZ6SmJPNWxuekFZVlhnN001VmlEbU1HQS9ReE1CY29EZ0w1ei9rai9BL3pZUDkzandJNUJ6MERyUXg0OHRzPQ\\u003d\\u003d\x22,\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\\u003d\x22],null,[\x22conf\x22,null,\x226LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19\x22,0,null,null,null,1,[21,125,63,73,95,87,41,43,42,83,102,105,109,121],[7668936,537],0,null,null,null,null,0,null,0,null,700,1,null,0,\x22CuUBEg8I8ajhFRgAOgZUOU5CNWISDwjY0oEyGAA6BkFxNzd2ZhIOCLjllDIYAToFUUJPRDASDwjmjuIVGAA6BlFCb29IYxIPCNLblTcYADoGZmZhV0FlEg8IldiUMhgAOgZQcTYwbmQSDwjF84g3GAA6BmFYb2lhYxIPCI3KhjIYAToGT3dONHRmEg8I8M3jFRgBOgZmSVZJaGISDwjiyqA3GAE6BmdMTkNIYxIPCN6/tzcYADoGZWF6dTZkEg4Iiv2INxgAOgVNZklJNBoZCAMSFR0U8JfjNw7/vqUGGcSdCRmc4owCGQ\\u003d\\u003d\x22,0,0,null,null,1,null,0,0],\x22https://admin.aff.esportesdasorte.com:443\x22,null,[3,1,1],null,null,null,1,3600,[\x22https://www.google.com/intl/en/policies/privacy/\x22,\x22https://www.google.com/intl/en/policies/terms/\x22],\x22Wnoohn4aYoo1DiQ1Qz5D2QBx63zl3t7Qvl9D31OMtN4\\u003d\x22,1,0,null,1,1764390679914,0,0,[8,198,233],null,[184],\x22RC-czGjgk-XR9vC7w\x22,null,null,null,null,null,\x220dAFcWeA5SX4qQAX-_urV-AAc1Q0Rn6VdEb3xzkJbqPkJ_k7Fegg5P-FEmU62dVr_2Nx0RZiNWvLFaI-Q96YoIrIIuBB-XZoj11g\x22,1764473480160]");
    </script></body></html>

