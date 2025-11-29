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

def start_browser(proxy: str, headless: bool) -> webdriver.Chrome:
    opts = Options()
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--lang=pt-BR')
    opts.add_argument(f'--proxy-server=socks5://{proxy}')
    if headless:
        opts.add_argument('--headless=new')
    try:
        return webdriver.Chrome(options=opts)
    except WebDriverException:
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service
            service = Service(ChromeDriverManager().install())
            return webdriver.Chrome(service=service, options=opts)
        except Exception as e:
            print(f'[-] Falha ao iniciar Chrome: {e}')
            raise

# ---------------------------------------------------------------------------
# Captura rtoken
# ---------------------------------------------------------------------------

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
    print("[*] Se for invisible, tente clicar no botão de LOGIN/SUBMIT para triggá-lo.")
    
    rtoken = None
    for i in range(timeout):
        try:
            val = driver.execute_script("return (document.getElementById('g-recaptcha-response')||{}).value")
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
        driver = start_browser(args.proxy_socks5, headless=args.headless)
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






reload?k=6LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19
api-auth
clr?k=6LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19
api-auth
collect
collect
collect
collect
collect
collect
collect
11 requests
26.1 kB transferred
Request URL
https://www.google.com/recaptcha/api2/reload?k=6LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19
Request Method
POST
Status Code
200 OK
Remote Address
127.0.0.1:9050
Referrer Policy
strict-origin-when-cross-origin
alt-svc
h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
cache-control
private
content-encoding
gzip
content-type
application/json; charset=utf-8
cross-origin-opener-policy-report-only
same-origin; report-to="coop_38fac9d5b82543fc4729580d18ff2d3d"
cross-origin-resource-policy
same-site
date
Sat, 29 Nov 2025 02:54:11 GMT
expires
Sat, 29 Nov 2025 02:54:11 GMT
report-to
{"group":"coop_38fac9d5b82543fc4729580d18ff2d3d","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/38fac9d5b82543fc4729580d18ff2d3d"}]}
server
ESF
set-cookie
_GRECAPTCHA=09ADiQh0fL8C4UgAkscJwwaU6wbVUsUOk8nu7l0BqKd84XmVnVV7orz9QyARzr_Uv3X6GAMhGVOh748EqRsJFdg9Y; Expires=Thu, 28-May-2026 02:54:11 GMT; Path=/recaptcha; Secure; HttpOnly; Priority=HIGH; SameSite=none
vary
Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site
x-content-type-options
nosniff
x-frame-options
SAMEORIGIN
x-xss-protection
0
:authority
www.google.com
:method
POST
:path
/recaptcha/api2/reload?k=6LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19
:scheme
https
accept
*/*
accept-encoding
gzip, deflate, br, zstd
accept-language
en-US,en;q=0.9
content-length
12108
content-type
application/x-protobuffer
origin
https://www.google.com
priority
u=1, i
referer
https://www.google.com/recaptcha/api2/anchor?ar=1&k=6LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19&co=aHR0cHM6Ly9hZG1pbi5hZmYuZXNwb3J0ZXNkYXNvcnRlLmNvbTo0NDM.&hl=en&v=TkacYOdEJbdB_JjX802TMer9&size=invisible&anchor-ms=20000&execute-ms=15000&cb=ki0lzy2kfenm
sec-ch-ua
"Not_A Brand";v="99", "Chromium";v="142"
sec-ch-ua-mobile
?0
sec-ch-ua-platform
"Linux"
sec-fetch-dest
empty
sec-fetch-mode
cors
sec-fetch-site
same-origin
sec-fetch-storage-access
none
user-agent
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
x-client-data
CIHoygE=
Decoded:
message ClientVariations {
  // Active Google-visible variation IDs on this client. These are reported for analysis, but do not directly affect any server-side behavior.
  repeated int32 variation_id = [3322881];
}







