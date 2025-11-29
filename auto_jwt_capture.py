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











Disable Cache
12 requests
39.70 kB / 60.71 kB transferred
Finish: 1.30 min

	
__Secure-1PSIDCC	
domain	".google.com"
expires	"2026-11-29T04:20:42.000Z"
httpOnly	true
path	"/"
secure	true
value	"AKEyXzUwFL_dR6k0Oedx7jI81IsU7nDBp3sfRaaD8PSfqoAak5rUoG3nuXh7hPAtvtXQY-NvLNE"
__Secure-3PSIDCC	
domain	".google.com"
expires	"2026-11-29T04:20:42.000Z"
httpOnly	true
path	"/"
samesite	"None"
secure	true
value	"AKEyXzWTGK9Ne4lUpHdkSj6fCeVjRLae4T90lvilVDCMbjQnBFB-w_3IqMjq3jvG1B1C5-hnFA"
SIDCC	
domain	".google.com"
expires	"2026-11-29T04:20:42.000Z"
path	"/"
value	"AKEyXzXOxeQWLucOmiqaP2WmR79sNSWa7fKhVsoRa6kk818dbkNCDBBjli3Qil3ZiWuhsVqnlg"

    	
    __Secure-1PAPISID	"074IP9yal-lHdfFY/ADHFz6bOKCJCT72Pp"
    __Secure-1PSID	"g.a0004AjU6aB3jYgheOjarUx7LrSrKyJON-9JDMCjuIS8KRMJucpiP9-tsLDYBVqHwsS3JELxXwACgYKAZkSARcSFQHGX2Mi4QbML2JPWKRdwhRS2ufnahoVAUF8yKrLnBIxpfXNVSTy7cNLw7Ig0076"
    __Secure-1PSIDCC	"AKEyXzVdmJN1Li6neG8yhzA3CSKn3YWkb6EeEGRT7jDlwo-WLXf-WmcGREBF0Rgoyws38U49XfM"
    __Secure-1PSIDTS	"sidts-CjEBwQ9iIwURPM427K9JXEtqAP-mT0Qtxx6A179WbIRDStdDS4OIVx9DFaPAcIGNr6qGEAA"
    __Secure-3PAPISID	"074IP9yal-lHdfFY/ADHFz6bOKCJCT72Pp"
    __Secure-3PSID	"g.a0004AjU6aB3jYgheOjarUx7LrSrKyJON-9JDMCjuIS8KRMJucpifK90GqKF2VjviAtU83j6QAACgYKAWUSARcSFQHGX2MiJ6jAyDRXsY_WynvijDoqihoVAUF8yKqxKc0rbZy-lWcuJNW67ero0076"
    __Secure-3PSIDCC	"AKEyXzUQmMpiXR7fvrkZ78BKk8LPHkUibFg7-0SIFe_eb6_76qiXQWBqsgXzpiTG_7bvhTGLsA"
    __Secure-3PSIDTS	"sidts-CjEBwQ9iIwURPM427K9JXEtqAP-mT0Qtxx6A179WbIRDStdDS4OIVx9DFaPAcIGNr6qGEAA"
    _GRECAPTCHA	"09ADiQh0e4slv3djlk4zEGJmM6HjKnJrlX1kpHsYtGMDIFGUlDrEVByNhQzFwLvbRa0VMiqk7eMI5tBVP1utDHkEc"
    APISID	"MzdIU4amqmTZvKjn/ACc1JKJH0N311_1p9"
    GOOGLE_ABUSE_EXEMPTION	"ID=5d6f194c93fe841a:TM=1764380583:C=r:IP=185.220.101.18-:S=k32r0S7X0Y5JzCY-vvnW0xI"
    HSID	"AyljRmD2UOE8ZQPs7"
    NID	"526=VU4PFUsN98eizNZFp4zMiciPPwfbAcF_1bji9RMBZYnxBdq-ieF6LJIsbrrcOPmzSHwYxCTuBcvW57oN7Yv2kRYAzTu9TGcyeRml7Nh6wqWeBl6aPwjo6RBNw1kvtlez8hDcb7AxsnDhDPdpkGBJTJAZE_Y4eAf0CVrVMzFIzwvfAH15JG9td0WELlkk6lU_jJmvOFFHTYRji9M3oYX3h2vyr1ycfSJSQosOk4PwDLtr4svqVpJKnnq7tZICE96y4AVMOHQoPCNYVi2RgrxA4ci9x9fUo30QECtKsjcdrpBxxiu5tN0VyPOxKBoGpG-Ce2dvprarA4EbSGvEL2RGOCC1dHix-v0eVFat7_ZVgtAetYG_hyHWFLXmZiyhEqnxNK9JoXyZezM7Q4XJ71C30TiMQ7Iz63nOoXVazWIzmmZtDS1KhPe3rfMiOXyyVHwU7GC9_d-BPLqFeRlpPAjnRp2wFC6fUbsg5nLr_Y0Sv6QP8DdkW6gEG9iIQ5oPPViN8dqACDDuM3sfsoT6I0cbrVx9eawWz7pl4i69VNGSWAw2OVhtntKq8u_EQE83-QrghCXOTGczSRjaXxG2pS4XlD1j0p4YbEY2eHelMHXEqwAGqcvJryhN4jXLloPJOLt2zG3BQ0-nKVQfa0steTdFmij4Wos_lY9AvdbYDPgSnbZMquu2Nk_vcPvuiS0kjAmF5gVgmEhpNxPz7qenZpXJsBjFYUr0ElmsGvIBGshxcP-kPloP_rvKHVuHdJUVPcY4corUem4FMnKyEnW5SW4"
    SAPISID	"074IP9yal-lHdfFY/ADHFz6bOKCJCT72Pp"
    SID	"g.a0004AjU6aB3jYgheOjarUx7LrSrKyJON-9JDMCjuIS8KRMJucpiZt8LStA-U8OCrGMpWhdG7wACgYKAXUSARcSFQHGX2MiQp11o20FLvWl1b686w8BtBoVAUF8yKpdJHli6LzqvmYnrsGgFS_50076"
    SIDCC	"AKEyXzW4qhjpEiY66bEhleS7jAdEoHK2RZOKkWHe-P3Ka2kKEvvH0csf8tK9lgk865gA8lkyxQ"
    SSID	"Ac7Mr6LBxPUnMmQCz"


Disable Cache
13 requests
39.70 kB / 61.98 kB transferred
Finish: 1.73 min
	
POST
	
scheme
	https
host
	www.google.com
filename
	/recaptcha/api2/reload
k
	6LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19
Address
	0.0.0.0:443
Status
200
VersionHTTP/2
Transferred23.78 kB (39.65 kB size)
Referrer Policystrict-origin-when-cross-origin
DNS ResolutionSystem

	
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
	Sat, 29 Nov 2025 04:20:42 GMT
expires
	Sat, 29 Nov 2025 04:20:42 GMT
report-to
	{"group":"coop_38fac9d5b82543fc4729580d18ff2d3d","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/38fac9d5b82543fc4729580d18ff2d3d"}]}
server
	ESF
set-cookie
	SIDCC=AKEyXzXOxeQWLucOmiqaP2WmR79sNSWa7fKhVsoRa6kk818dbkNCDBBjli3Qil3ZiWuhsVqnlg; expires=Sun, 29-Nov-2026 04:20:42 GMT; path=/; domain=.google.com; priority=high
set-cookie
	__Secure-1PSIDCC=AKEyXzUwFL_dR6k0Oedx7jI81IsU7nDBp3sfRaaD8PSfqoAak5rUoG3nuXh7hPAtvtXQY-NvLNE; expires=Sun, 29-Nov-2026 04:20:42 GMT; path=/; domain=.google.com; Secure; HttpOnly; priority=high
set-cookie
	__Secure-3PSIDCC=AKEyXzWTGK9Ne4lUpHdkSj6fCeVjRLae4T90lvilVDCMbjQnBFB-w_3IqMjq3jvG1B1C5-hnFA; expires=Sun, 29-Nov-2026 04:20:42 GMT; path=/; domain=.google.com; Secure; HttpOnly; priority=high; SameSite=none
vary
	Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site
x-content-type-options
	nosniff
X-Firefox-Spdy
	h2
x-frame-options
	SAMEORIGIN
x-xss-protection
	0
	
Accept
	*/*
Accept-Encoding
	gzip, deflate, br, zstd
Accept-Language
	en-US,en;q=0.5
Connection
	keep-alive
Content-Length
	12248
Content-Type
	application/x-protobuffer
Cookie
	_GRECAPTCHA=09ADiQh0e4slv3djlk4zEGJmM6HjKnJrlX1kpHsYtGMDIFGUlDrEVByNhQzFwLvbRa0VMiqk7eMI5tBVP1utDHkEc; NID=526=VU4PFUsN98eizNZFp4zMiciPPwfbAcF_1bji9RMBZYnxBdq-ieF6LJIsbrrcOPmzSHwYxCTuBcvW57oN7Yv2kRYAzTu9TGcyeRml7Nh6wqWeBl6aPwjo6RBNw1kvtlez8hDcb7AxsnDhDPdpkGBJTJAZE_Y4eAf0CVrVMzFIzwvfAH15JG9td0WELlkk6lU_jJmvOFFHTYRji9M3oYX3h2vyr1ycfSJSQosOk4PwDLtr4svqVpJKnnq7tZICE96y4AVMOHQoPCNYVi2RgrxA4ci9x9fUo30QECtKsjcdrpBxxiu5tN0VyPOxKBoGpG-Ce2dvprarA4EbSGvEL2RGOCC1dHix-v0eVFat7_ZVgtAetYG_hyHWFLXmZiyhEqnxNK9JoXyZezM7Q4XJ7…Secure-3PAPISID=074IP9yal-lHdfFY/ADHFz6bOKCJCT72Pp; SIDCC=AKEyXzW4qhjpEiY66bEhleS7jAdEoHK2RZOKkWHe-P3Ka2kKEvvH0csf8tK9lgk865gA8lkyxQ; __Secure-1PSIDCC=AKEyXzVdmJN1Li6neG8yhzA3CSKn3YWkb6EeEGRT7jDlwo-WLXf-WmcGREBF0Rgoyws38U49XfM; __Secure-3PSIDCC=AKEyXzUQmMpiXR7fvrkZ78BKk8LPHkUibFg7-0SIFe_eb6_76qiXQWBqsgXzpiTG_7bvhTGLsA; __Secure-1PSIDTS=sidts-CjEBwQ9iIwURPM427K9JXEtqAP-mT0Qtxx6A179WbIRDStdDS4OIVx9DFaPAcIGNr6qGEAA; __Secure-3PSIDTS=sidts-CjEBwQ9iIwURPM427K9JXEtqAP-mT0Qtxx6A179WbIRDStdDS4OIVx9DFaPAcIGNr6qGEAA
Host
	www.google.com
Origin
	https://www.google.com
Referer
	https://www.google.com/recaptcha/api2/anchor?ar=1&k=6LdYBt8UAAAAAFZXub0e0LuYfuKwm38FSg4eJP19&co=aHR0cHM6Ly9hZG1pbi5hZmYuZXNwb3J0ZXNkYXNvcnRlLmNvbTo0NDM.&hl=en&v=TkacYOdEJbdB_JjX802TMer9&size=invisible&anchor-ms=20000&execute-ms=15000&cb=gqvws2tsn9qd
Sec-Fetch-Dest
	empty
Sec-Fetch-Mode
	cors
Sec-Fetch-Site
	same-origin
TE
	trailers
User-Agent
	Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0

Disable Cache
14 requests
39.70 kB / 63.39 kB transferred
Finish: 2.04 min
	
POST
	
scheme
	https
host
	b.clarity.ms
filename
	/collect
Address
	0.0.0.0:443
Status
204
No Content
VersionHTTP/1.1
Transferred2.09 kB (0 B size)
Referrer Policystrict-origin-when-cross-origin
DNS ResolutionSystem
Blocking
Enhanced Tracking Protection
This URL matches a known tracker and it would be blocked with Content Blocking enabled.

	
Access-Control-Allow-Credentials
	true
Access-Control-Allow-Origin
	https://admin.aff.esportesdasorte.com
Connection
	keep-alive
Date
	Sat, 29 Nov 2025 04:20:34 GMT
Request-Context
	appId=cid-v1:2f7711a9-b21e-4abe-a9d6-5b0ce5d18b64
Server
	nginx
Vary
	Origin
	
Accept
	application/x-clarity-gzip
Accept-Encoding
	gzip, deflate, br, zstd
Accept-Language
	en-US,en;q=0.5
Connection
	keep-alive
Content-Length
	1293
Cookie
	MUID=217794E6799F66F239BD825578276715
Host
	b.clarity.ms
Origin
	https://admin.aff.esportesdasorte.com
Referer
	https://admin.aff.esportesdasorte.com/
Sec-Fetch-Dest
	empty
Sec-Fetch-Mode
	cors
Sec-Fetch-Site
	cross-site
User-Agent
	Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0

Disable Cache
15 requests
39.70 kB / 64.73 kB transferred
Finish: 2.28 min

    	
    MUID	"217794E6799F66F239BD825578276715"


Disable Cache
16 requests
39.70 kB / 66.26 kB transferred
Finish: 2.54 min

    	
    AWSALBTG	
    expires	"2025-12-06T04:20:43.000Z"
    path	"/"
    value	"ltyuBsaslXNlwm4dNzGzagpEKTqqwYSwVs+5GiRWFFmuuJIWWnw6AVKfP2Cn6CHmt+AcXAvQrwqcD0AUVGfOZOCCYK8rdeYcfB1BtKeqDrtDtgvV6xANuGYNC0jwWpRS2lT4h8hL/OJroNpWlmLTHP2JjXdGy/Wpq3A8ia2p0Qpqj/myfJ0="
    AWSALBTGCORS	
    expires	"2025-12-06T04:20:43.000Z"
    path	"/"
    samesite	"None"
    secure	true
    value	"ltyuBsaslXNlwm4dNzGzagpEKTqqwYSwVs+5GiRWFFmuuJIWWnw6AVKfP2Cn6CHmt+AcXAvQrwqcD0AUVGfOZOCCYK8rdeYcfB1BtKeqDrtDtgvV6xANuGYNC0jwWpRS2lT4h8hL/OJroNpWlmLTHP2JjXdGy/Wpq3A8ia2p0Qpqj/myfJ0="


Disable Cache
16 requests
39.70 kB / 66.26 kB transferred
Finish: 2.54 min
	
password	"ReconPass2025!"
rtoken	"0cAFcWeA5bU5OjVGPgAdtcaIlbR3pIU8i5C9VvZ5wNn_119iqZ1hAZyxy86174gtt44YXoCRQgRFk98SEcx_wjeQTcsXR9RabRsN7TwKr17n1-hi6MvGOmt6eeDbvsKBIKT0mZtDEMxwHCu8S-Fvrh-h1JSmuZbOBuzA1QkeIALztAUHY8mlw9knDU3aaX_TOOGASWNQV2fLnnEfgecHCQnS_e-w2aRHcr73ygfW8sqikr4auHa6ld35hzJI7vU2-nS0K460_KQDJf9HGlxe6DcNHDaGpWEHDxPIPEHq-hCwkbNyOrZCHR-3cfqOqCZu6M587YtmzY4C3GNQ2zFSlJZPYBSVovhuiHQzKatAUAUaCQbxNxPR8x34T8mHZODhnV8DVafuTaTNTVrfcK0BzzjNLbHGMUAKsqrBRGnrn5mi301Xqvld62abdQYunrhGixh-tuJAyjbO-KwE3a6_B45u8cV-Bw4lx3UBTjiMHv4BhbM8HuK-shUWvN_0GuY…-KDq9Hhjrd61ZnXytioPGghSU4KIM80_HWkL0PUQ3t4cdBG57-hlKvlkPXSBBvhEesSQiToHOmDNmMyrIVqtGqbqKx8hmGd8llTLrqIAyTEAyLQ6doBVelHo4ts8HNd5ZMxqViZs8DSKKj3bkJg1wBv232O8ukSfhJU55j74c2PRBIq3FmzLbV0Ze6jg-hYTPrnBa1hrBPgDPIDph6afFthAHlMFrrKAh9uKQtNk91M1WxNcLF_oYdfQ_g7GK732peA9joPRK9_qJkkmA99kfJR4TJIYNWC4X68mmvs93nMd5gTCz6CZTA0HJDZyvZNrXTNi2DJH7xbaPGSCMpnX1Nye2DN-9jZUOmibPNEuTweGk9SxeyGK3UFJXjcjA3wvdNmBL-h8WQuKu6VYhArVp9u-9fPb-HgI1pAZ08QVDZsDs9jLvqf-WmfRu2hO-bKMx4oIGXp30fCnkG_FirmEKPFhnCh61qLmG43h4QP5ju0wzgp_AlO_8wIS1zkThg"
username	"recon_A1@test.com"

Disable Cache
17 requests
39.70 kB / 67.95 kB transferred
Finish: 2.91 min
	
errCode	2
message	"Wrong username or password"
