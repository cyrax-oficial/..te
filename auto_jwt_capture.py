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







28-11-2025 17:46:16.162 I [Dictionary]  Start load EN language. main.js:3:1054
28-11-2025 17:46:16.608 I [Dictionary]  EN language loaded main.js:3:1054
28-11-2025 17:46:17.937 I [AuthProvider]  Check auto login. Has token: false main.js:3:1054
28-11-2025 17:46:17.937 I [AuthProvider]  Go to Login main.js:3:1054
28-11-2025 17:46:17.937 D [AccountEngine]  On clear BO account main.js:3:906
28-11-2025 17:46:17.940 I [AuthProvider]  Already Logged Out main.js:3:1054

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
    return uniq#!/usr/bin/env python3
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

