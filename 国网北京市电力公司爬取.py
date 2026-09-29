import subprocess
import re
import requests
import time
import json
import binascii
import os
from gmssl import sm2, sm3
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== 常量 ====================
STR_A = "5a1d642e9b784be5"
API_BASE = "https://zhaopin.sgcc.com.cn/sgcchr/"
TARGET_URL = "https://zhaopin.sgcc.com.cn/sgcchr/static/unitPart.html?id=50b970de66634fabac9c3730642d7f8d&obj_id=10500000"
BULLETIN_URL = "https://zhaopin.sgcc.com.cn/sgcchr/html/bulletin/50b970de66634fabac9c3730642d7f8d"
OUTPUT_FILE = "国网北京市电力公司_2026招聘公告.json"


# ==================== 工具函数 ====================

def bytes_to_hex(b):
    return binascii.hexlify(b).decode()


def hex_to_bytes(h):
    return binascii.unhexlify(h)


def sm3_hash(text: str) -> str:
    return sm3.sm3_hash(list(text.encode('utf-8')))


def sm4_encrypt_cbc(key_hex: str, iv_hex: str, plaintext: str) -> str:
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(hex_to_bytes(key_hex), SM4_ENCRYPT)
    cipher = crypt_sm4.crypt_cbc(hex_to_bytes(iv_hex), plaintext.encode('utf-8'))
    return bytes_to_hex(cipher)


def sm4_decrypt_cbc(key_hex: str, iv_hex: str, ciphertext_hex: str) -> str:
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(hex_to_bytes(key_hex), SM4_DECRYPT)
    plain = crypt_sm4.crypt_cbc(hex_to_bytes(iv_hex), hex_to_bytes(ciphertext_hex))
    plain = plain.rstrip(b'\x00')
    try:
        return plain.decode('utf-8')
    except Exception:
        if len(plain) > 0:
            pad_len = plain[-1]
            if 1 <= pad_len <= 16:
                return plain[:-pad_len].decode('utf-8')
        return plain.decode('utf-8', errors='ignore')


def generate_random_key() -> str:
    return binascii.hexlify(os.urandom(16)).decode()


def sm2_encrypt(pub_key_hex: str, data: str) -> str:
    sm2_crypt = sm2.CryptSM2(public_key=pub_key_hex[2:], private_key=None)
    encrypted = sm2_crypt.encrypt(data.encode('utf-8'))
    return "04" + bytes_to_hex(encrypted)


def encrypt_str(text: str, random_key: str) -> str:
    timestamp = str(int(time.time() * 1000))
    salt = "{" + text + "}" + "{" + timestamp + "}" + "{param}"
    deg = sm3_hash(salt)
    ciphertext = sm4_encrypt_cbc(random_key, random_key, salt + STR_A + deg)
    return ciphertext


def get_pub_k(data_pk: str) -> str:
    if STR_A in data_pk:
        parts = data_pk.split(STR_A)
        deg = sm3_hash(parts[0])
        if deg == parts[1]:
            return parts[0][:-13]
    return "0"


# ==================== 自动调用 rs-reverse 生成 Cookie ====================

def generate_cookie_via_rs_reverse():
    cmd = [
        "npx", "--registry=https://registry.npmjs.org",
        "-p", "rs-reverse@latest", "rs-reverse", "makecookie",
        "-u", TARGET_URL
    ]
    print("正在调用 rs-reverse 生成 Cookie，请稍候...")
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        shell=True, encoding='utf-8', errors='ignore'
    )
    output = result.stdout + result.stderr
    print("rs-reverse 输出（末尾）:", output[-300:])

    match = re.search(r'cookie值[:：]\s*([^\n\r]+)', output)
    if not match:
        print("❌ 未找到 Cookie，请检查 rs-reverse 是否成功运行")
        return None

    cookie_str = match.group(1).strip()
    print("✅ 提取到的 Cookie 字符串:", cookie_str[:80] + "...")

    cookies = {}
    for item in cookie_str.split(';'):
        item = item.strip()
        if '=' in item:
            k, v = item.split('=', 1)
            cookies[k] = v
    return cookies


# ==================== 主流程 ====================

def main():
    # ---- 1. 自动生成 Cookie ----
    cookies = generate_cookie_via_rs_reverse()
    if not cookies:
        print("Cookie 生成失败，退出")
        return

    # ---- 2. 创建 session 并注入 Cookie ----
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
    })
    for k, v in cookies.items():
        session.cookies.set(k, v, domain='zhaopin.sgcc.com.cn')
    print("已注入 Cookie:", list(cookies.keys()))

    # ---- 3. 请求 encodeNew 接口，获取 SM2 公钥 ----
    url1 = API_BASE + "index/encodeNew/00000000/00000000"
    r1 = session.get(url1, verify=False)
    print("r1 status:", r1.status_code)

    if r1.status_code != 200:
        print("❌ 请求被拦截，Cookie 可能已失效。请重新运行脚本。")
        return

    data1 = r1.json()
    pK = data1['retdata']['pK']
    sm2_pub = get_pub_k(pK)
    encry_flag = sm2_pub[0]
    sm2_pub = sm2_pub[1:]
    print(f"encry_flag={encry_flag}, sm2_pub={sm2_pub[:20]}...")

    # ---- 4. 根据 encry_flag 决定是否加密 ----
    if encry_flag != "1":
        print("不加密，直接请求数据接口...")
        r_data = session.get(BULLETIN_URL, verify=False)
        print("数据接口状态:", r_data.status_code)

        try:
            data_json = r_data.json()
        except Exception as e:
            print(f"JSON 解析失败: {e}")
            print(f"原始响应: {r_data.text[:1000]}")
            return

        if data_json.get('retcode') != '200':
            print(f"❌ 数据接口返回错误: {data_json}")
            return

        # ---- 5. 保存为 JSON 文件 ----
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(data_json, f, ensure_ascii=False, indent=2)

        page_data = data_json['retdata']['page_data']
        print(f"\n✅ 已保存到文件: {OUTPUT_FILE}")
        print(f"   标题: {page_data.get('bullet_title', '')}")
        print(f"   发布日期: {page_data.get('pub_time', '')}")
        print(f"   正文长度: {len(page_data.get('content', ''))} 字符")
        return

    # ---- 6. 需要加密：第二次请求，获取 sK ----
    print("需要加密，走 SM2/SM3/SM4 流程...")
    url2 = API_BASE + "index/encodeNew/" + "11111111" + "/" + "11111111"
    r2 = session.get(url2, verify=False)
    data2 = r2.json()
    pK2 = data2['retdata']['pK']
    sm2_pub2 = get_pub_k(pK2)[1:]

    random_key = generate_random_key()
    sm4_encrypted_key = sm2_encrypt(sm2_pub2, random_key)
    encrypted_prik = encrypt_str("1111", random_key)

    final_url = (BULLETIN_URL + "?prik=" + encrypted_prik +
                 STR_A + sm4_encrypted_key + STR_A + sm2_pub2)

    r3 = session.get(final_url, verify=False)
    print(f"请求状态: {r3.status_code}")

    try:
        resp_json = r3.json()
        if 'encryptStr' in resp_json:
            encrypted_data = resp_json['encryptStr']
            decrypted = sm4_decrypt_cbc(random_key, random_key, encrypted_data)
            data_json = json.loads(decrypted)
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(data_json, f, ensure_ascii=False, indent=2)
            print(f"\n✅ 已保存到文件: {OUTPUT_FILE}")
        else:
            print("响应未加密:", resp_json)
    except Exception as e:
        print(f"解析失败: {e}")
        print(f"原始响应: {r3.text[:2000]}")


if __name__ == "__main__":
    main()
