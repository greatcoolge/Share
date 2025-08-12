import aiohttp
import asyncio
import gzip
import os
import re
import requests
import shutil
import subprocess
mport sys
import tim
import zipfile
from bs4 import BeautifulSoup
from datetime import datetime
from dateutil.tz import tzutc
from pathlib import Path
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


# === 配置参数 ===
MI_HOME = os.environ.get('MI_HOME', '/usr/local/bin')

# === 路径配置 ===
TEMP_DIR = Path("temp")
CACHE_DIR = Path("temp/cache")
SITE_DIR = Path("rules/site")
IP_DIR = Path("rules/ip")

# === 自定义异常 ===
class WorkflowError(Exception):
    """工作流处理异常基类"""
    def __init__(self, message, detail=None):
        super().__init__(f"[ERROR] {message}")
        self.detail = detail
    def __str__(self):
        return f"{self.args[0]} (Detail: {self.detail})" if self.detail else self.args[0]

# === 环境准备 ===
def setup_environment():
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    SITE_DIR.mkdir(parents=True, exist_ok=True)
    IP_DIR.mkdir(parents=True, exist_ok=True)

# === 文件下载 ===
def download_file(url, target_path):
    try:
        # 确保目标路径父目录存在
        target_path.parent.mkdir(parents=True, exist_ok=True)

        r = requests.get(url, timeout=10)
        r.raise_for_status()

        if target_path.suffix == '.zip':
            target_path.write_bytes(r.content)
        else:
            target_path.write_text(r.text, encoding='utf-8')
    except Exception as e:
        raise WorkflowError(f"下载失败： {target_path.name} - {str(e)}")



                
def download_resources():
    """统一资源下载入口"""
    resources = {
        "temp": [
            ("https://github.com/MetaCubeX/meta-rules-dat/archive/refs/heads/meta.zip", "meta.zip"),
            ("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-httpdns-cn.list", "httpdns_1.list"),
            ("https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/discretion/dns.txt", "httpdns_2.list"),
            ("https://raw.githubusercontent.com/QingRex/LoonKissSurge/refs/heads/main/Surge/HTTPDNS%E6%8B%A6%E6%88%AA%E5%99%A8.sgmodule", "httpdns_3.list"),
            ("https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/discretion/pcdn.txt", "pmcdn_1.list"),
            ("https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/multi.txt", "dns-blocklists.list"),
        ],
        "site": [],
    }

    # 批量下载资源
    try:
        # 下载临时文件
        for url, filename in resources["temp"]:
            download_file(url, TEMP_DIR / filename)

    except Exception as e:
        raise WorkflowError(f"资源下载失败: {str(e)}")

    try:
        # 处理 meta.zip 文件
        meta_zip_path = TEMP_DIR / "meta.zip"

        if not meta_zip_path.exists():
            raise FileNotFoundError(f"meta.zip 不存在: {meta_zip_path}")
        if meta_zip_path.stat().st_size == 0:
            raise ValueError("meta.zip 文件为空")

        print("正在解压 meta.zip...")
        try:
            with zipfile.ZipFile(meta_zip_path, 'r') as zip_ref:
                zip_ref.extractall(str(TEMP_DIR))  # 直接解压到TEMP_DIR
        except zipfile.BadZipFile:
            raise RuntimeError(
                f"meta.zip文件损坏或不是有效的ZIP文件: {meta_zip_path}"
            )
    except Exception as e:
        raise WorkflowError(f"meta.zip 解压失败: {str(e)}")




async def generate_base():
    try:
        # 读取基础规则文件
        geolocation_notcn = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/geolocation-!cn.list").read_text().splitlines())
        gfw = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/gfw.list").read_text().splitlines())
        google_cn = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/google-cn.list").read_text().splitlines())
        google_cn2 = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/google@cn.list").read_text().splitlines())
        microsoft_cn = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/microsoft@cn.list").read_text().splitlines())
        apple_cn = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/apple-cn.list").read_text().splitlines())
        apple_cn2 = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/apple@cn.list").read_text().splitlines())
        cn = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/cn.list").read_text().splitlines())
        geolocation_cn = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/geolocation-cn.list").read_text().splitlines())
        tld_cn = set((TEMP_DIR / "meta-rules-dat-meta/geo/geosite/tld-cn.list").read_text().splitlines())

        # 生成组合规则
        combined_not_cn = sorted((geolocation_notcn | gfw) - (cn | geolocation_cn | tld_cn))
        (SITE_DIR / "!cn.list").write_text("\n".join(combined_not_cn))

        combined_cn = sorted((cn | geolocation_cn | tld_cn) - (geolocation_notcn | gfw | (google_cn | google_cn2) | microsoft_cn | (apple_cn | apple_cn2)))
        (SITE_DIR / "cn.list").write_text("\n".join(combined_cn))

        combined_cn_lite = sorted((geolocation_notcn | gfw) & (cn | geolocation_cn | tld_cn))
        (SITE_DIR / "cn-lite.list").write_text("\n".join(combined_cn_lite))

        # 获取中国ASN列表
        try:
            cache_file = CACHE_DIR / "cn_asns.txt"
            session = requests.Session()
            retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
            session.mount('https://', HTTPAdapter(max_retries=retries))

            response = session.get(
                "https://????.com",  # 这里地址要确认，填实际ASN来源URL
                timeout=30,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6788.76 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5'
                }
            )
            response.raise_for_status()

            if not response.text.strip():
                raise ValueError("服务器返回空内容，可能页面未加载完成")

            # 解析HTML提取ASN链接
            soup = BeautifulSoup(response.text, 'html.parser')
            asn_links = soup.find_all('a', href=re.compile(r'(/AS\d+|whois\.ipip\.net/AS\d+)'))

            cn_asns = set()
            for a_tag in asn_links:
                href = a_tag.get('href', '')
                text = a_tag.text.strip()

                asn_match = re.search(r'AS(\d+)', href)
                if not asn_match:
                    asn_match = re.search(r'AS(\d+)', text)

                if asn_match:
                    asn_num = f"AS{asn_match.group(1)}"
                    cn_asns.add(asn_num)

            if not cn_asns:
                raise ValueError("未提取到有效ASN编号")

            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text("\n".join(sorted(cn_asns)), encoding='utf-8')

        except Exception as e:
            print(f"在线获取失败: {str(e)}")
            if cache_file.exists():
                print("使用缓存数据...")
                cn_asns = set(cache_file.read_text(encoding='utf-8').splitlines())
            else:
                default_asn_file = IP_DIR / "asn/cn.list"
                if default_asn_file.exists():
                    print(f"使用默认ASN文件: {default_asn_file}")
                    cn_asns = set(default_asn_file.read_text(encoding='utf-8').splitlines())
                    cache_file.write_text("\n".join(sorted(cn_asns)), encoding='utf-8')
                else:
                    raise RuntimeError("ASN获取失败且无默认文件可用")

        print(f"获取到 {len(cn_asns)} 个中国ASN")

        # 合并ASN规则
        all_rules = set()
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))

        for asn in cn_asns:
            try:
                url = f"https://stat.ripe.net/data/ris-prefixes/data.json?list_prefixes=true&types=o&resource={asn}"
                response = session.get(
                    url,
                    timeout=30,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
                    }
                )
                response.raise_for_status()

                data = response.json()

                # 注意ripe.net数据结构，有时可能不同，请根据实际调整
                v4_prefixes = [p['prefix'] for p in data.get('data', {}).get('prefixes', []) if 'v4' in p['prefix']]
                v6_prefixes = [p['prefix'] for p in data.get('data', {}).get('prefixes', []) if 'v6' in p['prefix']]

                all_rules.update(v4_prefixes)
                all_rules.update(v6_prefixes)

            except Exception as e:
                print(f"获取 {asn} 的前缀失败: {str(e)}")
                continue

        (IP_DIR / "cn.list").write_text("\n".join(sorted(all_rules)), encoding='utf-8')
        print(f"生成 {len(all_rules)} 条 CN ASN ip 规则")

        # 更新ASN缓存
        cache_file.write_text("\n".join(sorted(cn_asns)), encoding='utf-8')

    except Exception as e:
        raise RuntimeError(f"基础规则生成失败: {str(e)}")



def process_httpdns_rules():
    try:
        # 读取 httpdns_1.list
        httpdns1_path = TEMP_DIR / "httpdns_1.list"
        httpdns1_data = httpdns1_path.read_text().splitlines()

        # 读取 httpdns_2.list
        httpdns2_path = TEMP_DIR / "httpdns_2.list"
        httpdns2_data = httpdns2_path.read_text().splitlines()

        # 读取 httpdns_3.list
        httpdns3_path = TEMP_DIR / "httpdns_3.list"
        httpdns3_data = httpdns3_path.read_text().splitlines()

        # 处理 httpdns_3.list 获取站点和IP规则
        site_rules = set()
        ip_rules = set()

        for line in httpdns3_data:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # 处理 DOMAIN,<domain>,REJECT 行
            if line.startswith('DOMAIN,') and ',REJECT' in line:
                parts = line.split(',')
                if len(parts) >= 3:
                    domain = parts[1]
                    if not domain.startswith('+'):
                        site_rules.add(f"+.{domain}")
                    else:
                        site_rules.add(domain)

            # 处理 IP-CIDR,<ip>,REJECT 行
            elif line.startswith('IP-CIDR,') and ',REJECT' in line:
                parts = line.split(',')
                if len(parts) >= 3:
                    ip = parts[1]
                    ip_rules.add(ip)

        # 合并 httpdns_1.list 和 httpdns_2.list 的域名规则
        for line in httpdns1_data + httpdns2_data:
            line = line.strip()
            if line and not line.startswith('#'):
                if not line.startswith('+'):
                    site_rules.add(f"+.{line}")
                else:
                    site_rules.add(line)

        # 写入站点规则文件
        (SITE_DIR / "httpdns.list").write_text("\n".join(sorted(site_rules)))
        print(f"生成 {len(site_rules)} httpdns domains")

        # 写入IP规则文件
        (IP_DIR / "httpdns.list").write_text("\n".join(sorted(ip_rules)))
        print(f"生成 {len(ip_rules)} httpdns ip")

    except Exception as e:
        raise WorkflowError(f"HTTPDNS 规则处理失败: {str(e)}")

def process_pmcdn_rules():
    try:
        # 读取 pmcdn_1.list
        pmcdn1_path = TEMP_DIR / "pmcdn_1.list"
        pmcdn1_data = pmcdn1_path.read_text().splitlines()

        site_rules = set()

        # 处理 pmcdn_1.list 数据
        for line in pmcdn1_data:
            line = line.strip()
            if line and not line.startswith('#'):
                # 域名不以 + 开头则加上 +. 前缀
                if not line.startswith('+'):
                    site_rules.add(f"+.{line}")
                else:
                    site_rules.add(line)

        # 写入规则文件
        (SITE_DIR / "pmcdn.list").write_text("\n".join(sorted(site_rules)))
        print(f"生成 {len(site_rules)} PMCDN domains")

    except Exception as e:
        raise WorkflowError(f"PMCDN 规则处理失败: {str(e)}")


def process_dns_blocklist():
    try:
        raw = TEMP_DIR / "dns-blocklists.list"
        lines = raw.read_text().splitlines()
        seen = set()
        result = []

        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                # 统一处理通配符格式，把 * 替换成 +
                processed_line = line.replace("*", "+")
                if processed_line not in seen:
                    seen.add(processed_line)
                    # 如果原始行以 * 开头，改成 + 开头
                    if line.startswith("*"):
                        line = "+" + line[1:]
                    result.append(line)

        (SITE_DIR / "dns-blocklists.list").write_text("\n".join(result))
        print(f"生成 {len(result)} dns-blocklists domains")

        # 删除原始文件
        raw.unlink()

    except Exception as e:
        raise WorkflowError(f"dns-blocklists 处理失败: {str(e)}")




def generate_tracker_lists():
    try:
        url = "https://testingcf.jsdelivr.net/gh/Tunglies/TrackersList@main/all.txt"
        r = requests.get(url, timeout=10)
        r.raise_for_status()

        lines = r.text.splitlines()
        ips = set()
        domains = set()

        ip_pattern = re.compile(
            r'^('
            r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'           # IPv4 octet
            r'(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}'  # IPv4 address
            r'(?:/(?:[0-9]|[12][0-9]|3[0-2]))?'                        # IPv4 CIDR
            r')|('
            r'(?:([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'              # Full IPv6
            r'(::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})|'           # :: IPv6
            r'([0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}))'
            r'(?:/(?:[0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?'          # IPv6 CIDR
            r')$',
            re.IGNORECASE
        )

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 去除协议头、路径和端口
            if "://" in line:
                line = line.split("://", 1)[1]
            if "/" in line:
                line = line.split("/", 1)[0]
            if ":" in line:
                line = line.split(":", 1)[0]

            if ip_pattern.match(line):
                try:
                    # IPv4增强验证
                    parts = line.split('.')
                    if len(parts) != 4:
                        continue
                    valid_octets = []
                    for part in parts:
                        if not part.isdigit():
                            raise ValueError(f"Invalid octet: {part}")
                        octet = int(part)
                        if 0 <= octet <= 255:
                            valid_octets.append(str(octet))
                    normalized_ip = ".".join(valid_octets)
                    if len(valid_octets) == 4:
                        ips.add(normalized_ip)
                except Exception as e:
                    print(f"跳过无效IP格式: {line} - {str(e)}")
            elif '.' in line:
                domain = line.lower().replace("*.", "+.")
                domains.add(domain)

        if domains:
            (SITE_DIR / "tracker.list").write_text("\n".join(sorted(domains)), encoding='utf-8')
            print(f"生成 {len(domains)} tracker domains")
        else:
            print("未找到 tracker domains")
            (SITE_DIR / "tracker.list").write_text("# Empty domain list", encoding='utf-8')

        if ips:
            (IP_DIR / "tracker.list").write_text("\n".join(sorted(ips)), encoding='utf-8')
            print(f"生成 {len(ips)} tracker IPs")
        else:
            print("未找到 tracker IP")
            (IP_DIR / "tracker.list").write_text("# Empty IP list", encoding='utf-8')

    except Exception as e:
        raise WorkflowError(f"Tracker list generation failed: {str(e)}")




def install_mihomo():
    try:
        version_response = requests.get(
            "https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/version.txt",
            timeout=10
        )
        version_response.raise_for_status()  # 请求失败抛错
        version = version_response.text.strip()

        if not version:
            raise WorkflowError("从version.txt获取的版本号为空")

        download_url = f"https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/mihomo-linux-amd64-v3-{version}.gz"

        with requests.get(download_url, stream=True) as response:
            response.raise_for_status()

            # 流式解压写文件
            with gzip.GzipFile(fileobj=response.raw) as gz_file:
                with open(os.path.join(MI_HOME, "mihomo"), 'wb') as f:
                    shutil.copyfileobj(gz_file, f)

        # 设置可执行权限
        os.chmod(os.path.join(MI_HOME, "mihomo"), 0o755)
        print(f"Mihomo {version} 安装成功 -> {MI_HOME}")

    except requests.RequestException as e:
        raise WorkflowError(f"网络请求失败: {str(e)}")
    except IOError as e:
        raise WorkflowError(f"文件操作失败: {str(e)}")
    except Exception as e:
        raise WorkflowError(f"未知错误: {str(e)}")






      


            
