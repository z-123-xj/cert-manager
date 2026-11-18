#!/usr/bin/env python3
"""cert-manager

用 acme.sh 签发 Let's Encrypt 证书（DNS-01 自动验证，支持阿里云 DNS / Cloudflare），
签发成功后：
  1. 上传到阿里云 SSL 证书服务（CAS）
  2. 绑定到对应 DCDN 加速域名 / WAF 3.0 防护域名
  3. 清理该证书在阿里云上的旧版本（保留刚上传的）

配置以「证书」为单位，每张证书自带 dcdn_domains / waf_domains（可选），无需 cert 交叉引用：
  - name:           可选标识（CAS 证书名前缀）；省略时取主域名
  - dns/dns_account: DNS-01 验证平台名 / 该平台下账号名
  - domains:        可选 SAN 列表；省略时由 dcdn_domains + waf_domains 去重推导
  - deploy/deploy_account: 部署平台（aliyun_cn/aliyun_intl）+ 该平台下账号名，二者配对确定账号
  - dcdn_domains:   字符串简写或 {domain, deploy, deploy_account}
  - waf_domains:    字符串简写或 {domain, deploy, deploy_account, waf_zone, waf_id, origin}（origin=源站，兼容旧 backends）
  - waf_origin:     可选，证书级默认源站，供未写 origin 的 WAF 域名复用
  - waf_zone:       WAF 地域 cn=中国内地(cn-hangzhou) / intl=非中国内地(ap-southeast-1)，域名级可覆盖；
                    每地域自动发现该账号下唯一实例，无需填 waf_id
  - waf_id:         可选高级覆盖，显式 WAF 实例 ID（多实例时才需要），填了不再自动发现
账号层级（aliyun_cn / aliyun_intl / cloudflare，下一层为账号名）写在 certs.yaml；AK/SK 等敏感值放 config/.env（CN1_AK / CN1_SK 等），用 ${VAR} 注入，region 写在 yaml。
WAF 地域按 waf_zone 解析（cn->cn-hangzhou / intl->ap-southeast-1；缺省沿用账号 region 或 WAF_REGION）；实例 ID 优先级：waf_id > <平台>_<账号>_WAF_INSTANCE_ID > <账号>_WAF_INSTANCE_ID > 全局 WAF_INSTANCE_ID > 按地域自动发现唯一实例。同账号 cn/intl 是两个实例，分开查询/缓存/部署。发现结果只在本次脚本执行内缓存（按 平台.账号.地域），同一账号同一地域只查一次；不跨进程持久化，下次执行重新发现。
每个证书只签发一次，按「证书 + 部署平台 + 部署账号」分组，每组只上传一次。

支持国内站 / 国际站两套阿里云账号部署；DNS 验证可分别走阿里云 DNS 或 Cloudflare（按证书配置）。
告警（Prometheus / 到期前两周）后续接入，本脚本只负责签发与替换。

依赖：见 requirements.txt
"""
import os
import sys
import re
import json
import time
import subprocess
import argparse
import yaml
import shutil

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
# CAS SDK 与 DCDN 类似：包命名空间里 X 是模块，需从具体模块文件导入类
from aliyunsdkcas.request.v20180713.CreateUserCertificateRequest import CreateUserCertificateRequest
from aliyunsdkcas.request.v20180713.DeleteUserCertificateRequest import DeleteUserCertificateRequest
from aliyunsdkcas.request.v20180713.DescribeUserCertificateListRequest import DescribeUserCertificateListRequest
# DCDN SDK 的 API 版本目录随包版本变化（实测 2.2.19 为 v20180115），做兼容兜底
try:
    from aliyunsdkdcdn.request.v20180115.SetDcdnDomainSSLCertificateRequest import SetDcdnDomainSSLCertificateRequest
except ImportError:
    from aliyunsdkdcdn.request.v20180510.SetDcdnDomainSSLCertificateRequest import SetDcdnDomainSSLCertificateRequest
try:
    from aliyunsdkdcdn.request.v20180115.DescribeDcdnDomainCertificateInfoRequest import DescribeDcdnDomainCertificateInfoRequest
except ImportError:
    DescribeDcdnDomainCertificateInfoRequest = None

LE_DIR = os.environ.get("LE_WORKING_DIR", os.path.join(os.path.expanduser("~"), ".acme.sh"))


def acme_bin():
    """探测 acme.sh 可执行文件路径；支持 ACME_SH_BIN 环境变量或常见安装位置。"""
    cands = []
    if os.environ.get("ACME_SH_BIN"):
        cands.append(os.environ["ACME_SH_BIN"])
    which = shutil.which("acme.sh")
    if which:
        cands.append(which)
    cands += [
        os.path.join(os.path.expanduser("~"), ".acme.sh", "acme.sh"),
        "/acme.sh/acme.sh",
        "/root/.acme.sh/acme.sh",
    ]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "acme.sh"  # 回退 PATH；若仍缺失 subprocess 会给出清晰报错


def check_acme():
    if acme_bin() == "acme.sh" and not shutil.which("acme.sh"):
        log("[ERROR] 找不到 acme.sh。请先安装：curl https://get.acme.sh | sh")
        log("        （若装在非标准路径，设置环境变量 ACME_SH_BIN=/path/to/acme.sh）")
        sys.exit(1)


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ----------------------------- 配置加载 -----------------------------
def expand_env(obj):
    """递归把配置里的 ${VAR} / $VAR 用环境变量替换。"""
    if isinstance(obj, str):
        return re.sub(r"\$\{([^}]+)\}|\$(\w+)",
                      lambda m: os.environ.get(m.group(1) or m.group(2), ""), obj)
    if isinstance(obj, dict):
        return {k: expand_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand_env(v) for v in obj]
    return obj


def load_env_file(path):
    """加载 config/.env（KEY=VALUE）到环境变量；已存在的变量（如 cron 内联）优先。"""
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k:
                os.environ.setdefault(k, v)


def dns_kind(dns):
    """把证书的 dns 平台名归一为 aliyun / cloudflare。
    aliyun_cn / aliyun_intl 都是阿里云 DNS（对应配置里的 aliyun_* 分组）；cloudflare 保持。"""
    if dns == "cloudflare":
        return "cloudflare"
    if dns == "aliyun" or (isinstance(dns, str) and dns.startswith("aliyun_")):
        return "aliyun"
    return None


def flatten_aliyun_groups(cfg):
    """把顶层 aliyun_* 分组（如 aliyun_cn / aliyun_intl）的下一层账号拍平进 accounts。
    下一层 key 即自定义账号名（cn1/intl1/...），与 dns_account/deploy_account 对应。
    分组名只是组织用途（国内站/国际站），不参与账号名；顶层 accounts 旧写法仍兼容。"""
    accounts = dict(cfg.get("accounts") or {})
    for key, value in cfg.items():
        if not (isinstance(key, str) and key.startswith("aliyun_") and isinstance(value, dict)):
            continue
        for name, acc in value.items():
            if isinstance(acc, dict):
                accounts[name] = dict(acc)
    cfg["accounts"] = accounts
    return cfg


def load_config(path):
    # 加载 certs.yaml 同目录的 .env 作为变量值，再展开 yaml 里的 ${VAR}。
    # 账号层级（aliyun_* 分组 / cloudflare）写在 certs.yaml；.env 只放扁平 key=value 值。
    load_env_file(os.path.join(os.path.dirname(os.path.abspath(path)), ".env"))
    with open(path, "r", encoding="utf-8") as f:
        cfg = expand_env(yaml.safe_load(f)) or {}
    return flatten_aliyun_groups(cfg)


# ----------------------------- 配置归一化 -----------------------------
def _as_list(v):
    if v is None or v == "":
        return []
    return [v] if isinstance(v, str) else list(v)


def deploy_items(items, default_account, with_origin=False, default_origin=None,
                 default_platform=None, default_waf_id=None, platform_accounts=None,
                 default_waf_zone=None):
    """把 dcdn_domains / waf_domains 统一成 [{domain, deploy, deploy_account, ...}]；支持字符串简写。
    deploy=部署平台（如 aliyun_cn），deploy_account=该平台下账号名，二者配对确定用哪个账号部署。
    域名项只写 deploy 未写 deploy_account 时，按 platform_accounts 推断该平台下的默认账号，
    避免跨账号错配（如只写 aliyun_intl 却落到证书级默认的 cn1）。
    with_origin=True 时保留 origin（WAF 自动接入源站，字符串或列表；域名级 waf_origin/backends
    亦可），并把证书级 waf_id/waf_zone 下发给域名项（域名级可覆盖）。waf_zone=cn/intl 决定
    WAF OpenAPI 地域（cn-hangzhou / ap-southeast-1），每地域自动发现唯一实例，无需填 waf_id；
    waf_id 仅作为显式实例 ID 的高级覆盖。default_origin 为证书级 waf_origin。
    若 items 本身是字符串（如 waf_domains: "a.com"），当成单元素列表处理，避免逐字符拆分。"""
    if isinstance(items, str):
        items = [items]
    out = []
    for item in items or []:
        if isinstance(item, str):
            row = {"domain": item.strip(), "deploy": default_platform, "deploy_account": default_account}
        elif isinstance(item, dict):
            deploy = item.get("deploy") or default_platform
            acct = item.get("deploy_account") or item.get("account")
            if not acct and deploy and platform_accounts:
                acct = platform_accounts.get(deploy)
            acct = acct or default_account
            row = {
                "domain": str(item.get("domain") or "").strip(),
                "deploy": deploy,
                "deploy_account": acct,
            }
        else:
            row = {"domain": "", "deploy": default_platform, "deploy_account": default_account}
        if with_origin:
            raw = (item.get("origin") or item.get("waf_origin") or item.get("backends")
                   if isinstance(item, dict) else None)
            origin = _as_list(raw) or _as_list(default_origin)
            if origin:
                row["origin"] = origin
            item_waf_id = (item.get("waf_id") or "").strip() if isinstance(item, dict) else ""
            # 证书级 waf_id 只继承给「部署平台/账号与证书级相同」的域名；
            # 域名若改到了别的账号，那个实例不通用，必须自己写 waf_id 或留空自动发现。
            same_target = (row["deploy"] == default_platform
                           and row["deploy_account"] == default_account)
            row["waf_id"] = item_waf_id or ((default_waf_id or "").strip() if same_target else "")
            item_zone = (item.get("waf_zone") or "").strip() if isinstance(item, dict) else ""
            row["waf_zone"] = item_zone or (default_waf_zone or "").strip()
        out.append(row)
    return out


def dcdn_items(items, default_account, default_platform=None, platform_accounts=None):
    return deploy_items(items, default_account, default_platform=default_platform,
                        platform_accounts=platform_accounts)


def waf_items(items, default_account, default_origin=None, default_platform=None,
              default_waf_id=None, platform_accounts=None, default_waf_zone=None):
    return deploy_items(items, default_account, with_origin=True,
                        default_origin=default_origin, default_platform=default_platform,
                        default_waf_id=default_waf_id, platform_accounts=platform_accounts,
                        default_waf_zone=default_waf_zone)


def normalize_config(cfg):
    """把新旧配置统一成「每张证书自带 dcdn_domains」的内部结构。

    新格式：certificates[].dcdn_domains（字符串简写或 {domain, deploy_account}）
    旧格式：顶层 dcdn_domains 按 cert 引用 / 后缀自动匹配回填（仅迁移用）
    归一化后每张证书一定有 name / domains / dns_account / dcdn_domains。
    """
    cfg = dict(cfg or {})
    accounts = cfg.get("accounts") or {}
    first_acc = next(iter(accounts), None)
    cf = cfg.get("cloudflare") or {}
    if isinstance(cf, dict) and "api_token" in cf:
        # 旧写法：cloudflare 段直接放单账号凭证 -> 归一化为命名子账号 default
        single = {k: cf[k] for k in ("api_token", "account_id", "email") if k in cf}
        cfg["cloudflare"] = {"default": single}
        cf = cfg["cloudflare"]
    # 平台 -> 该平台下第一个账号名，供域名项只写 deploy 未写 deploy_account 时推断。
    # 顶层 aliyun_cn / aliyun_intl / cloudflare 分组即平台；旧 accounts 写法无分组则跳过。
    platform_accounts = {}
    for pkey, pval in cfg.items():
        if isinstance(pval, dict) and pkey not in ("accounts", "cloudflare", "certificates"):
            for aname in pval:
                if isinstance(pval[aname], dict):
                    platform_accounts[pkey] = aname
                    break
    if isinstance(cf, dict):
        for aname in cf:
            if isinstance(cf[aname], dict):
                platform_accounts.setdefault("cloudflare", aname)
                break
    certs = cfg.get("certificates") or []
    norm = []
    for raw in certs if isinstance(certs, list) else []:
        if not isinstance(raw, dict):
            continue
        c = dict(raw)
        c.setdefault("dns", "aliyun_cn")
        if not c.get("dns_account"):
            # 按 dns 平台分组取该平台下第一个账号（与 deploy_account 一致），避免 aliyun_intl
            # 证书误用 first_acc（cn1）去签发；cloudflare 段亦然。旧 account 字段/兼容性兜底。
            c["dns_account"] = (c.get("account") or platform_accounts.get(c["dns"])
                                or (next(iter(cf), None) if isinstance(cf, dict) and cf else None)
                                or first_acc)
        default_deploy = c.get("deploy_account") or c.get("account") or first_acc
        default_platform = c.get("deploy") or c.get("platform")
        c["dcdn_domains"] = dcdn_items(c.get("dcdn_domains"), default_deploy,
                                       default_platform=default_platform,
                                       platform_accounts=platform_accounts)
        c["waf_domains"] = waf_items(c.get("waf_domains"), default_deploy,
                                     default_origin=c.get("waf_origin"),
                                     default_platform=default_platform,
                                     default_waf_id=c.get("waf_id"),
                                     platform_accounts=platform_accounts,
                                     default_waf_zone=c.get("waf_zone"))
        norm.append(c)

    # 先补齐 name / domains，供旧格式的自动匹配使用。省略 domains 时由 dcdn + waf 域名
    # 去重 + 排序推导，保证主域名（即 acme.sh 目录名）在增删域名后尽量稳定。
    def _all_targets(cert):
        return [i["domain"] for i in (cert["dcdn_domains"] + cert.get("waf_domains", []))
                if i.get("domain")]

    for c in norm:
        if not c.get("domains"):
            c["domains"] = sorted(set(_all_targets(c))) \
                           or ([c["name"]] if c.get("name") else [])
            c["_derived_domains"] = True
        if not c.get("name"):
            c["name"] = (c["domains"][0] if c["domains"] else "<未命名>").lstrip("*.")

    # 旧格式顶层 dcdn_domains：回填到对应证书（按 cert 引用；无 cert 则后缀自动匹配）
    for dd in cfg.pop("dcdn_domains", None) or []:
        if not isinstance(dd, dict):
            continue
        domain = str(dd.get("domain") or "").strip()
        cert_name = dd.get("cert")
        cert = (next((c for c in norm if c.get("name") == cert_name), None)
                if cert_name else match_cert(domain, norm))
        if cert is None:
            norm.append({"name": cert_name or "<未匹配>", "dns": "aliyun_cn", "domains": [],
                         "dcdn_domains": [], "_unmatched": domain})
            continue
        cert["dcdn_domains"].append({
            "domain": domain,
            "deploy": dd.get("deploy") or cert.get("deploy") or cert.get("platform"),
            "deploy_account": dd.get("deploy_account") or dd.get("account")
                              or cert.get("deploy_account") or first_acc,
        })
        if cert.get("_derived_domains"):
            derived = sorted({i["domain"] for i in cert["dcdn_domains"] if i.get("domain")})
            cert["domains"] = derived or cert["domains"]

    cfg["certificates"] = norm
    return cfg


# ----------------------------- 配置校验 -----------------------------
def validate_config(cfg):
    """加载期校验；返回 (errors, warnings)。主流程遇 error 直接退出，避免静默漏配。"""
    errors, warnings = [], []
    accounts = cfg.get("accounts") or {}
    cf = cfg.get("cloudflare") or {}
    certs = cfg.get("certificates") or []
    if not certs:
        errors.append("certificates 为空，没有要签发的证书")
    seen_names, seen_domains = set(), {}
    for c in certs:
        name = c.get("name") or "<未命名>"
        tag = f"证书 {name}"
        if c.get("_unmatched"):
            errors.append(f"旧格式 dcdn_domains 的 {c['_unmatched']} 找不到对应证书"
                          f"（补 cert 字段或改成嵌套写法）")
            continue
        if name in seen_names:
            errors.append(f"{tag}: name 重复（name 是 CAS 证书名前缀，必须唯一）")
        seen_names.add(name)
        dns, acc_name = c.get("dns"), c.get("dns_account")
        kind = dns_kind(dns)
        if not kind:
            errors.append(f"{tag}: 不支持的 dns={dns}（仅 aliyun_cn / aliyun_intl / cloudflare；"
                          f"兼容 aliyun）")
        if kind == "aliyun":
            acc = accounts.get(acc_name) if acc_name else None
            if not isinstance(acc, dict):
                errors.append(f"{tag}: dns_account={acc_name} 不在 aliyun_* 分组账号中")
            elif not (acc.get("access_key") and acc.get("access_secret")):
                errors.append(f"{tag}: DNS 账号 {acc_name} 缺少 access_key/access_secret")
        elif kind == "cloudflare":
            cf_cfg = cf.get(acc_name) if acc_name and isinstance(cf, dict) else None
            if not (isinstance(cf_cfg, dict) and cf_cfg.get("api_token")):
                errors.append(f"{tag}: dns_account={acc_name} 在 cloudflare 中不存在或缺少 api_token")
        domains = c.get("domains") or []
        if not domains:
            errors.append(f"{tag}: domains 为空（显式写 domains，或至少配一个 dcdn/waf 域名）")
        for d in domains:
            if (not isinstance(d, str) or not d or any(ch in d for ch in " /")
                    or d.startswith(".") or "." not in d):
                errors.append(f"{tag}: 非法域名 {d!r}")
        for kind, items in (("DCDN", c["dcdn_domains"]), ("WAF", c.get("waf_domains") or [])):
            for dd in items:
                domain, deploy_acc = dd.get("domain"), dd.get("deploy_account")
                if not domain:
                    errors.append(f"{tag}: {kind}_domains 存在空域名或非法项")
                    continue
                if not deploy_acc or deploy_acc not in accounts:
                    errors.append(f"{tag}: {domain} 的 deploy_account={deploy_acc} 不在 accounts 中")
                if domains and not cert_covers(c, domain):
                    errors.append(f"{tag}: {kind} 域名 {domain} 不被证书 SAN 覆盖（domains={domains}）")
                if domain in seen_domains and seen_domains[domain] != name:
                    errors.append(f"域名 {domain} 同时声明在证书 {seen_domains[domain]} 和 {name}，会重复绑定")
                seen_domains[domain] = name
                if kind == "WAF" and not dd.get("origin"):
                    warnings.append(f"{tag}: WAF 域名 {domain} 未配 origin 源站；"
                                    f"若该域名尚未接入 WAF 将无法自动接入，请先接入或补 origin/waf_origin")
        if c.get("_derived_domains") and len(domains) > 1:
            warnings.append(f"{tag}: domains 由 dcdn/waf 域名推导为 {domains}；"
                            f"如需泛域/裸域/额外 SAN，请显式写 domains")
    return errors, warnings


# ----------------------------- 证书路径 -----------------------------
def cert_paths(domain):
    """返回 (fullchain.cer, <domain>.key)。acme.sh 用 ECC 时目录名为 <domain>_ecc，
    RSA 时为 <domain>；优先检测已存在的目录，都不存在时回退到 <domain>（供首次签发前判断）。"""
    for d in (domain + "_ecc", domain):
        base = os.path.join(LE_DIR, d)
        cert_file = os.path.join(base, "fullchain.cer")
        if os.path.exists(cert_file):
            return cert_file, os.path.join(base, domain + ".key")
    base = os.path.join(LE_DIR, domain)
    return os.path.join(base, "fullchain.cer"), os.path.join(base, domain + ".key")


# ----------------------------- 证书域名解析 -----------------------------
def cert_domains(cert):
    """证书 SAN 列表；normalize_config 后恒有 domains（省略时已由 dcdn 域名推导）。"""
    return list(cert.get("domains") or [cert["name"]])


# ----------------------------- acme.sh 签发 -----------------------------
def run_acme(domains, dns_arg, env, renew):
    """调用 acme.sh 签发 / 续期。domains[0] 作主域名，其余作 SAN，每个拆成 -d。"""
    acme = acme_bin()
    # 让 acme.sh 把证书存到 LE_DIR（与 cert_paths 读取位置一致）
    env = dict(os.environ, LE_WORKING_DIR=LE_DIR, **env)
    main = domains[0]
    base = [acme, "--home", LE_DIR]
    if renew:
        cmd = base + ["--renew", "--no-cron", "-d", main]
    else:
        # 固化默认 CA 为 Let's Encrypt（幂等），避免环境默认 CA 被改回 ZeroSSL 导致签发异常
        subprocess.run([acme, "--home", LE_DIR, "--set-default-ca", "--server", "letsencrypt"],
                       env=dict(os.environ, LE_WORKING_DIR=LE_DIR), capture_output=True, text=True)
        # 签发时显式指定 Let's Encrypt（无需注册邮箱/EAB，最适合脚本化）；
        # 若想改用 ZeroSSL，去掉下面 --server 参数，并先执行一次 `acme.sh --register-account -m 你的邮箱`
        cmd = base + ["--issue", "--server", "letsencrypt", "--dns", dns_arg, "--no-cron", "-d", main]
        for d in domains[1:]:
            cmd += ["-d", d]
    log(f"acme.sh {'renew' if renew else 'issue'} {main}" +
        (f" +SAN {domains[1:]}" if len(domains) > 1 else ""))
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    log(out[-2000:])  # 只打印末尾，避免刷屏
    # acme.sh 在 renew 未到期时会打印 "Skipping" 且（部分版本）以非零退出码结束；
    # 这不算失败（证书仍有效，可直接部署），故视为成功。真正签发失败（如 DNS 错误）
    # 的 out 里不会有 "Skipping"，仍会判为失败。
    ok = r.returncode == 0 or "Skipping" in out
    return ok, out


# ----------------------------- 阿里云客户端 -----------------------------
def make_client(account):
    region = account.get("region", "cn-hangzhou")
    endpoint = account.get("endpoint")
    if endpoint:
        return AcsClient(account["access_key"], account["access_secret"], region, endpoint)
    return AcsClient(account["access_key"], account["access_secret"], region)


# ----------------------------- 删除旧证书 -----------------------------
def delete_old_certs(client, prefix, keep):
    """删除指定名称前缀的旧证书（仅本脚本 acme_ 前缀管理的），保留 keep 那一份。"""
    req = DescribeUserCertificateListRequest()
    req.set_accept_format("json")
    req.set_CurrentPage(1)
    req.set_ShowSize(100)
    try:
        resp = json.loads(client.do_action_with_exception(req))
    except Exception as e:
        log(f"[WARN] 列出证书失败: {e}")
        return
    raw = resp.get("CertificateList", {})
    certs = raw.get("Certificate", []) if isinstance(raw, dict) else (raw or [])
    for c in certs:
        name = c.get("Name", "")
        cid = c.get("CertId")
        if name.startswith(prefix) and str(cid) != str(keep):
            try:
                d = DeleteUserCertificateRequest()
                d.set_accept_format("json")
                d.set_CertId(str(cid))
                client.do_action_with_exception(d)
                log(f"已删除旧证书 cert_id={cid}")
            except Exception as e:
                log(f"[WARN] 删除旧证书 {cid} 失败: {e}")


def find_cert_id_by_name(client, name):
    """在 CAS 中按证书名称查找已存在的 CertId；找不到返回 None。
    兼容不同返回结构与字段命名（含小写 name/id）；未匹配时打印诊断摘要。"""
    req = DescribeUserCertificateListRequest()
    req.set_accept_format("json")
    for setter, val in (("set_ShowSize", 500), ("set_PageSize", 500),
                        ("set_CurrentPage", 1), ("set_PageNo", 1)):
        if hasattr(req, setter):
            try:
                getattr(req, setter)(val)
            except Exception:
                pass
    try:
        resp = json.loads(client.do_action_with_exception(req))
    except Exception as e:
        log(f"[WARN] 查询证书列表失败: {e}")
        return None
    # CertificateList 可能是 list，也可能是 {Certificate:[...]}，兼容两者
    cl = resp.get("CertificateList") or resp.get("CertificateListModel") or resp.get("Certificate") or []
    certs = cl if isinstance(cl, list) else (cl.get("Certificate", []) if isinstance(cl, dict) else [])
    for c in certs:
        cname = (c.get("name") or c.get("Name") or c.get("certName")
                 or c.get("CertName") or c.get("CommonName"))
        if cname == name:
            return c.get("id") or c.get("CertId") or c.get("certId")
    log(f"[DEBUG] 列表未匹配 name={name}；共 {len(certs)} 张")
    return None


# ----------------------------- 证书覆盖判断 -----------------------------
def cert_covers(cert, domain):
    """domain 是否被该证书的 SAN 覆盖。泛域 *.suf 只覆盖一级子域，
    既不覆盖裸域 suf，也不覆盖多级子域（如 a.b.suf）。"""
    for n in cert_domains(cert):
        if n == domain:
            return True
        if n.startswith("*."):
            tail = n[1:]  # ".suf"
            if domain.endswith(tail):
                label = domain[:-len(tail)]
                if label and "." not in label:
                    return True
    return False


def match_cert(domain, certs):
    """为 DCDN 域名选证书：精确匹配优先，否则选最长泛域名后缀。
    仅用于旧格式（顶层 dcdn_domains 未写 cert）的迁移，新格式不需要。"""
    exact = None
    best = None
    best_len = -1
    for c in certs:
        if not cert_covers(c, domain):
            continue
        if domain in cert_domains(c):
            exact = c
        sufs = [n[2:] for n in cert_domains(c) if n.startswith("*.")]
        if sufs:
            suf = max(sufs, key=len)
            if len(suf) > best_len:
                best = c
                best_len = len(suf)
    return exact or best


# ----------------------------- 签发单个证书 -----------------------------
def issue_certificate(cert, accounts, cf, force):
    name = cert["name"]
    dns = cert.get("dns", "aliyun_cn")
    kind = dns_kind(dns)
    if kind == "aliyun":
        acc_name = cert.get("dns_account")
        acc = accounts.get(acc_name)
        if not acc:
            log(f"[ERROR] 证书 {name} dns={dns} 但 DNS 账号 {acc_name} 不在 aliyun_* 分组中，跳过")
            return
        # acme.sh 的 dns_ali 插件读取的变量名是「首字母大写的 Ali_Key / Ali_Secret」
        # （不是 ALI_KEY，也不是全大写的 ALI_Key），大小写必须精确匹配，否则凭证读不到 → 签发失败。
        k = acc.get("access_key")
        s = acc.get("access_secret")
        if not (k and s):
            log(f"[ERROR] 证书 {name} 的 DNS 账号 {acc_name} 未配置 access_key/access_secret，跳过签发")
            return
        acme_env = {"Ali_Key": k, "Ali_Secret": s}
        # 调试用：打印账号名 + 脱敏 access_key，便于确认实际使用的是哪个 DNS 账号
        log(f"[DEBUG] 证书 {name} 使用 DNS 账号 {acc_name} 签发（Ali_Key={k[:10]}****，请核对阿里云控制台该账号 AccessKey 前缀是否一致）")
        dns_arg = "dns_ali"
    elif kind == "cloudflare":
        # cloudflare 支持多账号（命名子字典）；也兼容旧的「单账号直接写在 cloudflare 下」写法
        cf_name = cert.get("dns_account")
        cf_cfg = None
        if isinstance(cf, dict):
            if cf_name and cf_name in cf and isinstance(cf[cf_name], dict):
                cf_cfg = cf[cf_name]
            elif not cf_name and "api_token" in cf:
                cf_cfg = cf
        if not isinstance(cf_cfg, dict) or not cf_cfg.get("api_token"):
            log(f"[ERROR] 证书 {name} dns=cloudflare 凭证缺失（dns_account={cf_name}），跳过")
            return
        acme_env = {"CF_Token": cf_cfg["api_token"]}
        if cf_cfg.get("account_id"):
            acme_env["CF_Account_ID"] = cf_cfg["account_id"]
        if cf_cfg.get("email"):
            acme_env["CF_Email"] = cf_cfg["email"]
        dns_arg = "dns_cf"
    else:
        log(f"[ERROR] 证书 {name} 不支持的 dns={dns}，跳过")
        return
    domains = cert_domains(cert)
    cert_file, _ = cert_paths(domains[0])
    exists = os.path.exists(cert_file)
    # 首次 issue；之后 renew（acme.sh 自己判断是否需要真正续期，未到期会跳过）
    if exists and not force:
        log(f"[INFO] {name} 本地已存在签发且未过期（到期 {cert_expiry_date(cert_file)}），"
            f"调用 renew，acme.sh 未到期会自动跳过")
    else:
        log(f"[INFO] {name} 开始签发（{'--force 强制重签' if force else '本地无证书'}）")
    ok, _out = run_acme(domains, dns_arg, acme_env, renew=exists and not force)
    if not ok:
        log(f"[ERROR] acme.sh 签发 {name} 失败（dns_account={cert.get('dns_account')}）："
            f"请检查该 DNS 账号凭证是否正确、是否拥有对应域名的解析权限")
        return


# ----------------------------- 部署一组（证书 + 账号） -----------------------------
def get_dcdn_cert(client, domain):
    """查询 DCDN 域名当前绑定的证书信息；接口缺失或查询失败时返回 None。"""
    if DescribeDcdnDomainCertificateInfoRequest is None:
        return None
    req = DescribeDcdnDomainCertificateInfoRequest()
    req.set_accept_format("json")
    req.set_DomainName(domain)
    try:
        resp = json.loads(client.do_action_with_exception(req))
    except Exception as e:
        log(f"[WARN] 查询 {domain} 当前绑定证书失败: {e}")
        return None
    infos = resp.get("CertInfos") or {}
    items = infos.get("CertInfo", []) if isinstance(infos, dict) else (infos or [])
    return items[0] if isinstance(items, list) and items else None


def _leaf_pem(pem_text):
    """取 PEM 文本里第一段证书（叶子），统一换行便于比较。"""
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_text or "", re.S)
    return m.group(0).replace("\r\n", "\n").strip() if m else ""


def cert_not_before_date(cert_pem):
    """取证书签发开始日期 YYYY-MM-DD（openssl x509 的 startdate）用作 acme_ 后缀标签；解析失败回退当天。"""
    try:
        from cryptography import x509
        c = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        nb = getattr(c, "not_valid_before_utc", None)
        if nb is None:
            nb = c.not_valid_before
        return nb.strftime("%Y-%m-%d")
    except Exception:
        return time.strftime("%Y-%m-%d")


def cert_expiry_date(cert_file):
    """本地证书的到期日 YYYY-MM-DD（openssl x509 的 enddate），仅用于日志展示；解析失败返回 '?'。"""
    try:
        pem = open(cert_file, "r", encoding="utf-8").read()
        from cryptography import x509
        c = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        na = getattr(c, "not_valid_after_utc", None)
        if na is None:
            na = c.not_valid_after
        return na.strftime("%Y-%m-%d")
    except Exception:
        return "?"


def deploy_cert_group(cert, account, acc_name, domains, force):
    """以 DCDN 云端实际绑定状态为准做幂等：逐域名查当前绑定证书，与本地上传的
    证书内容一致即跳过；否则上传（acme_ 前缀命名）并绑定，最后清理同名前缀的旧证书
    （只动 acme_ 前缀，不碰手动上传的其他证书）。"""
    cert_name = cert["name"]
    main = cert_domains(cert)[0]
    cert_file, key_file = cert_paths(main)
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        log(f"[WARN] 证书文件缺失: {cert_file}，跳过部署")
        return
    cert_pem = open(cert_file, "r", encoding="utf-8").read()
    key_pem = open(key_file, "r", encoding="utf-8").read()
    client = make_client(account)
    # acme_ 前缀 = 本脚本管理的标识；* 等字符替换掉以保证证书名合法
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cert_name)
    nb_date = cert_not_before_date(cert_pem)
    cert_label = f"acme_{safe}_{nb_date}"

    def dcdn_label(domain):
        """DCDN 绑定名按部署域名生成：同一张证书部署到多个域名时名字各不相同
        （如 acme_api.jssupergame.com_2026-11-16 / acme_cdn.jssupergame.com_2026-11-16），
        避免 DCDN 侧同名证书互抢（CertNameAlreadyExists）；实际内容都是同一份证书文件。"""
        return f"acme_{re.sub(r'[^A-Za-z0-9._-]', '_', domain)}_{nb_date}"

    local_pem = _leaf_pem(cert_pem)
    # 0) 逐域名检查云端已绑定的证书是否就是这份（域名级证书名 + 内容一致 + HTTPS 已开）
    # to_bind 记录 (域名, 原绑定的 CertName)，用于绑定成功后注明替换了哪张旧证书
    to_bind = []
    for domain in domains:
        bound = get_dcdn_cert(client, domain)
        old_name = (bound.get("CertName", "") if bound else "") or ""
        if (not force and bound
                and old_name == dcdn_label(domain)
                and str(bound.get("SSLProtocol")) == "on"
                and _leaf_pem(bound.get("SSLPub") or "") == local_pem):
            log(f"[SKIP] {domain} 已绑定该证书（CertName={old_name}），跳过")
            continue
        to_bind.append((domain, old_name or None))
    if not to_bind:
        return
    # 1) 上传到阿里云 SSL 证书服务（同名先查重，存在则复用，避免 NameRepeat 重复创建）
    reused = False
    cert_id = find_cert_id_by_name(client, cert_label)
    if not cert_id:
        req = CreateUserCertificateRequest()
        req.set_accept_format("json")
        req.set_Name(cert_label)
        req.set_Cert(cert_pem)
        req.set_Key(key_pem)
        try:
            resp = json.loads(client.do_action_with_exception(req))
            cert_id = resp.get("CertId")
        except Exception as e:
            # 同名已存在（NameRepeat）时回退查重复用，避免重复创建
            if "NameRepeat" in str(e):
                cert_id = find_cert_id_by_name(client, cert_label)
                if cert_id:
                    reused = True
            if not cert_id:
                log(f"[ERROR] 上传证书到阿里云失败: {e}")
                return
        if cert_id and not reused:
            log(f"已上传证书 cert_id={cert_id}（账号 {acc_name}，名称 {cert_label}）")
    else:
        reused = True
    if not cert_id:
        log(f"[ERROR] 上传证书未返回 CertId")
        return
    if reused:
        log(f"复用已存在同名证书 cert_id={cert_id}（账号 {acc_name}，名称 {cert_label}）")
    # 2) 绑定到需要更新的 DCDN 加速域名
    # DCDN 的 SetDcdnDomainSSLCertificate 接口只能「上传内容绑定」，不支持「切换到已存在的
    # 同名证书」（实测：不传内容会 SSLPri.MissingParameter，传同名内容会 CertNameAlreadyExists）。
    # 因此仅在证书名无冲突时上传绑定；遇到同名冲突视为已部署并 SKIP，需在控制台手动改绑。
    def _bind(domain, cert_name):
        r = SetDcdnDomainSSLCertificateRequest()
        r.set_accept_format("json")
        r.set_DomainName(domain)
        r.set_CertName(cert_name)
        r.set_SSLProtocol("on")
        if hasattr(r, "set_SSLPub"):
            r.set_SSLPub(cert_pem)
        elif hasattr(r, "set_Cert"):
            r.set_Cert(cert_pem)
        if hasattr(r, "set_SSLPri"):
            r.set_SSLPri(key_pem)
        client.do_action_with_exception(r)

    for domain, old_name in to_bind:
        try:
            _bind(domain, dcdn_label(domain))
            if old_name:
                log(f"[BIND] {domain} -> {dcdn_label(domain)}（替换原证书 {old_name}）")
            else:
                log(f"[BIND] {domain} -> {dcdn_label(domain)}（原未开启 HTTPS 或查不到绑定记录）")
        except Exception as e:
            if "CertNameAlreadyExists" in str(e):
                # DCDN 库已存在同名证书，接口不允许覆盖/切换引用，只能控制台手动改绑
                log(f"[SKIP] {domain} 绑定失败：DCDN 已存在同名证书 {dcdn_label(domain)}"
                    f"（若未生效，请在 DCDN 控制台把该域名改绑到 {dcdn_label(domain)} 后重跑）")
            else:
                log(f"[ERROR] 绑定 DCDN {domain} 失败: {e}")
    # 3) 清理本脚本上传的旧版本（仅 acme_<cert_name>_ 前缀，保留当前这份）
    delete_old_certs(client, f"acme_{safe}_", keep=cert_id)


# ----------------------------- WAF 3.0 部署 -----------------------------
# WAF 3.0 用 RPC 风格 OpenAPI（版本 2021-10-01，endpoint wafopenapi.<region>.aliyuncs.com）。
# 与 DCDN 不同：证书以「引用 CertId」方式绑定，ModifyDomainCert 只换证书不动端口/转发；
# 只有首次开 443 才需要 ModifyDomain（必须带 Listen + Redirect）。
WAF_API_VERSION = "2021-10-01"
WAF_LISTEN_FIELDS = ("HttpPorts", "HttpsPorts", "Http2Enabled", "CertId", "SM2Enabled",
                     "SM2CertId", "SM2AccessOnly", "TLSVersion", "EnableTLSv3", "CipherSuite",
                     "CustomCiphers", "FocusHttps", "XffHeaderMode", "XffHeaders", "IPv6Enabled",
                     "ProtectionResource", "ExclusiveIp", "HstsIncludeSubDomain", "HstsPreload",
                     "HstsMaxAge")
WAF_REDIRECT_FIELDS = ("Backends", "Loadbalance", "FocusHttpBackend", "SniEnabled", "SniHost",
                       "RequestHeaders", "ConnectTimeout", "ReadTimeout", "WriteTimeout",
                       "CnameEnabled", "RoutingRules", "Keepalive", "Retry", "KeepaliveRequests",
                       "KeepaliveTimeout", "XffProto", "BackupBackends", "XClientIp", "XTrueIp",
                       "WebServerType", "WLProxyClientIp", "MaxBodySize", "Http2Origin",
                       "Http2OriginMaxConcurrency", "BackendPorts", "ProxyProtocol")


def waf_api(client, action, params, region):
    """调 WAF 3.0 OpenAPI，返回 dict；region 用于拼 endpoint 且作为 RegionId 默认传入。"""
    req = CommonRequest()
    req.set_accept_format("json")
    req.set_domain(f"wafopenapi.{region}.aliyuncs.com")
    req.set_version(WAF_API_VERSION)
    req.set_action_name(action)
    req.set_method("POST")
    payload = {"RegionId": region}
    payload.update({k: v for k, v in (params or {}).items() if v is not None})
    for k, v in payload.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False)
        req.add_query_param(k, v)
    return json.loads(client.do_action_with_exception(req))


def _waf_instance_items(resp):
    """把 DescribeInstance 的返回归一成实例 dict 列表。
    文档 2021-10-01 顶层就是单个实例（含 InstanceId），个别版本包在 Instances/Instance 里。"""
    if not isinstance(resp, dict):
        return []
    if resp.get("InstanceId"):
        return [resp]
    for key in ("Instances", "Instance", "InstanceInfos", "InstanceList"):
        v = resp.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
        if isinstance(v, dict):
            return [v] if v.get("InstanceId") else [x for x in v.values() if isinstance(x, dict)]
    return []


def _ms_to_date(v):
    try:
        return time.strftime("%Y-%m-%d", time.localtime(int(v) / 1000))
    except Exception:
        return "-"


def describe_and_list_waf_instances(client, region):
    """调 DescribeInstance 拉取并打印账号下 WAF 实例详情，返回实例列表。"""
    resp = waf_api(client, "DescribeInstance", {}, region)
    items = _waf_instance_items(resp)
    status_map = {1: "正常", 2: "到期", 3: "释放"}
    log(f"[WAF 实例] region={region} 查到 {len(items)} 个实例：")
    if not items and isinstance(resp, dict):
        # 解析为空时打印原始响应结构，便于判断是账号无实例 / region 不对 / 返回结构未识别
        log(f"[WAF 实例] 原始响应字段={list(resp.keys())}；摘要={str(resp)[:500]}")
    for it in items:
        log("  "
            f"InstanceId={it.get('InstanceId', '-')}"
            f" | 地域={it.get('RegionId', '-')}"
            f" | 状态={status_map.get(it.get('Status'), it.get('Status', '-'))}"
            f" | 版本={it.get('Edition', '-')}"
            f" | 付费={it.get('PayType', '-')}"
            f" | 欠费={'是' if str(it.get('InDebt')) == '1' else '否'}"
            f" | 到期={_ms_to_date(it.get('EndTime'))}")
    return items


# 每个账号自动发现到的 WAF 实例 ID，按账号名缓存（本次进程内复用，避免重复调接口）
_WAF_ID_CACHE = {}

# waf_zone -> WAF OpenAPI region（阿里云固定：中国内地 cn-hangzhou / 非中国内地 ap-southeast-1）
WAF_ZONE_REGION = {"cn": "cn-hangzhou", "intl": "ap-southeast-1"}


def waf_account_env(account_name, suffix, platform=None):
    """取账号级 WAF 配置，按优先级尝试（平台+账号 > 账号 > 全局）：
      <PLATFORM>_<ACCOUNT>_WAF_<SUFFIX>  如 ALIYUN_CN_CN1_WAF_INSTANCE_ID（平台 aliyun_cn）
      <ACCOUNT>_WAF_<SUFFIX>            如 CN1_WAF_INSTANCE_ID
      ALIYUN_<ACCOUNT>_WAF_<SUFFIX>     兼容旧写法
      WAF_<SUFFIX>                      全局兜底"""
    up = (account_name or "").upper()
    prefixes = []
    if platform:
        plat = str(platform).upper()  # aliyun_cn -> ALIYUN_CN
        prefixes.append(f"{plat}_{up}" if up else plat)
    prefixes += [up, "ALIYUN_" + up] if up else []
    for prefix in prefixes:
        v = (os.environ.get(f"{prefix}_WAF_{suffix}") or "").strip()
        if v:
            return v
    return (os.environ.get(f"WAF_{suffix}") or "").strip()


def waf_region(zone, account_name=None, platform=None, account=None):
    """解析 WAF 地域：waf_zone(cn/intl) 优先，其次环境变量 WAF_REGION，最后账号 region。
    cn -> cn-hangzhou（中国内地实例），intl -> ap-southeast-1（非中国内地实例）。"""
    z = (zone or "").strip().lower()
    if z in WAF_ZONE_REGION:
        return WAF_ZONE_REGION[z]
    env_region = waf_account_env(account_name, "REGION", platform)
    if env_region:
        return env_region
    return (account or {}).get("region") or "cn-hangzhou"


def get_waf_instance_id(client, region, account_name=None, platform=None, configured_id=None):
    """取 WAF 实例 ID：证书 waf_id > 平台+账号 > 账号 > 全局 > 自动发现（单实例自动用，多实例报错）。"""
    # 缓存 key 带 region：同一账号的 cn/intl 两个 zone 是两个不同 WAF 实例，不能串用
    key = (f"{platform}.{account_name}.{region}" if platform else f"{account_name}.{region}").lower()
    iid = (configured_id or "").strip() or waf_account_env(account_name, "INSTANCE_ID", platform)
    if iid:
        return iid
    if key in _WAF_ID_CACHE:
        # 值为 False 表示本进程已查询但该账号无可定实例，直接返回 None，避免重复调接口
        return _WAF_ID_CACHE[key] or None
    who = f"平台 {platform} / 账号 {account_name}" if platform else f"账号 {account_name or '-'}"
    var_hint = (f"{(platform or '').upper()}_{(account_name or '').upper()}_WAF_INSTANCE_ID"
                if platform and account_name else
                (f"{(account_name or '').upper()}_WAF_INSTANCE_ID" if account_name else "WAF_INSTANCE_ID"))
    log(f"[INFO] {who} 未配 WAF 实例 ID，调用 DescribeInstance 获取实例列表…")
    try:
        items = describe_and_list_waf_instances(client, region)
    except Exception as e:
        log(f"[WARN] 查询 WAF 实例失败: {e}；请在 .env 配置 {var_hint}")
        _WAF_ID_CACHE[key] = False
        return None
    active = [it for it in items if it.get("Status") in (1, "1") and str(it.get("InDebt")) != "1"]
    if len(active) == 1:
        chosen = active[0]["InstanceId"]
        _WAF_ID_CACHE[key] = chosen
        log(f"[INFO] 账号 {account_name or '-'} 地域 {region} 未配 {var_hint}，自动选用唯一正常实例 {chosen}"
            f"（本次执行内已缓存，同一账号同一地域不再重复查询；如需固定可在 config/.env 写 {var_hint}={chosen}）")
        return chosen
    if not active:
        log(f"[ERROR] 账号 {account_name or '-'} 在 region={region} 未查到状态正常、未欠费的 WAF 实例，"
            f"请检查账号或 .env 的 WAF_REGION/{var_hint}")
    else:
        log(f"[ERROR] 账号 {account_name or '-'} 在 region={region} 查到 {len(active)} 个可用 WAF 实例，"
            f"请在 .env 明确写 {var_hint}=<上面任一 InstanceId> 后重跑")
    _WAF_ID_CACHE[key] = False
    return None


def waf_find_domain(client, region, iid, domain):
    """DescribeDomains 按域名过滤查是否已接入。
    返回 (record, ok)：record 为接入记录 dict；ok=False 表示查询失败（不能据此判定未接入）。"""
    try:
        resp = waf_api(client, "DescribeDomains",
                       {"InstanceId": iid, "Domain": domain}, region)
    except Exception as e:
        log(f"[WARN] 查询 WAF 域名 {domain} 失败: {e}")
        return None, False
    for d in resp.get("Domains") or []:
        if d.get("Domain") == domain:
            return d, True
    return None, True


def waf_domain_detail(client, region, iid, domain):
    try:
        return waf_api(client, "DescribeDomainDetail",
                       {"InstanceId": iid, "Domain": domain}, region)
    except Exception as e:
        log(f"[WARN] 查询 WAF 域名详情 {domain} 失败: {e}")
        return None


def waf_cert_number(value):
    """把 WAF 证书 ID 归一成纯数字串用于比对：'123-cn-hangzhou' -> '123'。"""
    s = str(value or "")
    return s.split("-", 1)[0] if re.match(r"^\d+-", s) else s


def waf_backends(redirect):
    """兼容详情里 Backends/Backeds 的数组形态（元素可能是字符串或 {Backend: ...}）。"""
    raw = (redirect or {}).get("Backends") or (redirect or {}).get("Backeds") or []
    out = []
    for b in raw if isinstance(raw, list) else []:
        v = b.get("Backend") if isinstance(b, dict) else b
        if v:
            out.append(v)
    return out


def waf_open_443_and_bind(client, region, iid, domain, detail, item, cert_identifier):
    """用 ModifyDomain 显式开启 443 并绑定证书：必须带完整 Listen + Redirect，
    并保留云端现有回源，否则会冲掉已配置的转发规则。返回实际使用的源站列表。"""
    listen = detail.get("Listen") or {}
    new_listen = {k: listen[k] for k in WAF_LISTEN_FIELDS if k in listen}
    new_listen["HttpsPorts"] = [443]
    new_listen["CertId"] = cert_identifier
    redirect_in = detail.get("Redirect") or {}
    new_redirect = {k: redirect_in[k] for k in WAF_REDIRECT_FIELDS if k in redirect_in}
    # 优先用云端现有回源，其次用配置的 origin 源站，避免开 443 时冲掉回源
    backends = waf_backends(redirect_in) or item.get("origin") or []
    new_redirect["Backends"] = backends
    new_redirect.setdefault("Loadbalance", "iphash")
    waf_api(client, "ModifyDomain", {
        "InstanceId": iid, "Domain": domain, "AccessType": "share",
        "Listen": new_listen, "Redirect": new_redirect,
    }, region)
    return backends


def waf_wait_cert_visible(client, region, iid, cert_number, tries=6, interval=10):
    """等上传到 CAS 的证书同步进 WAF 可选证书库；可见返回 CertIdentifier，超时返回拼接兜底值。"""
    fallback = f"{cert_number}-{region}"
    for i in range(tries):
        try:
            resp = waf_api(client, "DescribeCerts", {"InstanceId": iid}, region)
            for c in resp.get("Certs") or []:
                if waf_cert_number(c.get("CertIdentifier")) == str(cert_number):
                    return c.get("CertIdentifier") or fallback
        except Exception as e:
            log(f"[WARN] 查询 WAF 可选证书失败: {e}")
        if i < tries - 1:
            time.sleep(interval)
    log(f"[WARN] 证书 {cert_number} 在 {tries * interval}s 内未同步到 WAF 证书库，"
        f"仍按 {fallback} 尝试绑定（若失败请稍后重跑）")
    return fallback


def deploy_waf_group(cert, account, acc_name, items, force, platform=None, waf_id=None, region=None):
    """WAF 3.0 部署：证书换名上传到 CAS（acme_waf_ 前缀，避开 DCDN 同名冲突），
    逐域名查 443/当前证书做幂等；确实未接入且配了源站（origin/waf_origin）则自动以 HTTP 接入。
    platform=部署平台（如 aliyun_cn），与 acc_name 配对决定用哪个账号；region=WAF 地域
    （由 waf_zone 解析），同账号 cn/intl 各查各的实例；waf_id=显式实例 ID（可选），留空自动发现。"""
    waf_region = region or waf_account_env(acc_name, "REGION", platform) or account.get("region") or "cn-hangzhou"
    client = make_client(account)
    iid = get_waf_instance_id(client, waf_region, acc_name, platform, configured_id=waf_id)
    if not iid:
        plat_up = (platform or "").upper()
        acc_up = (acc_name or "").upper()
        log(f"[ERROR] 平台 {platform or '-'} 账号 {acc_name} 缺少 WAF 实例 ID"
            f"（证书 waf_id / .env 配 {plat_up}_{acc_up}_WAF_INSTANCE_ID / {acc_up}_WAF_INSTANCE_ID "
            f"或全局 WAF_INSTANCE_ID），跳过该组 WAF 部署")
        return

    cert_name = cert["name"]
    main = cert_domains(cert)[0]
    cert_file, key_file = cert_paths(main)
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        log(f"[WARN] 证书文件缺失: {cert_file}，跳过 WAF 部署")
        return
    cert_pem = open(cert_file, "r", encoding="utf-8").read()
    key_pem = open(key_file, "r", encoding="utf-8").read()
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cert_name)
    waf_label = f"acme_waf_{safe}_{cert_not_before_date(cert_pem)}"

    # 0) 以接入域名为准逐个判定：已接入直接纳入；确实未接入且有源站则自动 CreateDomain；
    #    查询失败的域名本次跳过（避免误判未接入而重复接入）
    targets = []
    for item in items:
        domain = item["domain"]
        rec, ok = waf_find_domain(client, waf_region, iid, domain)
        if not ok:
            log(f"[WARN] WAF {domain} 接入状态查询失败，本次跳过（不自动接入，避免重复创建）")
            continue
        if rec is None:
            origin = item.get("origin")
            if not origin:
                log(f"[WARN] WAF {domain} 未接入且未配 origin 源站，无法自动接入，跳过"
                    f"（请在 waf_domains 写 origin 或证书级 waf_origin，或先在控制台接入）")
                continue
            try:
                waf_api(client, "CreateDomain", {
                    "InstanceId": iid, "Domain": domain, "AccessType": "share",
                    "Listen": {"HttpPorts": [80]},
                    "Redirect": {"Backends": origin, "Loadbalance": "iphash"},
                }, waf_region)
                log(f"[JOIN] WAF 接入域名 {domain}（HTTP 80，源站 {origin}）")
                time.sleep(3)  # 等接入生效再查详情
            except Exception as e:
                if "ResourceExsit" in str(e) or "ResourceExist" in str(e):
                    log(f"[INFO] WAF {domain} 已存在接入记录（ResourceExsit），按已接入继续")
                else:
                    log(f"[ERROR] WAF 接入域名 {domain} 失败: {e}")
                    continue
        targets.append(item)
    if not targets:
        return

    # 1) 上传到 CAS（换名避开 DCDN 冲突；同名先查重复用）
    cert_id = find_cert_id_by_name(client, waf_label)
    if not cert_id:
        req = CreateUserCertificateRequest()
        req.set_accept_format("json")
        req.set_Name(waf_label)
        req.set_Cert(cert_pem)
        req.set_Key(key_pem)
        try:
            cert_id = json.loads(client.do_action_with_exception(req)).get("CertId")
        except Exception as e:
            if "NameRepeat" in str(e):
                cert_id = find_cert_id_by_name(client, waf_label)
            if not cert_id:
                log(f"[ERROR] 上传 WAF 证书到阿里云失败: {e}")
                return
        log(f"已上传 WAF 证书 cert_id={cert_id}（账号 {acc_name}，名称 {waf_label}）")
    if not cert_id:
        log("[ERROR] 上传 WAF 证书未返回 CertId")
        return
    cert_number = str(cert_id)
    cert_identifier = waf_wait_cert_visible(client, waf_region, iid, cert_number)
    log(f"WAF 证书标识 CertIdentifier={cert_identifier}")

    # 2) 逐域名：按 443 状态分流做幂等
    for item in targets:
        domain = item["domain"]
        detail = waf_domain_detail(client, waf_region, iid, domain)
        if not detail or not detail.get("Listen"):
            log(f"[WARN] 查不到 {domain} 的 WAF 监听配置，跳过")
            continue
        listen = detail["Listen"] or {}
        https_ports = listen.get("HttpsPorts") or []
        cur_cert = listen.get("CertId") or (detail.get("CertDetail") or {}).get("Id")
        same_cert = waf_cert_number(cur_cert) == cert_number
        has_443 = 443 in https_ports or "443" in [str(p) for p in https_ports]

        if has_443 and same_cert and not force:
            log(f"[SKIP] WAF {domain} 443 已开且证书一致（CertId={cur_cert}），跳过")
            continue
        try:
            if has_443:
                try:
                    # 只换证书引用，不碰端口/转发（ModifyDomainCert 无 HttpsPorts 参数）
                    waf_api(client, "ModifyDomainCert", {
                        "InstanceId": iid, "Domain": domain, "CertId": cert_identifier,
                    }, waf_region)
                    log(f"[BIND] WAF {domain} 换证书 -> {waf_label}（原 CertId={cur_cert}）")
                except Exception as e:
                    if "NeedSsl" not in str(e):
                        raise
                    # DescribeDomainDetail 看到 443 但 WAF 判定未开 SSL 保护：回退到
                    # ModifyDomain 显式带完整 Listen(HttpsPorts=443, CertId) + Redirect 开 443 绑定
                    log(f"[WARN] WAF {domain} 换证书报 NeedSsl（WAF 侧未真正开启 SSL），"
                        f"改用 ModifyDomain 显式开 443 并绑定")
                    backends = waf_open_443_and_bind(client, waf_region, iid, domain, detail, item, cert_identifier)
                    log(f"[BIND] WAF {domain} 开启 443 并绑定 {waf_label}（源站 {backends}）")
            else:
                # 首次开 443：ModifyDomain 必须带完整 Listen + Redirect，否则会冲掉回源配置
                backends = waf_open_443_and_bind(client, waf_region, iid, domain, detail, item, cert_identifier)
                log(f"[BIND] WAF {domain} 开启 443 并绑定 {waf_label}（源站 {backends}）")
        except Exception as e:
            log(f"[ERROR] WAF {domain} 绑定证书失败: {e}")

    # 3) 清理本脚本上传的 WAF 旧证书（仅 acme_waf_<cert_name>_ 前缀）
    delete_old_certs(client, f"acme_waf_{safe}_", keep=cert_id)


# ----------------------------- 主流程 -----------------------------
def process(cfg, force=False):
    accounts = cfg.get("accounts") or {}
    cf = cfg.get("cloudflare") or {}
    certs = cfg.get("certificates") or []

    # 0) WAF 实例预检：签发前按各 WAF 部署 (平台, 账号, 地域) 独立发现实例。
    #    waf_zone(cn/intl) 决定 region；同账号的 cn/intl 是两个实例，必须分开查询/缓存。
    #    waf_id（域名项级 > 证书级）> 账号级 <NAME>_WAF_INSTANCE_ID > 全局 > 自动发现。
    #    某组若既没写 waf_id、环境也没配实例 ID，才需要预检发现；无/多实例只影响该组 WAF 部署。
    waf_pairs = {}  # (platform, account, region) -> 是否需要发现
    for c in certs:
        for dd in (c.get("waf_domains") or []):
            platform = dd.get("deploy") or c.get("deploy")
            acc_name = dd.get("deploy_account") or c.get("deploy_account")
            if not acc_name:
                continue
            acc = accounts.get(acc_name)
            region = waf_region(dd.get("waf_zone"), acc_name, platform, acc)
            wid = (dd.get("waf_id") or "").strip()
            resolved = bool(wid or waf_account_env(acc_name, "INSTANCE_ID", platform))
            k = (platform, acc_name, region)
            waf_pairs[k] = waf_pairs.get(k, False) or (not resolved)
    for (platform, acc_name, region), need_discover in sorted(
            waf_pairs.items(), key=lambda x: (x[0][0] or "", x[0][1] or "", x[0][2] or "")):
        if not need_discover:
            continue  # 该组全部已由 waf_id 或环境指定，无需查询
        acc = accounts.get(acc_name)
        if not (isinstance(acc, dict) and acc.get("access_key")):
            continue
        key = f"{platform}.{acc_name}.{region}".lower()
        if key in _WAF_ID_CACHE:
            continue
        log(f"[INFO] 平台 {platform or '-'} 账号 {acc_name} 地域 {region} 未配 WAF 实例 ID，签发前先查询实例…")
        try:
            get_waf_instance_id(make_client(acc), region, acc_name, platform)
        except Exception as e:
            log(f"[WARN] 平台 {platform or '-'} 账号 {acc_name} 地域 {region} 预检 WAF 实例失败: {e}")
    if waf_pairs:
        unresolved = [(p, a, r) for (p, a, r), need in sorted(
                          waf_pairs.items(), key=lambda x: (x[0][0] or "", x[0][1] or "", x[0][2] or ""))
                      if need and not _WAF_ID_CACHE.get(f"{p}.{a}.{r}".lower())]
        if unresolved:
            log(f"[WARN] 平台/账号/地域 {unresolved} 未确定 WAF 实例 ID，对应 WAF 部署将跳过；"
                "dcdn 证书签发/绑定不受影响（可用 --list-waf-instances 查看后填 waf_id 或 .env）")

    # 1) 签发所有证书（每张只签一次）
    for c in certs:
        issue_certificate(c, accounts, cf, force)

    # 2) 分组；每组只上传一次。DCDN 按 (证书, 平台, 账号)，WAF 额外带上地域（同账号 cn/intl 是两个实例）。
    dcdn_groups, waf_groups = {}, {}
    for c in certs:
        for kind, groups in (("dcdn", dcdn_groups), ("waf", waf_groups)):
            field = "dcdn_domains" if kind == "dcdn" else "waf_domains"
            for dd in c.get(field) or []:
                domain, acc_name = dd.get("domain"), dd.get("deploy_account")
                platform = dd.get("deploy")
                account = accounts.get(acc_name)
                if not (domain and account):
                    continue
                item_waf_id = (dd.get("waf_id") or "").strip() if isinstance(dd, dict) else ""
                if kind == "waf":
                    region = waf_region(dd.get("waf_zone"), acc_name, platform, account)
                    key = (c["name"], platform, acc_name, region)
                else:
                    region = None
                    key = (c["name"], platform, acc_name)
                g = groups.setdefault(key, {"cert": c, "account": account,
                                            "acc_name": acc_name, "platform": platform,
                                            "region": region, "waf_id": item_waf_id, "domains": []})
                if domain not in [x["domain"] if isinstance(x, dict) else x for x in g["domains"]]:
                    g["domains"].append(dd if kind == "waf" else domain)

    # 3) 每组上传一次 + 绑定组内所有域名 + 删旧
    for g in dcdn_groups.values():
        deploy_cert_group(g["cert"], g["account"], g["acc_name"], g["domains"], force)
    if waf_groups:
        log(f"[INFO] 检测到 {len(waf_groups)} 个 WAF 部署组，开始处理")
    for g in waf_groups.values():
        deploy_waf_group(g["cert"], g["account"], g["acc_name"], g["domains"], force,
                         platform=g.get("platform"), waf_id=g.get("waf_id"), region=g.get("region"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/certs.yaml")
    ap.add_argument("--force", action="store_true", help="强制重新签发并重新上传/绑定部署")
    ap.add_argument("--check", action="store_true", help="只校验并打印归一化后的配置，不签发/部署")
    ap.add_argument("--list-waf-instances", action="store_true",
                    help="列出各账号下的 WAF 实例详情（供填写 WAF_INSTANCE_ID），不签发/部署")
    ap.add_argument("--account", help="配合 --list-waf-instances，只查指定账号（如 cn1）")
    args = ap.parse_args()
    if not os.path.exists(args.config):
        log(f"[ERROR] 配置文件不存在: {args.config}")
        sys.exit(1)
    cfg = normalize_config(load_config(args.config))
    if args.list_waf_instances:
        accounts = cfg.get("accounts") or {}
        targets = {args.account: accounts[args.account]} if args.account and args.account in accounts else accounts
        if args.account and args.account not in accounts:
            log(f"[ERROR] 账号 {args.account} 不在 accounts 中（可用：{list(accounts)}）")
            sys.exit(1)
        for name, acc in targets.items():
            if not (isinstance(acc, dict) and acc.get("access_key") and acc.get("access_secret")):
                log(f"[WARN] 账号 {name} 缺 AK/SK，跳过")
                continue
            region = waf_account_env(name, "REGION") or acc.get("region") or "cn-hangzhou"
            cfg_iid = waf_account_env(name, "INSTANCE_ID")
            try:
                log(f"=== 账号 {name}（region={region}，当前配置实例={cfg_iid or '未配置'}）===")
                describe_and_list_waf_instances(make_client(acc), region)
            except Exception as e:
                log(f"[ERROR] 账号 {name} 查询 WAF 实例失败: {e}")
        log("提示：把选定的 InstanceId 写入 config/.env 的 <平台大写>_<账号大写>_WAF_INSTANCE_ID"
            "（如 ALIYUN_CN_CN1_WAF_INSTANCE_ID / ALIYUN_INTL_INTL1_WAF_INSTANCE_ID）；"
            "兼容旧写法 <账号名大写>_WAF_INSTANCE_ID（CN1_WAF_INSTANCE_ID / INTL1_WAF_INSTANCE_ID）；"
            "如需改地域写 <平台>_<账号>_WAF_REGION。所有账号共用一个实例时才用全局 WAF_INSTANCE_ID")
        return
    errors, warnings = validate_config(cfg)
    for w in warnings:
        log(f"[WARN] {w}")
    for e in errors:
        log(f"[ERROR] 配置校验失败: {e}")
    if errors:
        sys.exit(1)
    if args.check:
        for c in cfg["certificates"]:
            pairs = sorted({(d.get("deploy"), d["deploy_account"]) for d in c["dcdn_domains"]}
                           | {(d.get("deploy"), d["deploy_account"])
                              for d in (c.get("waf_domains") or [])},
                           key=lambda x: (x[0] or "", x[1] or ""))
            deploy_desc = ", ".join(f"{p or '-'}/{a}" for p, a in pairs) or "无"
            waf = c.get("waf_domains") or []
            waf_desc = ", ".join(
                d["domain"] + (f"(源站 {','.join(d['origin'])})" if d.get("origin") else "")
                for d in waf) or "无"
            waf_zone_desc = ", ".join(sorted({(d.get("waf_zone") or "-") for d in waf})) if waf else ""
            log(f"[OK] 证书 {c['name']}: 主域名={c['domains'][0]}, SAN={c['domains']}, "
                f"DCDN {len(c['dcdn_domains'])} 个, WAF {len(waf)} 个 [{waf_desc}], "
                f"部署平台/账号={deploy_desc}"
                + (f", WAF zone={waf_zone_desc}（实例自动发现）" if waf else ""))
        log(f"[OK] 配置校验通过：{len(cfg['certificates'])} 张证书")
        return
    check_acme()
    process(cfg, force=args.force)


if __name__ == "__main__":
    main()
