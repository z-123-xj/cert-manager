#!/usr/bin/env python3
"""cert-manager

用 acme.sh 签发 Let's Encrypt 证书（DNS-01 自动验证，支持阿里云 DNS / Cloudflare），
签发成功后：
  1. 上传到阿里云 SSL 证书服务（CAS）
  2. 绑定到对应 DCDN 加速域名
  3. 清理该证书在阿里云上的旧版本（保留刚上传的）

配置以「证书」为单位，每张证书自带 dcdn_domains（要绑定的加速域名），无需 cert 交叉引用：
  - name:           可选标识（CAS 证书名前缀）；省略时取主域名
  - dns/dns_account: DNS-01 验证提供方与账号
  - domains:        可选 SAN 列表；省略时由 dcdn_domains 里的域名去重推导（纯具体域名证书）
  - deploy_account: 证书级默认部署账号，单个 dcdn 域名可用同名键覆盖
  - dcdn_domains:   字符串简写或 {domain, deploy_account}
顶层 dcdn_domains（旧格式）会被归一化回填到对应证书，便于平滑迁移。
每个证书只签发一次，可被多个 DCDN 域名共用（按「证书 + 部署账号」分组，每组只上传一次）。

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


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return expand_env(yaml.safe_load(f))


# ----------------------------- 配置归一化 -----------------------------
def dcdn_items(items, default_account):
    """把 dcdn_domains 统一成 [{domain, deploy_account}]；支持字符串简写。"""
    out = []
    for item in items or []:
        if isinstance(item, str):
            out.append({"domain": item.strip(), "deploy_account": default_account})
        elif isinstance(item, dict):
            out.append({
                "domain": str(item.get("domain") or "").strip(),
                "deploy_account": item.get("deploy_account") or item.get("account") or default_account,
            })
        else:
            out.append({"domain": "", "deploy_account": default_account})
    return out


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
    certs = cfg.get("certificates") or []
    norm = []
    for raw in certs if isinstance(certs, list) else []:
        if not isinstance(raw, dict):
            continue
        c = dict(raw)
        c.setdefault("dns", "aliyun")
        if not c.get("dns_account"):
            # cloudflare 从 cloudflare 段取第一个账号；aliyun 从 accounts 取（避免串用）
            c["dns_account"] = (next(iter(cf), None) if c["dns"] == "cloudflare"
                                else (c.get("account") or first_acc))
        default_deploy = c.get("deploy_account") or c.get("account") or first_acc
        c["dcdn_domains"] = dcdn_items(c.get("dcdn_domains"), default_deploy)
        norm.append(c)

    # 先补齐 name / domains，供旧格式的自动匹配使用。省略 domains 时由 dcdn 域名
    # 去重 + 排序推导，保证主域名（即 acme.sh 目录名）在增删域名后尽量稳定。
    for c in norm:
        if not c.get("domains"):
            c["domains"] = sorted({i["domain"] for i in c["dcdn_domains"] if i.get("domain")}) \
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
            norm.append({"name": cert_name or "<未匹配>", "dns": "aliyun", "domains": [],
                         "dcdn_domains": [], "_unmatched": domain})
            continue
        cert["dcdn_domains"].append({
            "domain": domain,
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
        if dns not in ("aliyun", "cloudflare"):
            errors.append(f"{tag}: 不支持的 dns={dns}（仅 aliyun / cloudflare）")
        if dns == "aliyun":
            acc = accounts.get(acc_name) if acc_name else None
            if not isinstance(acc, dict):
                errors.append(f"{tag}: dns_account={acc_name} 不在 accounts 中")
            elif not (acc.get("access_key") and acc.get("access_secret")):
                errors.append(f"{tag}: DNS 账号 {acc_name} 缺少 access_key/access_secret")
        elif dns == "cloudflare":
            cf_cfg = cf.get(acc_name) if acc_name and isinstance(cf, dict) else None
            if not (isinstance(cf_cfg, dict) and cf_cfg.get("api_token")):
                errors.append(f"{tag}: dns_account={acc_name} 在 cloudflare 中不存在或缺少 api_token")
        domains = c.get("domains") or []
        if not domains:
            errors.append(f"{tag}: domains 为空（显式写 domains，或至少配一个 dcdn_domains 域名）")
        for d in domains:
            if (not isinstance(d, str) or not d or any(ch in d for ch in " /")
                    or d.startswith(".") or "." not in d):
                errors.append(f"{tag}: 非法域名 {d!r}")
        for dd in c["dcdn_domains"]:
            domain, deploy_acc = dd.get("domain"), dd.get("deploy_account")
            if not domain:
                errors.append(f"{tag}: dcdn_domains 存在空域名或非法项")
                continue
            if not deploy_acc or deploy_acc not in accounts:
                errors.append(f"{tag}: {domain} 的 deploy_account={deploy_acc} 不在 accounts 中")
            if domains and not cert_covers(c, domain):
                errors.append(f"{tag}: DCDN 域名 {domain} 不被证书 SAN 覆盖（domains={domains}）")
            if domain in seen_domains and seen_domains[domain] != name:
                errors.append(f"域名 {domain} 同时声明在证书 {seen_domains[domain]} 和 {name}，会重复绑定")
            seen_domains[domain] = name
        if c.get("_derived_domains") and len(domains) > 1:
            warnings.append(f"{tag}: domains 由 dcdn_domains 推导为 {domains}；"
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
    names = [c.get("name") or c.get("Name") or c.get("certName") for c in certs]
    log(f"[DEBUG] 列表未匹配 name={name}；共 {len(certs)} 张；名称列表(前20)={names[:20]}")
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
    dns = cert.get("dns", "aliyun")
    if dns == "aliyun":
        acc_name = cert.get("dns_account")
        acc = accounts.get(acc_name)
        if not acc:
            log(f"[ERROR] 证书 {name} dns=aliyun 但 DNS 账号 {acc_name} 不存在，跳过")
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
    elif dns == "cloudflare":
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
    cert_label = f"acme_{safe}_{cert_not_before_date(cert_pem)}"
    local_pem = _leaf_pem(cert_pem)
    # 0) 逐域名检查云端已绑定的证书是否就是这份（acme_ 前缀 + 内容一致 + HTTPS 已开）
    to_bind = []
    for domain in domains:
        bound = get_dcdn_cert(client, domain)
        # 必须精确匹配正规证书名（cert_label）才算已正确绑定；若当前绑定的是带时间戳的
        # alt 名（acme_xxx_2026-10-21_1697...），视为未对齐，需重新绑定到正规名。
        if (not force and bound
                and bound.get("CertName", "") == cert_label
                and str(bound.get("SSLProtocol")) == "on"
                and _leaf_pem(bound.get("SSLPub") or "") == local_pem):
            log(f"[SKIP] {domain} 已绑定该证书（CertName={bound.get('CertName')}），跳过")
            continue
        to_bind.append(domain)
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

    for domain in to_bind:
        try:
            _bind(domain, cert_label)
            log(f"已绑定 DCDN {domain} -> 证书名 {cert_label}")
        except Exception as e:
            if "CertNameAlreadyExists" in str(e):
                # DCDN 库已存在同名证书，接口不允许覆盖/切换引用，只能控制台手动改绑
                log(f"[SKIP] DCDN 已存在同名证书 {cert_label}，跳过 {domain}"
                    f"（若 {domain} 未生效，请在 DCDN 控制台把该域名改绑到 {cert_label} 后重跑）")
            else:
                log(f"[ERROR] 绑定 DCDN {domain} 失败: {e}")
    # 3) 清理本脚本上传的旧版本（仅 acme_<cert_name>_ 前缀，保留当前这份）
    delete_old_certs(client, f"acme_{safe}_", keep=cert_id)


# ----------------------------- 主流程 -----------------------------
def process(cfg, force=False):
    accounts = cfg.get("accounts") or {}
    cf = cfg.get("cloudflare") or {}
    certs = cfg.get("certificates") or []

    # 1) 签发所有证书（每张只签一次）
    for c in certs:
        issue_certificate(c, accounts, cf, force)

    # 2) 证书自带 dcdn_domains，按 (证书, 部署账号) 分组；每组只上传一次
    groups = {}
    for c in certs:
        for dd in c.get("dcdn_domains") or []:
            domain, acc_name = dd.get("domain"), dd.get("deploy_account")
            account = accounts.get(acc_name)
            if not (domain and account):
                continue
            key = (c["name"], acc_name)
            g = groups.setdefault(key, {"cert": c, "account": account,
                                        "acc_name": acc_name, "domains": []})
            if domain not in g["domains"]:
                g["domains"].append(domain)

    # 3) 每组上传一次 + 绑定组内所有域名 + 删旧
    for g in groups.values():
        deploy_cert_group(g["cert"], g["account"], g["acc_name"], g["domains"], force)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/certs.yaml")
    ap.add_argument("--force", action="store_true", help="强制重新签发并重新上传/绑定部署")
    ap.add_argument("--check", action="store_true", help="只校验并打印归一化后的配置，不签发/部署")
    args = ap.parse_args()
    if not os.path.exists(args.config):
        log(f"[ERROR] 配置文件不存在: {args.config}")
        sys.exit(1)
    cfg = normalize_config(load_config(args.config))
    errors, warnings = validate_config(cfg)
    for w in warnings:
        log(f"[WARN] {w}")
    for e in errors:
        log(f"[ERROR] 配置校验失败: {e}")
    if errors:
        sys.exit(1)
    if args.check:
        for c in cfg["certificates"]:
            accs = sorted({d["deploy_account"] for d in c["dcdn_domains"]})
            log(f"[OK] 证书 {c['name']}: 主域名={c['domains'][0]}, SAN={c['domains']}, "
                f"DCDN {len(c['dcdn_domains'])} 个, 部署账号={accs}")
        log(f"[OK] 配置校验通过：{len(cfg['certificates'])} 张证书")
        return
    check_acme()
    process(cfg, force=args.force)


if __name__ == "__main__":
    main()
