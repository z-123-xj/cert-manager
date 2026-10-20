#!/usr/bin/env python3
"""cert-manager

用 acme.sh 签发 Let's Encrypt 证书（DNS-01 自动验证，支持阿里云 DNS / Cloudflare），
签发成功后：
  1. 上传到阿里云 SSL 证书服务（CAS）
  2. 绑定到对应 DCDN 加速域名
  3. 清理该域名在阿里云上的旧证书（保留刚上传的）

支持国内站 / 国际站两套阿里云账号部署；DNS 验证可分别走阿里云 DNS 或 Cloudflare（按域名配置）。
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

from aliyunsdkcore.client import AcsClient
from aliyunsdkcas.request.v20180713 import (
    CreateUserCertificateRequest,
    DeleteUserCertificateRequest,
    DescribeUserCertificateListRequest,
)
from aliyunsdkdcdn.request.v20180510 import SetDcdnDomainSSLCertificateRequest

LE_DIR = os.environ.get("LE_WORKING_DIR", "/acme.sh")


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ----------------------------- 配置加载 -----------------------------
def expand_env(obj):
    """递归把配置里的 ${VAR} / $VAR 用环境变量替换（支持 docker-compose 注入 AK）。"""
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


# ----------------------------- 证书路径 -----------------------------
def cert_paths(domain):
    base = os.path.join(LE_DIR, domain)
    return os.path.join(base, "fullchain.cer"), os.path.join(base, domain + ".key")


# ----------------------------- acme.sh 签发 -----------------------------
def run_acme(domain, dns_arg, env, renew):
    """调用 acme.sh 签发 / 续期。
    dns_arg: 验证方式，如 dns_ali / dns_cf
    env:     对应 DNS 提供方的凭证环境变量（如 ALI_KEY/ALI_SECRET 或 CF_Token）
    """
    env = dict(os.environ, **env)
    if renew:
        cmd = ["acme.sh", "--renew", "--no-cron", "-d", domain]
    else:
        cmd = ["acme.sh", "--issue", "--dns", dns_arg, "--no-cron", "-d", domain]
    log(f"acme.sh {'renew' if renew else 'issue'} {domain}")
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    log(out[-2000:])  # 只打印末尾，避免刷屏
    return r.returncode == 0, out


# ----------------------------- 阿里云客户端 -----------------------------
def make_client(account):
    region = account.get("region", "cn-hangzhou")
    endpoint = account.get("endpoint")
    if endpoint:
        return AcsClient(account["access_key"], account["access_secret"], region, endpoint)
    return AcsClient(account["access_key"], account["access_secret"], region)


# ----------------------------- 上传 + 绑定 + 删旧 -----------------------------
def upload_and_bind(domain, cdn_domain, account):
    cert_file, key_file = cert_paths(domain)
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        log(f"[WARN] 证书文件缺失: {cert_file}，跳过部署")
        return False

    cert_pem = open(cert_file, "r", encoding="utf-8").read()
    key_pem = open(key_file, "r", encoding="utf-8").read()
    client = make_client(account)
    ts = int(time.time())

    # 1) 上传到阿里云 SSL 证书服务
    req = CreateUserCertificateRequest.CreateUserCertificateRequest()
    req.set_accept_format("json")
    req.set_Name(f"auto-{domain}-{ts}")
    req.set_Cert(cert_pem)
    req.set_Key(key_pem)
    try:
        resp = json.loads(client.do_action_with_exception(req))
    except Exception as e:
        log(f"[ERROR] 上传证书到阿里云失败: {e}")
        return False
    cert_id = resp.get("CertId")
    if not cert_id:
        log(f"[ERROR] 上传证书未返回 CertId: {resp}")
        return False
    log(f"已上传证书 cert_id={cert_id}")

    # 2) 绑定到 CDN 加速域名
    req2 = SetDcdnDomainSSLCertificateRequest()
    req2.set_accept_format("json")
    req2.set_DomainName(cdn_domain)
    req2.set_CertName(f"auto-{domain}-{ts}")
    req2.set_CertId(str(cert_id))
    req2.set_SSLProtocol("on")
    try:
        client.do_action_with_exception(req2)
    except Exception as e:
        log(f"[ERROR] 绑定 CDN {cdn_domain} 失败: {e}")
        return False
    log(f"已绑定 CDN {cdn_domain} -> cert_id={cert_id}")

    # 3) 清理同域名旧证书（保留刚上传的）
    delete_old_certs(client, domain, keep=cert_id)
    return True


def delete_old_certs(client, domain, keep):
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
    prefix = f"auto-{domain}"
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


# ----------------------------- 主流程 -----------------------------
def process(cfg, force=False):
    accounts = cfg.get("accounts", {})
    cf = cfg.get("cloudflare", {})
    domains = cfg.get("domains", [])
    for d in domains:
        name = d["name"]
        dns = d.get("dns", "aliyun")

        # 1) 解析 DNS 验证方式与对应凭证（与 CDN 部署账号相互独立）
        if dns == "aliyun":
            dns_acc_name = d.get("dns_account") or d.get("deploy_account") or d.get("account", "cn")
            dns_acc = accounts.get(dns_acc_name)
            if not dns_acc:
                log(f"[ERROR] 域名 {name} dns=aliyun 但 DNS 账号 {dns_acc_name} 不存在，跳过")
                continue
            acme_env = {
                "ALI_KEY": dns_acc["access_key"],
                "ALI_SECRET": dns_acc["access_secret"],
            }
            dns_arg = "dns_ali"
        elif dns == "cloudflare":
            # cloudflare 支持多账号（命名子字典）；也兼容旧的「单账号直接写在 cloudflare 下」写法
            cf_name = d.get("dns_account")
            cf_cfg = None
            if isinstance(cf, dict):
                if cf_name and cf_name in cf and isinstance(cf[cf_name], dict):
                    cf_cfg = cf[cf_name]
                elif not cf_name and "api_token" in cf:
                    cf_cfg = cf
            if not isinstance(cf_cfg, dict) or not cf_cfg.get("api_token"):
                log(f"[ERROR] 域名 {name} dns=cloudflare 凭证缺失（dns_account={cf_name}），跳过")
                continue
            acme_env = {"CF_Token": cf_cfg["api_token"]}
            if cf_cfg.get("account_id"):
                acme_env["CF_Account_ID"] = cf_cfg["account_id"]
            if cf_cfg.get("email"):
                acme_env["CF_Email"] = cf_cfg["email"]
            dns_arg = "dns_cf"
        else:
            log(f"[ERROR] 域名 {name} 不支持的 dns={dns}，跳过")
            continue

        # 2) 解析部署账号（证书上传 + 绑定 CDN）
        deploy_acc_name = d.get("deploy_account") or d.get("account", "cn")
        deploy_account = accounts.get(deploy_acc_name)
        if not deploy_account:
            log(f"[ERROR] 域名 {name} 指定的部署账号 {deploy_acc_name} 不存在，跳过")
            continue
        cdn_domain = d.get("cdn_domain", name)

        # 3) 签发 / 续期 + 部署
        cert_file, _ = cert_paths(name)
        exists = os.path.exists(cert_file)
        # 首次 issue；之后 renew（acme.sh 自己判断是否需要真正续期，未到期会跳过）
        run_acme(name, dns_arg, acme_env, renew=exists and not force)
        # 部署幂等：每次都重新上传 + 绑定 + 删旧，保证 CDN 持有最新可用证书
        upload_and_bind(name, cdn_domain, deploy_account)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/app/config/certs.yaml")
    ap.add_argument("--force", action="store_true", help="强制重新签发并部署（跳过 acme.sh 续期判断）")
    args = ap.parse_args()
    if not os.path.exists(args.config):
        log(f"[ERROR] 配置文件不存在: {args.config}")
        sys.exit(1)
    cfg = load_config(args.config)
    process(cfg, force=args.force)


if __name__ == "__main__":
    main()
