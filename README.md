# cert-manager

用 [acme.sh](https://github.com/acmesh-official/acme.sh) 自动签发 Let's Encrypt 证书，
并自动**上传到阿里云 SSL 证书服务 → 绑定 DCDN 和/或 WAF 3.0 → 删除旧证书**。
支持**国内站 / 国际站**两套阿里云账号，按域名分配；DNS 验证可走阿里云 DNS 或 Cloudflare。
DCDN 与 WAF 可单独或同时启用：DCDN 用「传内容绑定」，WAF 用「引用 CertId 切换」。

> 告警（证书到期前两周、签发/替换失败）后续接入 Prometheus，本期只做自动签发与替换。

## 架构

```
certmgr.py（编排，由系统 crontab 每日驱动）
  ├─ 读 config/.env（账号 AK/SK、WAF_INSTANCE_ID）+ config/certs.yaml
  ├─ acme.sh --issue/--renew  (DNS-01 验证，调 DNS 提供方 API 加 _acme-challenge TXT)
  └─ 上传 + 绑定 + 删旧（阿里云 SDK：CAS + DCDN；WAF 3.0 用 OpenAPI）
            │
            ▼
      阿里云（国内/国际账号）：SSL 证书控制台 + DCDN 域名 + WAF 防护域名
```

acme.sh 仅负责证书文件的签发/续期；证书的「上传到 CAS → 绑定 DCDN/WAF → 删旧」由本脚本完成。
脚本调用 acme.sh 时已带 `--no-cron`，不会自注册系统定时任务，续期与部署统一由本项目的 crontab 一条任务驱动。

## 目录

```
cert-manager/
├── certmgr.py              # 主程序
├── requirements.txt
└── config/
    ├── certs.example.yaml  # 配置示例（复制为 certs.yaml 后填写）
    └── .env.example        # 账号凭证示例（复制为 .env 后填写，AK/SK/WAF_INSTANCE_ID）
```

## 前置条件

1. 服务器已安装 Python 3.9+ 与 acme.sh（acme.sh 默认装在 `~/.acme.sh`）。
2. 域名 DNS 需可被所选验证方式控制：
   - `dns: aliyun`：域名 DNS 托管在对应阿里云账号（acme.sh 用其 AK 自动加 `_acme-challenge` TXT 记录）；
   - `dns: cloudflare`：域名 DNS 在 Cloudflare，需提供 Cloudflare API Token（见配置 `cloudflare` 段）。
3. 提供阿里云 AK（国内站 / 国际站，按需），需具备权限：
   - **SSL 证书服务（CAS）**：上传/查询/删除证书
   - **DCDN**：`SetDcdnDomainSSLCertificate`（绑定证书到加速域名）
   - **WAF 3.0（如启用）**：`DescribeInstance`、`DescribeDomains`、`DescribeDomainDetail`、
     `DescribeCerts`、`CreateDomain`（未接入时）、`ModifyDomain`（开 443）、`ModifyDomainCert`（换证书）
   - **DNS**：`dns_ali` 需要的 AliyunDNSFullAccess（或最小权限）

## 配置

复制示例并填写：

```bash
cp config/certs.example.yaml config/certs.yaml
```

账号 AK/SK 和 WAF 实例 ID 放在 **`config/.env`**（复制 `.env.example`），不再写进 `certs.yaml`：

```bash
cp config/.env.example config/.env   # 填 AK/SK、WAF_INSTANCE_ID 等
```

`.env` 约定：`<账号名>_AK` / `<账号名>_SK` → 账号 `cn1`（`CN1_AK`/`CN1_SK`）；也可加 `ALIYUN_` 标记写成 `ALIYUN_CN1_AK`/`ALIYUN_CN1_SK`，同样映射成账号 `cn1`（SK/REGION 需用同样前缀），证书配置里仍写 `deploy_account: cn1`。账号的 `REGION` 也统一写在 `.env`（`CN1_REGION` / `INTL1_REGION`），**`certs.yaml` 里不再写 `accounts`**（含 region），`_ENDPOINT` 可选。WAF 实例按账号分开配：`<账号名大写>_WAF_INSTANCE_ID`（如 `CN1_WAF_INSTANCE_ID` / `INTL1_WAF_INSTANCE_ID`）+ 可选 `<账号名大写>_WAF_REGION`；全局 `WAF_INSTANCE_ID` / `WAF_REGION` 作为所有账号共用一个实例时的兜底（优先级低于账号级）。留空时脚本对每个 WAF 账号分别调 `DescribeInstance`：仅 1 个正常实例自动选用，多个则要求显式写该账号的变量（用 `--list-waf-instances` 查看各账号实例）。国内站/国际站各自查各自的账号与地域，互不混用。`.env` 是扁平 KEY=VALUE，按 `cn*` / `intl*` 前缀区分国内站/国际站（见 `.env.example` 的注释分块）。服务器 crontab 内联的同名环境变量优先级高于 `.env`。旧版写在 `certs.yaml` 的 `accounts` 仍会被读取（迁移期兼容），但 `.env` 同名字段优先。

配置以**证书为单位**：每张证书自带 `dcdn_domains`（DCDN）和/或 `waf_domains`（WAF），不需要顶层 `dcdn_domains`，也不需要 `cert` 交叉引用。

```yaml
certificates:
  - name: "example.org"            # 可选：证书标识 = CAS 证书名前缀；省略时取主域名
    dns: cloudflare                # 可选，默认 aliyun（aliyun / cloudflare）
    dns_account: cloudflare1       # DNS-01 验证账号
    deploy_account: intl1          # 可选：证书级默认部署账号
    # domains: ["example.org", "*.example.org"]   # 可选：需要泛域/裸域/额外 SAN 时写
    dcdn_domains:
      - "www.example.org"          # 字符串简写：用证书级 deploy_account
      - "api.example.org"
      - domain: "cn.example.org"   # 需要换账号时才展开成对象
        deploy_account: cn1
    waf_origin: ["1.2.3.4"]         # 可选：证书级源站，供所有 waf_domains 共用
    waf_domains:                    # 可选：WAF 3.0 防护域名（字符串列表即可）
      - "waf.example.org"          # 已接入 WAF：仅替换证书
      - "new.example.org"          # 未接入：用 waf_origin 自动接入（HTTP 80 起步）
    # 仅当某域名源站/账号与证书级不同时，才展开成 {domain, origin, deploy_account} 对象
```

- **`domains`（可选）**：真正签进证书的 SAN 列表（裸域 / 泛域 / 子域），每项拆成 `-d`。**省略时由 `dcdn_domains` + `waf_domains` 的域名去重推导**（排序后首项为主域名，也就是 acme.sh 目录名）。需要泛域 `*.example.org`、裸域、或只签不部署的域名时必须显式写。推导模式下每新增一个域名都会改变 SAN → 触发重签，所以**域名较多或需要泛域时建议显式写 `domains`**。
- **`dcdn_domains`**：要绑定的 DCDN 加速域名。字符串简写用证书级 `deploy_account`；写成 `{domain, deploy_account}` 可覆盖账号，因此一张证书可同时部署到国内站和国际站。
- **`waf_domains`**：要绑定的 WAF 3.0 防护域名，写法同 `dcdn_domains`，额外支持 `origin`（源站 IP/域名，字符串或列表；旧名 `backends` 仍兼容）。**WAF 与 DCDN 用不同的 CAS 证书名前缀**（`acme_waf_` vs `acme_`），避免先部署 WAF 占用名字导致 DCDN 报 `CertNameAlreadyExists`。
- **`waf_origin`（可选）**：证书级默认源站，域名没写 `origin` 时统一用它，省得每个 WAF 域名重复写。
  脚本以**接入域名为准**逐个判定（DescribeDomains 按域名过滤）：
  - 已接入且 443 已开、证书一致 → 跳过；证书不同 → `ModifyDomainCert` 只切证书引用；
  - 已接入但 443 未开 → `ModifyDomain` 开 443 并绑证书（带回现有回源配置，不会冲掉）；
  - 确实未接入且有源站（`origin`/`waf_origin`）→ 自动 `CreateDomain` 接入（HTTP 80 起步）再开 443；无源站则跳过并告警；
  - 接入状态查询失败 → 本次跳过（不自动接入，避免误判重复创建）。
- **`dns` / `dns_account`**：`aliyun` 用 `.env` 账号的 AK 去阿里云 DNS 加 TXT；`cloudflare` 用 `cloudflare` 段下命名子账号的 API Token。`dns_account` 省略时取对应段的第一个 key；`cloudflare` 单账号旧写法也会自动归一化。

DNS 在 Cloudflare、DCDN/WAF 在阿里云互不影响的用法仍然支持。每个证书只签发一次，按「证书 + 部署账号」分组，每组只上传一次。

启动时会在**加载期校验**：账号引用存在、证书 SAN 覆盖 DCDN/WAF 域名、`name` 唯一、域名不跨证书重复；有错直接退出。用 `python3 certmgr.py --config config/certs.yaml --check` 可只校验并打印归一化后的证书与分组，不签发、不部署、也不要求装 acme.sh。

**旧配置迁移**：顶层 `dcdn_domains` 仍会被自动识别并回填；`accounts` 段若仍写在 yaml 也能用（同名被 .env 覆盖）。建议逐步把 `accounts` 搬进 `.env`、把顶层 `dcdn_domains` 移进各证书。

**多账号**：阿里云在 `.env` 里加任意多组 `<名>_AK/_SK`（如 `cn1` / `intl1` / `cn2`）；
Cloudflare 在 `cloudflare` 下用命名子账号（如 `cloudflare1` / `cloudflare2`），`dns_account` 指定具体哪一个。

## 运行（服务器原生，无 Docker）

```bash
# 1) 安装 Python 依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2) 准备配置
cp config/certs.example.yaml config/certs.yaml   # 填域名
cp config/.env.example config/.env               # 填 AK/SK、WAF_INSTANCE_ID（.env 已被 gitignore）
chmod 600 config/.env

# 3) acme.sh 目录（本机默认 ~/.acme.sh，容器默认 /acme.sh）
export LE_WORKING_DIR=$HOME/.acme.sh

# 4) 先校验配置（只打印归一化后的证书/分组，不签发、不部署）
python3 certmgr.py --config config/certs.yaml --check

# 4b) 如启用了 waf_domains 但不知道 WAF_INSTANCE_ID 填哪个：列出各账号的 WAF 实例详情
python3 certmgr.py --config config/certs.yaml --list-waf-instances
python3 certmgr.py --config config/certs.yaml --list-waf-instances --account cn1   # 只看某账号
# 把输出的 InstanceId 填进 .env 对应账号的 CN1_WAF_INSTANCE_ID / INTL1_WAF_INSTANCE_ID；
# 每个账号输出会同时显示 region 和当前配置的实例，按账号分别填；留空且单实例时自动选用

# 5) 立即执行一次
python3 certmgr.py --config config/certs.yaml

# 6) 注册系统 crontab（每日续期+部署，单一驱动）
# 若服务器此前已有 acme.sh 自动注册的 --cron 任务，先删掉避免重复：
crontab -l | grep -v 'acme.sh --cron' | crontab -
crontab -e
# 加入（用 venv 里 python 绝对路径）。脚本会自行加载 config/.env，cron 行无需 AK 变量：
17 3 * * * cd /opt/cert-manager && /opt/cert-manager/venv/bin/python3 certmgr.py --config /opt/cert-manager/config/certs.yaml >> /opt/cert-manager/logs/certmgr.log 2>&1
# 如不想把 AK 落在 .env，也可在 cron 行内联 CN1_AK/CN1_SK/WAF_INSTANCE_ID 等（优先级高于 .env）：
# 17 3 * * * CN1_AK=xxx CN1_SK=xxx WAF_INSTANCE_ID=waf_xxx LE_WORKING_DIR=/root/.acme.sh cd /opt/cert-manager && /opt/cert-manager/venv/bin/python3 certmgr.py --config /opt/cert-manager/config/certs.yaml >> /opt/cert-manager/logs/certmgr.log 2>&1
```

WAF 首次接入注意：`CreateDomain` 要求域名已完成**域名归属权验证**与（国内站）**ICP 备案**，
脚本不代办这两步，请先在控制台完成；否则接入会失败并在日志给出错误码。

## 验证

- 阿里云控制台 → SSL 证书：应出现 `acme_<name>_<日期>`（DCDN）与 `acme_waf_<name>_<日期>`（WAF）命名的证书；
- 阿里云控制台 → DCDN → 域名管理 → HTTPS 配置：应已绑定对应证书；
- 阿里云控制台 → WAF 3.0 → 防护域名：HTTPS（443）已开启、证书为 `acme_waf_` 前缀那份；
- 旧证书应被自动清理（仅保留最新一份同名前缀证书）。

## 注意事项

- `~/.acme.sh` 是 acme.sh 证书与 Let's Encrypt 账号目录，**不要删除**，否则已签发证书与账号会丢失，频繁重签可能触发 LE 速率限制。
- `name` 决定 CAS 证书名前缀（`acme_<name>_`）。改 `name` 会让旧前缀证书不再被自动清理（脚本只清理当前前缀），已有证书如非必要不要改名。
- 泛域 `*.example.org` 只覆盖一级子域（如 `www.example.org`），**不含**裸域 `example.org`，也不含 `a.b.example.org`；这类域名必须显式列进 `domains`，否则加载期校验会报错。
- 国际站账号的 `region` 写在 `config/.env` 的 `INTL1_REGION=ap-southeast-1`（不写会按默认 `cn-hangzhou`，导致国际站 API 调错）；如需指定 `endpoint` 写 `INTL1_ENDPOINT`。
- 阿里云 CAS / DCDN SDK 的接口参数若随版本变化，以阿里云官方文档为准微调 `certmgr.py` 中对应请求即可。

## 后续（告警）

- 暴露 Prometheus metrics：证书 `notAfter` 时间戳（gauge）+ 任务成败 counter；
- Alertmanager 规则：到期 `< 14天` 或 `deploy` 失败 → 钉钉/飞书告警。
