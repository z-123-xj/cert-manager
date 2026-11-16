# cert-manager

用 [acme.sh](https://github.com/acmesh-official/acme.sh) 自动签发 Let's Encrypt 证书，
并自动**上传到阿里云 SSL 证书服务 → 绑定 DCDN → 删除旧证书**。
支持**国内站 / 国际站**两套阿里云 DCDN 账号，按域名分配；DNS 验证可走阿里云 DNS 或 Cloudflare。

> 告警（证书到期前两周、签发/替换失败）后续接入 Prometheus，本期只做自动签发与替换。

## 架构

```
certmgr.py（编排，由系统 crontab 每日驱动）
  ├─ acme.sh --issue/--renew  (DNS-01 验证，调 DNS 提供方 API 加 _acme-challenge TXT)
  └─ 上传 + 绑定 + 删旧（阿里云 Python SDK: CAS 证书服务 + DCDN）
            │
            ▼
      阿里云（国内/国际账号）：SSL 证书控制台 + DCDN 域名
```

acme.sh 仅负责证书文件的签发/续期；证书的「上传到 CAS → 绑定 DCDN → 删旧」由本脚本完成。
脚本调用 acme.sh 时已带 `--no-cron`，不会自注册系统定时任务，续期与部署统一由本项目的 crontab 一条任务驱动。

## 目录

```
cert-manager/
├── certmgr.py              # 主程序
├── requirements.txt
└── config/
    └── certs.example.yaml  # 配置示例（复制为 certs.yaml 后填写）
```

## 前置条件

1. 服务器已安装 Python 3.9+ 与 acme.sh（acme.sh 默认装在 `~/.acme.sh`）。
2. 域名 DNS 需可被所选验证方式控制：
   - `dns: aliyun`：域名 DNS 托管在对应阿里云账号（acme.sh 用其 AK 自动加 `_acme-challenge` TXT 记录）；
   - `dns: cloudflare`：域名 DNS 在 Cloudflare，需提供 Cloudflare API Token（见配置 `cloudflare` 段）。
3. 提供阿里云 AK（国内站 / 国际站，按需），需具备权限：
   - **SSL 证书服务（CAS）**：上传/查询/删除证书
   - **DCDN**：`SetDcdnDomainSSLCertificate`（绑定证书到加速域名）
   - **DNS**：`dns_ali` 需要的 AliyunDNSFullAccess（或最小权限）

## 配置

复制示例并填写：

```bash
cp config/certs.example.yaml config/certs.yaml
```

配置里可用 `${ENV_VAR}` 注入 AK（见下方运行步骤），也可直接写明文。

配置以**证书为单位**：每张证书自带 `dcdn_domains`，不再有顶层 `dcdn_domains`，也不需要 `cert` 交叉引用（引用写错、多张证书自动匹配歧义的问题随之消失）。

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
```

- **`domains`（可选）**：真正签进证书的 SAN 列表（裸域 / 泛域 / 子域），每项拆成 `-d`。**省略时由 `dcdn_domains` 里的域名去重推导**（排序后首项为主域名，也就是 acme.sh 目录名），适合「只签具体域名」的简单场景；需要泛域 `*.example.org`、裸域、或只签不部署的域名时必须显式写。注意推导模式下每新增一个域名都会改变 SAN → 触发重签，且主域名可能变化，所以**域名较多或需要泛域时建议显式写 `domains`**。
- **`dcdn_domains`**：要绑定的加速域名。字符串简写用证书级 `deploy_account`；写成 `{domain, deploy_account}` 可覆盖账号，因此一张证书可同时部署到国内站和国际站。
- **`dns` / `dns_account`**：`aliyun` 用 `accounts` 里的 AK 去阿里云 DNS 加 TXT；`cloudflare` 用 `cloudflare` 段下命名子账号的 API Token。`dns_account` 省略时取对应账号段的第一个 key（`aliyun` → `accounts`，`cloudflare` → `cloudflare`）；`cloudflare` 单账号旧写法（凭证直接写在 `cloudflare:` 段下）也会自动归一化。

DNS 在 Cloudflare、DCDN 在阿里云互不影响的用法仍然支持。每个证书只签发一次，按「证书 + 部署账号」分组，每组只上传一次。

启动时会在**加载期校验**：账号引用存在、证书 SAN 覆盖 DCDN 域名、`name` 唯一、域名不跨证书重复；有错直接退出，不会静默跳过。用 `python3 certmgr.py --config config/certs.yaml --check` 可只校验并打印归一化后的证书与分组，不签发、不部署、也不要求装 acme.sh。

**旧配置迁移**：顶层 `dcdn_domains` 仍会被自动识别，按 `cert` 引用（无 `cert` 则按后缀匹配）回填到对应证书，新旧格式可混用一段时间。迁移时把顶层各项按 `cert` 分组移进对应证书的 `dcdn_domains`，删掉 `cert` 字段，同账号的项改成字符串简写，并在证书级写一次 `deploy_account`。完整对照见 `config/certs.example.yaml` 末尾。

**多账号**：阿里云可在 `accounts` 下加任意多个 key（如 `cn1` / `intl1` / `cn2` / `intl2`）；
Cloudflare 在 `cloudflare` 下用命名子账号（如 `cloudflare1` / `cloudflare2`），`dns_account` 指定具体哪一个。

## 运行（服务器原生，无 Docker）

```bash
# 1) 安装 Python 依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2) 准备配置
cp config/certs.example.yaml config/certs.yaml   # 填域名与账号

# 3) 配置 AK（二选一，推荐 A）
#    A. 直接在 config/certs.yaml 写明文 access_key / secret_key（推荐：最简单，配合 .gitignore
#       不提交该文件；cron 也能正常读到，无需任何环境变量）。选 A 则跳过下面的 export。
#    B. 用环境变量注入：certs.yaml 里写 "${CN1_AK}" 这类引用，运行时需提供对应变量。
#       ⚠️ 注意：~/.bashrc 里的 export 对 crontab 定时任务【无效】（cron 不加载 bashrc）！
#       若选 B，请改用下方第 6 步 crontab 行内联变量的方式，不要依赖 bashrc。
export LE_WORKING_DIR=$HOME/.acme.sh             # acme.sh 默认目录（本机需要，容器默认 /acme.sh）

# 4) 先校验配置（只打印归一化后的证书/分组，不签发、不部署）
python3 certmgr.py --config config/certs.yaml --check

# 5) 立即执行一次
python3 certmgr.py --config config/certs.yaml

# 6) 注册系统 crontab（每日续期+部署，单一驱动）
# 若服务器此前已有 acme.sh 自动注册的 --cron 任务，先删掉避免重复：
crontab -l | grep -v 'acme.sh --cron' | crontab -
crontab -e
# 加入（用 venv 里 python 绝对路径）：
# 方式 A（certs.yaml 明文）：无需任何 AK 变量
17 3 * * * cd /opt/cert-manager && /opt/cert-manager/venv/bin/python3 certmgr.py --config /opt/cert-manager/config/certs.yaml >> /opt/cert-manager/logs/certmgr.log 2>&1
# 方式 B（certs.yaml 用 ${...} 引用）：变量需内联在 cron 行里（bashrc 不生效）
# 17 3 * * * CN1_AK=xxx CN1_SK=xxx INTL1_AK=xxx INTL1_SK=xxx CF_TOKEN_1=xxx CF_ACCOUNT_ID_1=xxx LE_WORKING_DIR=/root/.acme.sh cd /opt/cert-manager && /opt/cert-manager/venv/bin/python3 certmgr.py --config /opt/cert-manager/config/certs.yaml >> /opt/cert-manager/logs/certmgr.log 2>&1
```

## 验证

- 阿里云控制台 → SSL 证书：应出现 `auto-<域名>-<时间戳>` 命名的证书；
- 阿里云控制台 → DCDN → 域名管理 → HTTPS 配置：应已绑定该证书；
- 旧证书应被自动清理（仅保留最新一份同名前缀证书）。

## 注意事项

- `~/.acme.sh` 是 acme.sh 证书与 Let's Encrypt 账号目录，**不要删除**，否则已签发证书与账号会丢失，频繁重签可能触发 LE 速率限制。
- `name` 决定 CAS 证书名前缀（`acme_<name>_`）。改 `name` 会让旧前缀证书不再被自动清理（脚本只清理当前前缀），已有证书如非必要不要改名。
- 泛域 `*.example.org` 只覆盖一级子域（如 `www.example.org`），**不含**裸域 `example.org`，也不含 `a.b.example.org`；这类域名必须显式列进 `domains`，否则加载期校验会报错。
- 国际站账号的 `region` / 如需指定 `endpoint` 在配置中填写（默认按 region 自动选 endpoint）。
- 阿里云 CAS / DCDN SDK 的接口参数若随版本变化，以阿里云官方文档为准微调 `certmgr.py` 中对应请求即可。

## 后续（告警）

- 暴露 Prometheus metrics：证书 `notAfter` 时间戳（gauge）+ 任务成败 counter；
- Alertmanager 规则：到期 `< 14天` 或 `deploy` 失败 → 钉钉/飞书告警。
