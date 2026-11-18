# cert-manager

用 [acme.sh](https://github.com/acmesh-official/acme.sh) 自动签发 Let's Encrypt 证书，
并自动**上传到阿里云 SSL 证书服务 → 绑定 DCDN 和/或 WAF 3.0 → 删除旧证书**。
支持**国内站 / 国际站**两套阿里云账号，按域名分配；DNS 验证可走阿里云 DNS 或 Cloudflare。
DCDN 与 WAF 可单独或同时启用：DCDN 用「传内容绑定」，WAF 用「引用 CertId 切换」。

> 告警（证书到期前两周、签发/替换失败）后续接入 Prometheus，本期只做自动签发与替换。

## 架构

```
certmgr.py（编排，由系统 crontab 每日驱动）
  ├─ 读 config/.env（AK/SK、CF Token、WAF 实例 ID 的值）+ config/certs.yaml（层级结构）
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
    └── .env.example        # 凭证变量值示例（复制为 .env 后填写）
```

## 前置条件

1. 服务器已安装 Python 3.9+ 与 acme.sh（acme.sh 默认装在 `~/.acme.sh`）。
2. 域名 DNS 需可被所选验证方式控制：
   - `dns: aliyun_cn` / `dns: aliyun_intl`：域名 DNS 托管在对应阿里云站点的账号（acme.sh 用其 AK 自动加 `_acme-challenge` TXT 记录）；
   - `dns: cloudflare`：域名 DNS 在 Cloudflare，需提供 Cloudflare API Token（在配置 `cloudflare` 段，见下）。
3. 提供阿里云 AK（国内站 / 国际站，按需），需具备权限：
   - **SSL 证书服务（CAS）**：上传/查询/删除证书
   - **DCDN**：`SetDcdnDomainSSLCertificate`（绑定证书到加速域名）
   - **WAF 3.0（如启用）**：`DescribeInstance`、`DescribeDomains`、`DescribeDomainDetail`、
     `DescribeCerts`、`CreateDomain`（未接入时）、`ModifyDomain`（开 443）、`ModifyDomainCert`（换证书）；
     自动归属权验证还需 `DescribeVerifyContent`、`VerifyDomainOwner`
   - **DNS**：`dns_ali` 需要的 AliyunDNSFullAccess（或最小权限）。新域名自动归属权验证会往域名的 DNS 写一条 TXT：
     Cloudflare 用证书的 `api_token`（需 Zone:DNS Edit 权限），阿里云 DNS 用对应账号 AK/SK（需 AddDomainRecord / UpdateDomainRecord / DescribeDomainRecords）。
     **阿里云国内站 / 国际站按证书的 `dns` 自动选 endpoint**：`aliyun_cn` → `alidns.aliyuncs.com`（cn-hangzhou）、
     `aliyun_intl` → `alidns.ap-southeast-1.aliyuncs.com`（ap-southeast-1），两站账号体系隔离不可混用；
     如需覆盖可在该账号配置里写 `dns_endpoint` / `region`（也兼容 `endpoint` 字段）

## 配置

复制示例并填写：

```bash
cp config/certs.example.yaml config/certs.yaml
```

凭证分两处：**层级结构写在 `certs.yaml`，敏感值写在 `config/.env`**（复制 `.env.example`）：

```bash
cp config/.env.example config/.env   # 填 AK/SK、CF Token、WAF 实例 ID
chmod 600 config/.env
```

`certs.yaml` 里按平台分组放层级结构（`aliyun_cn` / `aliyun_intl` / `cloudflare`），值用 `${VAR}` 从 `.env` 注入：

```yaml
aliyun_cn:                    # 国内站账号组；下一层账号名可自定义
  cn1:
    access_key: "${CN1_AK}"
    access_secret: "${CN1_SK}"
    region: "cn-hangzhou"     # 国内站固定，写在 yaml

aliyun_intl:                  # 国际站账号组
  intl1:
    access_key: "${INTL1_AK}"
    access_secret: "${INTL1_SK}"
    region: "ap-southeast-1"  # 国际站，必须写否则默认 cn-hangzhou 会调错

cloudflare:
  cloudflare1:
    api_token: "${CF_TOKEN_1}"
    account_id: "${CF_ACCOUNT_ID_1}"
```

第一层是**平台**、第二层是**账号名**，与证书字段一一对应：证书的 `dns` 填平台名（`aliyun_cn` / `aliyun_intl` / `cloudflare`），`dns_account` 填该平台下的账号名（`cn1` / `intl1` / `cloudflare1`）；部署同理用 `deploy`（平台）+ `deploy_account`（账号名）配对，决定「调用哪个平台、哪个账号」。脚本加载时把所有 `aliyun_*` 分组下的账号拍平成一个表。旧写法 `dns: aliyun` + `accounts:` 仍兼容（`aliyun` 视为阿里云 DNS）。

`.env` 只放扁平的 key=value 值（`CN1_AK` / `INTL1_AK` / `CF_TOKEN_1` 等）。**WAF 实例 ID 也放 `.env`**：按 `<平台>_<账号>` 配 `<平台大写>_<账号大写>_WAF_INSTANCE_ID`（如 `ALIYUN_CN_CN1_WAF_INSTANCE_ID` / `ALIYUN_INTL_INTL1_WAF_INSTANCE_ID`），兼容旧写法 `<账号大写>_WAF_INSTANCE_ID`（如 `CN1_WAF_INSTANCE_ID` / `INTL1_WAF_INSTANCE_ID`）+ 可选 `_WAF_REGION`；全局 `WAF_INSTANCE_ID` / `WAF_REGION` 是所有账号共用一个实例时的兜底。优先级：**平台+账号 > 账号 > 全局**。留空时脚本在**签发前**对每个 WAF `(平台, 账号)` 分别调 `DescribeInstance` 并打印实例详情：仅 1 个正常实例自动选用，多个则报错要求显式写（用 `--list-waf-instances` 查看）。国内站/国际站各查各的账号与地域，互不混用。

服务器 crontab 内联的同名环境变量优先级高于 `.env`。国际站账号 `region: ap-southeast-1` 必须写在 yaml，否则默认 `cn-hangzhou` 会调错。

**WAF 的 region 与账号 yaml 里的 region 是两回事**（账号 region 给 DCDN/CAS 用，WAF region 给 WAF OpenAPI 用）。用证书的 `waf_zone` 指定即可：`cn` → `cn-hangzhou`（中国内地实例）、`intl` → `ap-southeast-1`（非中国内地实例，含港澳台/海外）；脚本据此调 `DescribeInstance` 自动发现该地域唯一实例。若既没写 `waf_zone`、`.env` 也没配 `WAF_REGION`，脚本默认沿用账号 yaml 的 region——此时非中国内地实例会在 `cn-hangzhou` 查到 0 个、WAF 部署被跳过。故非中国内地 WAF 务必写 `waf_zone: intl`（或用 `.env` 的 `<平台>_<账号>_WAF_REGION=ap-southeast-1` 兜底）。

配置以**证书为单位**：每张证书自带 `dcdn_domains`（DCDN）和/或 `waf_domains`（WAF），不需要顶层 `dcdn_domains`，也不需要 `cert` 交叉引用。

```yaml
certificates:
  - name: "example.org"            # 可选：证书标识 = CAS 证书名前缀；省略时取主域名
    dns: aliyun_cn                  # 可选，默认 aliyun_cn（aliyun_cn / aliyun_intl / cloudflare）
    dns_account: cloudflare1       # DNS-01 验证账号（该平台下的账号名）
    deploy: aliyun_intl             # 可选：证书级默认部署平台（aliyun_cn / aliyun_intl）
    deploy_account: intl1          # 可选：证书级默认部署账号（该平台下的账号名）
    # domains: ["example.org", "*.example.org"]   # 可选：需要泛域/裸域/额外 SAN 时写
    dcdn_domains:
      - "www.example.org"          # 字符串简写：用证书级 deploy + deploy_account
      - "api.example.org"
      - domain: "cn.example.org"   # 需要换平台/账号时才展开成对象
        deploy: aliyun_cn
        deploy_account: cn1
    waf_origin: ["1.2.3.4"]         # 可选：证书级源站，供所有 waf_domains 共用
    waf_zone: cn                    # cn=中国内地 / intl=非中国内地；自动发现该地域唯一实例
    waf_domains:                    # 可选：WAF 3.0 防护域名（字符串列表即可）
      - "waf.example.org"          # 已接入 WAF：仅替换证书
      - "new.example.org"          # 未接入：用 waf_origin 自动接入（HTTP 80 起步）
    # 仅当某域名源站/平台/账号与证书级不同时，才展开成 {domain, origin, deploy, deploy_account} 对象
```

- **`domains`（可选）**：真正签进证书的 SAN 列表（裸域 / 泛域 / 子域），每项拆成 `-d`。**省略时由 `dcdn_domains` + `waf_domains` 的域名去重推导**（排序后首项为主域名，也就是 acme.sh 目录名）。需要泛域 `*.example.org`、裸域、或只签不部署的域名时必须显式写。推导模式下每新增一个域名都会改变 SAN → 触发重签，所以**域名较多或需要泛域时建议显式写 `domains`**。
- **`deploy` / `deploy_account`**：部署平台（`aliyun_cn` / `aliyun_intl`）+ 该平台下的账号名，二者配对确定「调用哪个平台、哪个账号」。证书级写一次作为默认，单个域名可用同名字段覆盖；**覆盖 `deploy_account` 时务必同时写对 `deploy`**（例如 `deploy: aliyun_cn` + `deploy_account: cn1`），否则会错误继承证书级平台。WAF 实例 ID 与地域也按这个配对去 `.env` 里找。
- **`dcdn_domains`**：要绑定的 DCDN 加速域名。字符串简写用证书级 `deploy` / `deploy_account`；写成 `{domain, deploy, deploy_account}` 可覆盖平台与账号，因此一张证书可同时部署到国内站和国际站。
- **同一张证书 DCDN 与 WAF 分属不同账号**：可以每个域名项各自写 `deploy`（更清晰），也可在证书级写 `deploy`/`deploy_account` 作默认、个别域名项覆盖。**域名项只写 `deploy` 未写 `deploy_account` 时，自动取该平台分组下的第一个账号**（如 `aliyun_intl` → `intl1`），不会错落到别的平台账号。DCDN 与 WAF 按各自的 `(证书, 平台, 账号)` 分组，互不干扰：

  ```yaml
  - name: "mix.example.com"
    dns: cloudflare
    dns_account: cloudflare1
    domains: ["mix.example.com", "*.mix.example.com"]
    dcdn_domains:
      - domain: "cdn.mix.example.com"
        deploy: aliyun_intl          # 自动取 intl1
    waf_domains:
      - domain: "waf.mix.example.com"
        waf_origin: "47.84.116.133"  # 源站也可写在域名项（等同 origin）
        deploy: aliyun_intl
        deploy_account: intl1
        waf_zone: intl               # 非中国内地实例 -> ap-southeast-1，自动发现唯一实例
  ```

  证书级 `waf_origin` / `waf_zone` 仍可作为所有 WAF 域名的默认；域名项写了就以域名项为准。
- **`waf_domains`**：要绑定的 WAF 3.0 防护域名，写法同 `dcdn_domains`，额外支持 `origin`（源站 IP/域名，字符串或列表；旧名 `backends` 仍兼容）。**WAF 与 DCDN 用不同的 CAS 证书名前缀**（`acme_waf_` vs `acme_`），避免先部署 WAF 占用名字导致 DCDN 报 `CertNameAlreadyExists`。新域名接入若报归属权未验证，脚本会用该证书的 `dns`/`dns_account` 凭证自动加 TXT 完成验证（详见「运行」节的首次接入说明）。
- **`waf_zone`（推荐）**：WAF 实例地域，`cn` = 中国内地（OpenAPI region `cn-hangzhou`）、`intl` = 非中国内地（`ap-southeast-1`）。阿里云一个账号在同一地域只有一个 WAF 实例，所以脚本按 `waf_zone` 解析出 region 后调 `DescribeInstance` **自动发现该地域唯一实例**，无需填实例 ID。证书级写一次作默认，域名项可覆盖；同账号的 `cn`/`intl` 是两个不同实例，会分别发现、互不串用。发现结果只在**本次脚本执行内**缓存（按 `平台.账号.地域`），同一账号同一地域只查一次；不跨进程持久化，实例更换后下次执行自动重新发现。
- **`waf_id`（可选高级覆盖）**：显式 WAF 实例 ID，填了就不再自动发现——仅当某地域查到多个实例、想指定某一个时才需要。优先级：**域名/证书 `waf_id` > `.env` 的 `<平台>_<账号>_WAF_INSTANCE_ID` / `<账号>_WAF_INSTANCE_ID` / 全局 `WAF_INSTANCE_ID` > 按 `waf_zone` 自动发现**。`.env` 的 `*_WAF_INSTANCE_ID` 只是兜底，证书配了 `waf_zone` 自动发现即可，不必填。
- **`waf_origin`（可选）**：证书级默认源站，域名没写 `origin` 时统一用它，省得每个 WAF 域名重复写。
  脚本以**接入域名为准**逐个判定（DescribeDomains 按域名过滤）：
  - 已接入且 443 已开、证书一致 → 跳过；证书不同 → `ModifyDomainCert` 只切证书引用；
  - 已接入但 443 未开 → `ModifyDomain` 开 443 并绑证书（带回现有回源配置，不会冲掉）；
  - 确实未接入且有源站（`origin`/`waf_origin`）→ 自动 `CreateDomain` 接入（HTTP 80 起步）再开 443；无源站则跳过并告警；
  - 接入状态查询失败 → 本次跳过（不自动接入，避免误判重复创建）。
- **`dns` / `dns_account`**：`dns` 是平台名 —— `aliyun_cn` / `aliyun_intl` 用对应 `aliyun_*` 分组账号的 AK 去阿里云 DNS 加 TXT（acme.sh `dns_ali`），`cloudflare` 用 `cloudflare` 段下账号的 API Token（`dns_cf`）。`dns_account` 是平台下的账号名（如 `cn1`/`intl1`/`cloudflare1`），**可省略**：省略时按 `dns` 平台取该分组下的第一个账号（`aliyun_cn`→`cn1`、`aliyun_intl`→`intl1`、`cloudflare`→第一个）；只有平台下有多个账号、想指定某个时才写。旧写法 `dns: aliyun` 仍视为阿里云 DNS。`cloudflare` 单账号旧写法也会自动归一化。

DNS 在 Cloudflare、DCDN/WAF 在阿里云互不影响的用法仍然支持。每个证书只签发一次，按「证书 + 部署平台 + 部署账号」分组，每组只上传一次。

启动时会在**加载期校验**：账号引用存在、证书 SAN 覆盖 DCDN/WAF 域名、`name` 唯一、域名不跨证书重复；有错直接退出。用 `python3 certmgr.py --config config/certs.yaml --check` 可只校验并打印归一化后的证书与分组，不签发、不部署、也不要求装 acme.sh。

**旧配置迁移**：顶层 `dcdn_domains` 仍会被自动识别并回填；旧写法 `dns: aliyun` + 顶层 `accounts:` 仍兼容。建议把顶层 `accounts` 改成 `aliyun_cn` / `aliyun_intl` 分组、把顶层 `dcdn_domains` 移进各证书，并给每张证书补 `deploy` / `deploy_account`。

**多账号**：阿里云在对应 `aliyun_*` 分组下加账号（如 `cn1` / `intl1` / `cn2`），AK/SK 的值写 `.env` 的 `<名>_AK` / `<名>_SK`；
Cloudflare 在 `cloudflare` 下用命名子账号（如 `cloudflare1` / `cloudflare2`），`dns_account` 指定具体哪一个。

## 运行（服务器原生，无 Docker）

```bash
# 1) 安装 Python 依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2) 准备配置
cp config/certs.example.yaml config/certs.yaml   # 填域名
cp config/.env.example config/.env               # 填 AK/SK、CF Token、WAF 实例 ID 的值（.env 已被 gitignore）
chmod 600 config/.env

# 3) acme.sh 目录（本机默认 ~/.acme.sh，容器默认 /acme.sh）
export LE_WORKING_DIR=$HOME/.acme.sh

# 4) 先校验配置（只打印归一化后的证书/分组，不签发、不部署）
python3 certmgr.py --config config/certs.yaml --check

# 4b) 如启用了 waf_domains 但不知道 WAF_INSTANCE_ID 填哪个：列出各账号的 WAF 实例详情
python3 certmgr.py --config config/certs.yaml --list-waf-instances
python3 certmgr.py --config config/certs.yaml --list-waf-instances --account cn1   # 只看某账号
# 把输出的 InstanceId 填进 .env 对应平台+账号的 ALIYUN_CN_CN1_WAF_INSTANCE_ID /
# ALIYUN_INTL_INTL1_WAF_INSTANCE_ID（或旧写法 CN1_WAF_INSTANCE_ID / INTL1_WAF_INSTANCE_ID）；
# 每个账号输出会同时显示 region 和当前配置的实例，按账号分别填；留空且单实例时自动选用

# 5) 立即执行一次
python3 certmgr.py --config config/certs.yaml

# 6) 注册系统 crontab（每日续期+部署，单一驱动）
# 若服务器此前已有 acme.sh 自动注册的 --cron 任务，先删掉避免重复：
crontab -l | grep -v 'acme.sh --cron' | crontab -
crontab -e
# 加入（用 venv 里 python 绝对路径）。脚本会自行加载 config/.env，cron 行无需 AK 变量：
17 3 * * * cd /opt/cert-manager && /opt/cert-manager/venv/bin/python3 certmgr.py --config /opt/cert-manager/config/certs.yaml >> /opt/cert-manager/logs/certmgr.log 2>&1
# 如不想把凭证落在 .env，也可在 cron 行内联（优先级高于 .env）：
# 17 3 * * * CN1_AK=xxx CN1_SK=xxx CF_TOKEN_1=xxx CN1_WAF_INSTANCE_ID=waf_xxx LE_WORKING_DIR=/root/.acme.sh cd /opt/cert-manager && /opt/cert-manager/venv/bin/python3 certmgr.py --config /opt/cert-manager/config/certs.yaml >> /opt/cert-manager/logs/certmgr.log 2>&1
```

WAF 首次接入注意：`CreateDomain` 要求域名已完成**域名归属权验证**与（国内站）**ICP 备案**。
- **归属权验证（DNS TXT）**：脚本自动代办。`CreateDomain` 报 `DomainOwnerNotVerify` 时，脚本用该证书自身的 DNS 账号（`dns` / `dns_account`，与签发同一套凭证）调 `DescribeVerifyContent` 取 TXT 内容，写入 DNS（存在则更新、不存在则新增），再调 `VerifyDomainOwner` 轮询校验，通过后自动重试接入。TXT 首次配置实时生效、修改最长约一个 TTL（10 分钟），若本次未通过可稍后重跑。若证书 DNS 凭证缺失或无相应权限，会跳过并在日志告警。
- **ICP 备案**：脚本不代办，国内站域名需先在阿里云控制台完成备案，否则接入失败。

## 验证

- 阿里云控制台 → SSL 证书：应出现 `acme_<name>_<日期>`（DCDN）与 `acme_waf_<name>_<日期>`（WAF）命名的证书；
- 阿里云控制台 → DCDN → 域名管理 → HTTPS 配置：应已绑定对应证书；
- 阿里云控制台 → WAF 3.0 → 防护域名：HTTPS（443）已开启、证书为 `acme_waf_` 前缀那份；
- 旧证书应被自动清理（仅保留最新一份同名前缀证书）。

## 注意事项

- `~/.acme.sh` 是 acme.sh 证书与 Let's Encrypt 账号目录，**不要删除**，否则已签发证书与账号会丢失，频繁重签可能触发 LE 速率限制。
- `name` 决定 CAS 证书名前缀（`acme_<name>_`）。改 `name` 会让旧前缀证书不再被自动清理（脚本只清理当前前缀），已有证书如非必要不要改名。
- 泛域 `*.example.org` 只覆盖一级子域（如 `www.example.org`），**不含**裸域 `example.org`，也不含 `a.b.example.org`；这类域名必须显式列进 `domains`，否则加载期校验会报错。
- 国际站账号的 `region` 写在 `config/certs.yaml` 对应账号下（`region: ap-southeast-1`，不写会按默认 `cn-hangzhou` 导致 API 调错）；如需指定 `endpoint` 也写在 yaml 同层。WAF 地域可用 `.env` 的 `<平台>_<账号>_WAF_REGION`（如 `ALIYUN_INTL_INTL1_WAF_REGION`）单独覆盖。
- 阿里云 CAS / DCDN SDK 的接口参数若随版本变化，以阿里云官方文档为准微调 `certmgr.py` 中对应请求即可。

## 后续（告警）

- 暴露 Prometheus metrics：证书 `notAfter` 时间戳（gauge）+ 任务成败 counter；
- Alertmanager 规则：到期 `< 14天` 或 `deploy` 失败 → 钉钉/飞书告警。
