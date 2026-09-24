# 人形机器人试验统计准入服务

本仓库是一套已经实现并可直接运行的服务端项目，用于把人形机器人在递送、讲解和灵巧操作等场景中的结构化试验记录转成可复核的统计准入结论。系统以 SQLite 保存组织、团队、成员关系、机器人、软件构建、不可变协议版本、试验批次、原始观测、排除申请、分析快照、准入决定和审计事件，不依赖机器人设备、图片、音频、视频或外部基础设施。

现有代码按职责分为：

- `api.py`：标准库实现的 HTTP JSON 接口与无网络路由测试边界；
- `service.py`：组织/团队权限、批次状态机、幂等导入、排除复核、任务租约、审批和报告；
- `analysis.py`：分层覆盖、Wilson 区间、描述性统计、确定性 bootstrap 和准入规则；
- `contracts.py`：协议、指标、分层、权重、随机种子和单次观测的数据契约；
- `jsonio.py`：严格 JSON/JSONL 读取、规范化序列化与内容摘要；
- `numeric.py`：不依赖第三方库的描述性统计和 Wilson 区间；
- `storage.py`：完整 SQLite 业务模式、约束、索引和事务辅助；
- `migrations.py`：v2 全局角色库到 v3 组织/团队模式的数据迁移；
- `clock.py`：生产时钟与可确定性推进的测试时钟；
- `acceptance.py`：贯通建档、导入、封存、分析、审批和报告的离线验收。

系统已经实现以下主流程：协议发布后不可原地覆盖；批次按版本从草稿进入运行、封存、分析和决定状态；观测分片同时受请求幂等键和来源行唯一身份保护；排除请求必须由不同角色复核；分析任务使用 SQLite 租约避免重复执行并支持过期接管；同一输入快照使用固定算法版本和随机种子得到一致结果；分析者与审批人职责分离，报告保留输入摘要、统计规则和批次审计链。

## 多组织权限模型

服务供多个事业部共用，授权全部来自组织内的成员关系，用户本身不携带全局角色：

- **团队成员关系**（`memberships`）：按“用户 × 团队”授予 operator、statistician、approver、auditor 之一，同一用户可以在不同团队拥有不同角色，职责分离语义与原来一致；
- **组织角色**（`org_roles`）：`org_admin` 维护团队与成员关系，但不能读取业务数据、不能审批试验结论，也不能修改自己的授权（防止自我授予审批权）；`org_auditor` 跨团队只读报告与审计事件；
- **对象归属**：机器人、构建、协议和批次都归属唯一的组织与团队，日常读写只能作用于操作人被授权团队的对象；批次引用的构建与协议必须同属一个团队，跨组织或跨团队引用一律拒绝；
- **存在性保护**：对无权可见的对象，列表自动过滤，单项读取、报告和写操作一律返回与“不存在”完全相同的 404 响应，无法通过响应差异探测其他组织的对象；
- **即时失权**：成员关系或组织角色被移除后，新请求立即失去权限；历史审计事件保留操作人当时的编号与显示名快照，不受移除影响；
- **并发安全**：封存、审批等写操作把成员资格检查放在 `BEGIN IMMEDIATE` 事务内执行，与成员变更串行化，杜绝“权限检查后被撤权仍写入”的窗口。

主要接口（均需 `X-Actor-Id`，写观测还需 `Idempotency-Key`）：

```
POST /users                                  创建用户（不携带角色）
POST /orgs                                   创建组织，创建人成为 org_admin
POST /orgs/{org}/teams                       创建团队（org_admin）
GET  /orgs/{org}/memberships                 查看成员与组织角色（org_admin/org_auditor）
POST /orgs/{org}/memberships                 授予团队成员关系（org_admin）
POST /orgs/{org}/memberships/revoke          移除团队成员关系（org_admin）
POST /orgs/{org}/org-roles                   授予组织角色（org_admin）
POST /orgs/{org}/org-roles/revoke            移除组织角色（org_admin）
POST /robots  /builds  /protocols  /batches  目录与批次建档（按团队授权）
GET  /batches[?org_id=&team_id=]             列出可见批次
GET  /batches/{id}                           读取单个批次
POST /batches/{id}/start|observations|seal   批次状态推进
GET  /batches/{id}/report                    完整报告（团队统计/审批/审计或组织审计员）
POST /exclusions  /exclusions/{id}/review|revoke
POST /jobs/claim  /jobs/{id}/complete|fail   分析任务租约（按团队领取）
POST /decisions                              准入审批
```

## 数据迁移

模式版本为 3。对 v2（全局角色）数据库，`initialize` 会在单个事务中自动迁移：全部业务对象归入 `legacy` 组织与团队，用户原有全局角色转换为该团队成员关系，审计事件补写操作人显示名快照，迁移完成后执行外键一致性校验。全新部署直接创建 v3 结构。

## 环境

- Linux
- Python 3.11 或更高版本
- 无需安装第三方 Python 包

如需安装到隔离环境，可在依赖已经准备好的容器中执行：

```bash
python3 -m pip install --no-index --no-deps .
```

## 测试

在 `project/` 目录执行：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

测试使用临时目录和内存数据库，不访问网络，也不依赖常驻服务。

## 构建检查

本项目是纯 Python 源码包，构建检查采用字节码编译：

```bash
python3 -m compileall -q src tests
```

## 无浏览器验收

下面的命令会读取 `fixtures/` 中的协议与观测记录，在临时 SQLite 数据库中完成组织与成员建档、协议发布、批次启动、观测导入、批次封存、任务领取、统计分析、准入审批和审计报告导出，随后输出一行 JSON 结果：

```bash
PYTHONPATH=src python3 -m robot_trials.acceptance --workspace .
```

成功时退出码为 `0`，输出中的 `status` 为 `ok`。验收过程不会写入仓库，也不需要浏览器或外部服务。

## 启动 HTTP 服务

```bash
PYTHONPATH=src python3 -m robot_trials.api --database robot_trials.sqlite3 --host 127.0.0.1 --port 8080
```

接口使用 `X-Actor-Id` 表示当前操作人，写入观测时还需提供 `Idempotency-Key`。正式使用前应先创建用户，由首个用户创建组织（自动成为组织管理员），再创建团队并授予成员关系，之后才能登记机器人、软件构建与协议版本。服务进程可以停止后重新启动，SQLite 中的业务状态、分析任务和租约信息会保留。
