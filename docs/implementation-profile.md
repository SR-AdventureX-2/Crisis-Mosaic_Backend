# 功能型 P0 实现边界与偏差

## 定位

本仓库按 V1.1 合并需求实现单机功能型 P0 业务闭环，但部署边界固定为单机 SQLite。
产品 AI 展示仍由独立 Flutter 前端负责；Swagger UI 只用于 API 文档、鉴权和 AI 调试。

`backend.md` 保持原文不改，本文件记录实现时锁定的覆盖项和偏差。

## 技术实现

- Python 3.12、FastAPI、Pydantic Settings、SQLAlchemy async、aiosqlite 和 Alembic。
- SQLite 启用 WAL、外键、5 秒 busy timeout 和 `synchronous=NORMAL`。
- 所有应用写事务通过进程内异步锁串行化；数据目录级操作系统锁确保同一部署只有一个
  Uvicorn worker/process。
- Alembic 启用 `render_as_batch`，支持 SQLite 表复制式结构变更。
- 主键使用 UUIDv7 字符串；时间按 UTC 写入，API 输出 `Z` 后缀。
- JSON 保存为 SQLite JSON/TEXT；位置保存原始值、WGS84 和 GCJ-02 投影。
- 范围检索使用 bbox、Haversine 和应用层几何逻辑，不冒充 PostGIS。
- 旧图片代理链路保存在 `data/uploads` 的隔离目录；新媒体链路支持 Kodo Mock，也可用
  服务端 AK/SK 为真实七牛 Kodo 签发标准短期 Token，并只保存对象 Key、会话和处理状态。
- 持久任务、业务 Outbox 和通知 Outbox 保存在 SQLite；WebSocket 连接中心仅驻留当前
  进程。

## 业务合同

- 匿名设备可维护多条普通上报；最近上报只返回最新普通上报。
- 匿名会话和轮换 Token 固定绑定当前 `active` 事件；事件停用后不可新签发或轮换。
- 创建版本 1 同样写入上报历史。所有更新以 `revision` 做乐观并发控制。
- 上报创建必须包含 reporter 联系方式；姓名、手机号、身份证、紧急联系人和救援备注
  字段级加密。列表及居民详情始终只返回脱敏形式；仅已登录且通过事件访问校验的
  operator/admin 在 `GET /api/v1/reports/{report_id}` 指挥详情中直接获得明文联系人和附加
  信息。该响应强制 `Cache-Control: no-store`，每次明文详情读取写入不含 PII 的审计记录，
  且不写入 Outbox。独立明文 reveal 仍只允许 admin + mock MFA，并写审计。
- PATCH 省略字段表示保留；显式 `null` 仅清除允许为空的字段；位置对象整体替换。
- 紧急上报固定为 `high/urgent_flag`；其余按人工覆盖、有效 AI 建议、类别默认值排序。
- 定向回答只更新回答和信息碎片，不额外生成上报；PUT 可用 `attachment_ids` 替换绑定的
  ready/clean 附件，回答响应和居民活动问题中的 `my_answer` 返回附件 ID 与明细。
- 上报创建可绑定 ready/clean 附件；PATCH 省略 `attachment_ids` 时保留、显式列表替换、
  空列表清除。上报创建、列表、详情、最近上报和更新响应返回附件 ID 与明细。同一附件
  不能同时绑定上报和定向回答，且必须属于同一事件和居民设备。
- 默认两个一致有效回答关闭盲区；大关桥种子场景覆盖为一个；`unknown` 不计数。
- 自动冲突检测只处理有 `claim_key/claim_value` 的结构化事实；自由文本由人工创建冲突。
- 人工决策必须覆盖当前完整证据，并在一个事务内更新冲突、证据处置、事实版本、地图、
  审计和 Outbox。
- 指挥角色读取授权精度坐标；居民地图中他人上报约 100m 模糊化，不返回设备 ID、
  精确地址或 Token。单次最多 500 个点，bbox 还受配置面积上限约束，任一超限均返回
  `MAP_VIEW_TOO_LARGE`。
- `/uploads/media-intents` 按 provider 返回 Mock Token 或真实七牛标准短期 Token、对象 Key
  和上传模式；客户端不支持可恢复上传时，图片/视频均使用 `KODO_FORM`，支持时均使用
  `KODO_RESUMABLE_V2`。API 不代理新媒体文件字节，也不下发 SK；视频仍由
  `ENABLE_VIDEO_UPLOAD` 控制。
- 指挥端 Push 使用设备注册、个人偏好、通知 Outbox、Mock provider 投递和回执记录；
  业务事务不直接调用第三方服务。
- AI 上报整理同步执行；正式冲突分析和态势简报异步执行。AI 输出必须通过 Schema、
  证据/source_ref 引用校验和事实保护校验；分析记录保存 prompt 版本、`prompt_sha256`、
  token 用量和校验状态。
- 上报创建的幂等记录与业务数据原子提交。其他写接口使用独立的持久幂等 reservation；
  极端进程崩溃发生在业务提交与响应快照提交之间时，会保留 `IN_PROGRESS` 到 24 小时
  窗口结束，而不是猜测结果并自动重放写操作。

## 与生产需求的明确偏差

| 范围 | 单机 P0 实现 | 不作出的声明 |
| --- | --- | --- |
| 数据库 | SQLite WAL、单写锁 | 不等价于 PostgreSQL/PostGIS |
| 并发 | 单进程、单 worker | 不满足 200 写请求/秒 |
| 实时 | 内存连接中心、SQLite 回放 | 不满足 20,000 长连接或跨实例广播 |
| 可用性 | 本机重启恢复任务和 Outbox | 不满足 99.9%、多可用区、自动故障转移 |
| 存储 | 旧本地图片 + Kodo Mock/真实 Token 签发与对象 Key | 未实现 Kodo Stat、回调接收、真实扫描/转码验收或生产级私有下载鉴权，不声明七牛 SLA 或配额能力 |
| 身份 | 本地账号、JWT、mock MFA code | 不提供 OIDC、真实 MFA 或企业目录 |
| 密钥 | 本地 `.env` 派生字段密钥 | 不等价于 KMS 信封加密或密钥轮换 |
| Push | SQLite Outbox + Mock provider | 不等价于 APNs/FCM/厂商通道送达能力 |
| 地图隐私 | 居民侧上报模糊化，最多 500 点 | 不实现低缩放聚合或复杂风险分级策略 |
| 监控 | 本机 Prometheus 进程/业务指标 | 无 SQLite 复制延迟或跨实例指标 |
| 灾备 | 手工数据库与上传目录备份 | 不承诺 RPO 5 分钟/RTO 30 分钟 |

## 前端边界

Flutter 客户端对接不再限定为“仅冲突分析”；本后端已提供登录会话、居民上报及附件、
定向回答及附件、地图、指挥简报、冲突分析和实时同步合同。具体客户端覆盖情况应以当前
Flutter 代码和 OpenAPI 为准，本文件不再把这些能力描述为尚未适配。本仓库中的 Swagger
UI 仍只用于 API 文档、鉴权和调试，不是产品 AI 页面。
