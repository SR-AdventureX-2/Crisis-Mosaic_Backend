# Crisis Mosaic Backend

Crisis Mosaic 的 FastAPI 单机功能型 P0 后端。它实现匿名居民上报、实名联络密文快照、
事件地图、图片/视频媒体意图、定向问答、冲突与事实版本链、AI 辅助分析、审计、
WebSocket 实时同步和指挥端 Push Outbox。

本实现使用 SQLite、单个 Uvicorn worker 和本地文件存储，适合功能联调、比赛演示和
单机部署。它不宣称满足 `backend.md` 中的生产容量、高可用或灾备指标。

## 主要能力

- 本地账号与匿名设备 JWT 会话，Access Token 60 分钟，Refresh Token 单次轮换。
- 六类居民上报、幂等创建、乐观锁更新、完整版本历史和人工优先级。
- WGS84/GCJ-02 一次性标准化、角色过滤地图、居民侧他人上报约 100m 模糊化、
  bbox 面积限制和 500 点安全上限。
- 上报人姓名、手机号、紧急联系人和救援备注字段级加密；报告列表及居民详情只返回脱敏
  摘要。已鉴权且有事件访问权的指挥账号可在单条报告详情中读取明文并留下无 PII 审计；
  独立 reveal API 仍使用 mock MFA 和审计。
- 旧本地图片三步上传继续保留；新媒体接口支持 Kodo Mock，以及服务端为真实七牛 Kodo
  签发标准短期直传 Token、对象 Key、表单/可恢复上传会话、分片检查点、续签和完成校验。
- 本地图片链路仍执行 SHA-256、真实 MIME、Pillow 像素限制、EXIF 净化、
  缩略图、感知哈希和重复来源聚类。
- 盲区、定向问题、回答历史和结构化冲突自动检测；定向回答不会重复生成上报，并可绑定
  已完成处理的图片/视频附件。上报创建、读取和更新响应同样返回已绑定附件明细。
- 多证据人工冲突决策、稳定事实头表和追加式事实版本链。
- OpenAI-compatible AI：同步上报整理，异步冲突研判和态势简报。
- SQLite 持久任务、租约重试、Transactional Outbox、通知 Outbox、WebSocket 补发
  和权限过滤。
- Prometheus HTTP 延迟、幂等、实时连接、任务、AI、冲突、盲区、地图和事实指标。
- OpenAPI 3.1 与离线 Swagger UI；根路径自动跳转到 `/docs`。

## 快速开始（PowerShell）

需要 Python 3.12。请在仓库根目录执行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

仓库已提供脱敏配置模板。首次配置时复制模板，并替换其中的密钥和密码：

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

仓库只提供 `.env.example`，不会预先生成 `.env`。复制模板后必须自行生成并填写本地随机
密钥；模板中的 `AI_API_KEY` 保持为空，填写兼容服务的 Key 后才会启用真实 AI。未配置时
核心业务正常运行，AI 接口返回明确的 `503 AI_SERVICE_UNAVAILABLE`。

初始化数据库并写入幂等演示数据：

```powershell
alembic upgrade head
crisis-mosaic seed
```

启动单进程服务：

```powershell
crisis-mosaic serve
```

也可直接运行：

```powershell
uvicorn crisis_mosaic.main:app --host 127.0.0.1 --port 8000 --workers 1
```

根目录兼容入口会自动解析 `src/`，即使尚未执行 editable install 也可以启动：

```powershell
python app.py
```

打开 [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)。Swagger UI 5 的
JavaScript、CSS 和图标均由仓库自托管，不依赖 CDN。

> **重要：** SQLite 写事务由进程内锁串行化，数据目录还持有操作系统级进程锁，因此
> 只能启动一个 worker。第二个进程会拒绝启动；不要使用 `--workers 2`、多实例或自动
> 横向扩容。

## 演示数据与登录

`crisis-mosaic seed` 可重复执行，且不会在普通启动时自动写数据。它创建：

- 杭州洪灾事件，别名 `demo-hangzhou-flood`。
- 大关桥盲区和阈值为 1 的演示定向问题。
- 沿江路冲突，别名 `along-river-road-passability`。
- `admin` 与 `operator` 本地账号及事件成员关系。

账号密码取自 `.env` 中的 `BOOTSTRAP_ADMIN_PASSWORD` 和
`BOOTSTRAP_OPERATOR_PASSWORD`。在 Swagger 中调用 `POST /api/v1/auth/token`
（表单格式）获取令牌，然后点击 **Authorize** 输入 `Bearer` Token。

匿名居民先调用 `POST /api/v1/resident-device-sessions`（兼容旧
`/anonymous-sessions`）。`installation_id` 应由客户端生成，
至少包含 128 位随机熵，例如 22 个以上 URL-safe 随机字符。新匿名会话和匿名 Token
轮换仅允许绑定 `active` 事件，不会跨事件续签到已关闭或尚未启用的事件。

## 常用 API

所有 REST 路径以 `/api/v1` 开头，成功响应统一为 `data/meta`，错误统一为
`error.code/message/request_id/details`。

| 领域 | 主要端点 |
| --- | --- |
| 认证 | `/resident-device-sessions`、`/anonymous-sessions`、`/auth/token`、`/auth/me` |
| 上报 | `/incidents/{id}/reports`、`/reports/{id}`、`/reporter-contact/reveal` |
| 媒体 | `/uploads/image-intents`、`/uploads/media-intents`、`/resumable-sessions` |
| 地图 | `/incidents/{id}/map-view` |
| 问答 | `/blind-spots`、`/directed-questions`、`/my-answer`、`/fragments` |
| 冲突事实 | `/conflicts`、`/decision`、`/fact-records` |
| AI | `/ai/report-refinements`、`/conflicts/{id}/ai-analysis`、`/ai/analyses/{id}` |
| 通知 | `/me/push-devices`、`/me/notification-preferences/{id}`、`/notifications/{id}/receipts` |
| 运维 | `/health/live`、`/health/ready`、`/metrics` |

创建业务资源时提交 `Idempotency-Key`。访问事件内资源时同时提交：

```text
Authorization: Bearer <access-token>
X-Incident-Id: <incident-uuid>
```

报告列表中的 `reporter` 对所有角色均为脱敏数据。已鉴权且具有对应事件访问权的
`operator`/`admin` 调用 `GET /api/v1/reports/{report_id}` 时，详情中的 `reporter` 才返回
明文联系人和附加信息；居民详情仍为脱敏数据。该指挥详情响应使用
`Cache-Control: no-store`，明文读取会写入不含 PII 的审计记录，也不会产生包含 PII 的
Outbox 事件。

上报创建会在同一数据库事务内保存业务结果和幂等响应。其他创建/PUT 接口由通用持久幂等
层保护：同一键和请求体会回放首次成功响应；键冲突返回 409。若进程恰好在业务提交后、
响应快照写入前崩溃，该键会返回 `IDEMPOTENCY_IN_PROGRESS` 直至 24 小时窗口到期，以
避免在结果未知时自动重复写入；此时应由操作员查询资源状态，不应更换键盲目重试。

图片采用三步协议：创建上传意图、向返回的 `upload_url` 发送原始二进制 `PUT`、调用
`complete`。完成请求会校验哈希并进入处理队列进行 MIME、像素与 EXIF 净化。

新版媒体接口使用 `/uploads/media-intents`。默认 `qiniu_kodo_mock` 返回 Mock Token；设置
`MEDIA_STORAGE_PROVIDER=qiniu_kodo` 后，服务端按七牛上传策略生成包含 bucket/object key
作用域、截止时间和防覆盖约束的标准短期 Token。AK 仅作为标准 Token 的组成部分返回，
SK 不下发给客户端。客户端声明
`client_capabilities.resumable_upload=false` 时，图片和视频均返回 `KODO_FORM`，以
`token`、`key` 和 `file` multipart 字段直传；为 `true` 时返回
`KODO_RESUMABLE_V2` 和可恢复会话入口。文件字节不经过业务后端。

媒体完成处理后才能绑定业务资源。上报创建和 PATCH 使用 `attachment_ids`；PATCH 省略该
字段时保留现有绑定，显式列表替换，空列表清除。定向回答 PUT 也接受 `attachment_ids`，
该列表代表本次回答的完整附件集合。附件必须属于同一事件和当前居民设备、处于 ready/clean
状态且尚未绑定其他上报或回答。上报响应、回答响应和居民活动问题中的 `my_answer` 均返回
`attachment_ids` 与 `attachments` 明细。

视频上传默认由 `ENABLE_VIDEO_UPLOAD=false` 关闭。当前真实 Kodo 集成只负责标准 Token
签发和客户端直传合同；尚未实现服务端 Kodo Stat 校验、七牛回调接收端，以及真实恶意
文件扫描、视频转码和验收，完成接口也不会主动向七牛查询对象；媒体访问 URL 仍使用 mock
签名。因此启用视频或用于生产前仍需完成这些外部集成检查。部署配置见
[单机部署与运维](docs/deployment.md#媒体与-kodo)。

WebSocket 地址为 `ws://127.0.0.1:8000/api/v1/realtime`。连接后 5 秒内发送：

```json
{
  "type": "authenticate",
  "access_token": "<access-token>",
  "incident_id": "<incident-uuid>",
  "last_sequence": 0
}
```

Token 不得放在查询参数。实时事件 Schema 位于
`/schemas/realtime-event.json`。

## 数据保留

后台进程在启动后立即执行一次保留期清理，之后按
`RETENTION_CLEANUP_HOURS`（默认 24 小时）重复执行。默认规则为：

- 幂等记录和已过期 Refresh Token 会话在到期后删除。
- 已发布 Outbox 事件超过 `REALTIME_REPLAY_HOURS` 后删除；未发布事件不会被清理。
- 审计日志保留 `AUDIT_RETENTION_DAYS`（默认 365 天）。
- 已关闭事件超过 `BUSINESS_RETENTION_DAYS`（默认 180 天）后，上报、回答、信息碎片、
  对应历史/冲突证据/AI 快照和地图投影中的居民敏感内容会被不可逆匿名化，本地附件
  也会删除。
- 上报联系人默认按 `REPORTER_CONTACT_RETENTION_DAYS_AFTER_INCIDENT` 独立匿名化；
  事件整体过期时同步清除联系人密文、远端对象 Key、媒体处理状态和策略快照。

附件清理只允许删除解析后位于 `STORAGE_ROOT` 内的普通文件；越界路径或非文件路径会被
跳过并记录告警。修改保留期前应先确认法规和备份要求。

## 监控指标

`GET /api/v1/metrics` 返回 Prometheus 文本格式，除 Python 进程指标外还包括：

- API 请求量、状态码和延迟直方图，可在 PromQL 中计算 P50/P95/P99 与错误率。
- 幂等 reservation/replay/conflict、WebSocket 在线连接/重连/补发/慢消费者。
- Outbox 积压与投递延迟、持久任务状态和重试结果。
- 上报、AI 状态与平均延迟、冲突解决耗时、盲区首次回答耗时。
- 精确地图点数/拒绝原因、事实状态与版本数、SQLite 写锁状态。

单机精确点模式不执行聚合，`crisis_mosaic_map_aggregation_ratio` 固定为 0。SQLite 没有
复制延迟；AI 成本也无法从未返回 usage 的 OpenAI-compatible 服务可靠推导，二者不会
伪造为生产级指标。

## AI 配置

真实模型使用 OpenAI-compatible `chat/completions` 协议：

```dotenv
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=
AI_CHAT_COMPLETIONS_PATH=/chat/completions
AI_REPORT_MODEL=gpt-4.1-mini
AI_VISION_MODEL=gpt-4.1-mini
AI_BRIEF_MODEL=gpt-4.1-mini
```

测试和离线演示可设置 `AI_PROVIDER=fake`。服务端始终使用 Pydantic Schema 校验 AI
输出，并校验证据 ID / source_ref 白名单、报告事实保护规则和简报 metrics 引用。AI 不能直接
写入最终事实；事实变更只能经过人工冲突决策。

提示词按任务在代码中固化，并分别记录版本和 `prompt_sha256`。当前版本为：
`cm-report-refinement-v1.0.0`、`cm-media-evidence-extraction-v1.0.0`、
`cm-conflict-analysis-v1.0.0`、`cm-command-brief-v1.0.0` 和
`cm-json-repair-v1.0.0`。

`GET /api/v1/ai/analyses/{analysis_id}` 会返回 `prompt_sha256`、`input_tokens`、
`output_tokens`、`schema_valid` 和 `reference_valid`，用于审计结构化输出和引用校验。

调用方传入 `context.evidence` 的旧同步冲突请求仅在 `ENABLE_LEGACY_DEMO_AI=true` 时
启用。正式请求始终从数据库读取当前完整证据并返回
`202 + analysis_id + status_url`。

## 验证

```powershell
python -m pytest
python -m ruff check src tests migrations
python -m mypy src\crisis_mosaic
alembic check
```

真实 AI Key、真实 Kodo 上传和真实 Push provider 属于可选集成检查。常规测试使用 fake
AI、Kodo Mock 和 Push Mock，并使用测试凭证验证真实 Kodo Token 的本地签名合同，不向
第三方服务发送请求。

更多说明：

- [实现边界与偏差](docs/implementation-profile.md)
- [单机部署与运维](docs/deployment.md)
- [本地贡献指南](CONTRIBUTING.md)

## License

本项目采用 [MIT License](LICENSE)。
