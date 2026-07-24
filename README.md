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
- 上报人姓名、手机号、紧急联系人和救援备注字段级加密，普通响应只返回脱敏摘要；
  明文读取走独立 reveal API、mock MFA 和审计。
- 旧本地图片三步上传继续保留；新媒体接口返回 Kodo Mock 直传 Token、对象 Key、
  可恢复上传会话、分片检查点、续签、取消和完成校验。
- 本地图片链路仍执行 SHA-256、真实 MIME、Pillow 像素限制、EXIF 净化、
  缩略图、感知哈希和重复来源聚类。
- 盲区、定向问题、回答历史和结构化冲突自动检测；定向回答不会重复生成上报。
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

当前工作区已经生成本地随机密钥并写入被 Git 忽略的 `.env`。`AI_API_KEY` 有意保持
为空，填写兼容服务的 Key 后才会启用真实 AI；未配置时核心业务正常运行，AI 接口返回
明确的 `503 AI_SERVICE_UNAVAILABLE`。

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

上报创建会在同一数据库事务内保存业务结果和幂等响应。其他创建/PUT 接口由通用持久幂等
层保护：同一键和请求体会回放首次成功响应；键冲突返回 409。若进程恰好在业务提交后、
响应快照写入前崩溃，该键会返回 `IDEMPOTENCY_IN_PROGRESS` 直至 24 小时窗口到期，以
避免在结果未知时自动重复写入；此时应由操作员查询资源状态，不应更换键盲目重试。

图片采用三步协议：创建上传意图、向返回的 `upload_url` 发送原始二进制 `PUT`、调用
`complete`。完成请求会校验哈希并进入处理队列进行 MIME、像素与 EXIF 净化。

新版媒体接口使用 `/uploads/media-intents`。服务端返回短期 Kodo Mock Upload Token、
单对象 Key、技术策略快照和上传模式；客户端文件字节不经过业务后端。视频上传默认由
`ENABLE_VIDEO_UPLOAD=false` 关闭，打开前应完成真实 Kodo、扫描和转码验收。

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

当前 Flutter 演示使用的 `context.evidence` 同步冲突请求仅在
`ENABLE_LEGACY_DEMO_AI=true` 时启用。正式请求始终从数据库读取当前完整证据并返回
`202 + analysis_id + status_url`。

## 验证

```powershell
python -m pytest
python -m ruff check src tests migrations
python -m mypy src\crisis_mosaic
alembic check
```

真实 AI Key、真实 Kodo 和真实 Push provider 属于可选本机集成检查；
常规测试使用 fake AI、Kodo Mock 和 Push Mock，不依赖外部服务。

更多说明：

- [实现边界与偏差](docs/implementation-profile.md)
- [单机部署与运维](docs/deployment.md)
- [本地贡献指南](CONTRIBUTING.md)

## License

本项目采用 [MIT License](LICENSE)。
