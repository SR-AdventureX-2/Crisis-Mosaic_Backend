# 单机部署与运维

## 前置条件

- Windows 11 或 Windows Server，Python 3.12。
- 一个可写的本地数据目录。
- OpenAI-compatible API Key（仅 AI 功能需要）。
- 真实 Kodo、FCM/APNs 或厂商 Push 凭证仅在接入相应通道时需要；媒体和 Push 默认使用
  Mock，但媒体服务也可为真实七牛 Kodo 签发标准直传 Token。

不使用 Docker、Compose、Redis、Celery 或 PostGIS。默认 Mock 便于单机联调；真实对象
存储需要独立凭证和上传验收，真实 Push provider 还需要相应通道凭证和投递验收。

## 安装与升级

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
Copy-Item .env.example .env
alembic upgrade head
crisis-mosaic seed
```

仓库不会附带或自动生成 `.env`；首次安装需要从模板复制并替换其中的占位密钥。已有
`.env` 时不要覆盖。部署升级前先备份数据库和上传目录，再执行：

```powershell
git pull --ff-only
python -m pip install -e .
alembic upgrade head
```

`crisis-mosaic seed` 只用于需要演示数据的环境，正常启动不会自动写种子。

本版本把匿名 Refresh Token 固定到签发时事件。升级前创建、尚无事件作用域的旧匿名
Refresh Token 会被拒绝；居民端应重新调用 `/api/v1/anonymous-sessions` 建立会话。

## 配置优先级

Pydantic Settings 从进程环境和仓库根目录 `.env` 读取配置；进程环境优先。至少必须替换：

- `JWT_SECRET`
- `INSTALLATION_ID_PEPPER`
- `UPLOAD_SIGNING_SECRET`
- `PII_ENCRYPTION_KEY`
- `PII_BLIND_INDEX_SECRET`
- `PUSH_TOKEN_SECRET`
- 两个 bootstrap 账号密码
- `AI_API_KEY`（需要真实 AI 时）

生产环境设置 `APP_ENV=production` 后，应用会拒绝模板占位值、过短或重复的签名密钥、
PII/Push 密钥、明显弱的 bootstrap 密码以及通配 CORS。

数据库和文件目录可改为绝对路径：

```dotenv
DATABASE_URL=sqlite+aiosqlite:///D:/CrisisMosaic/data/crisis_mosaic.db
DATA_DIR=D:/CrisisMosaic/data
STORAGE_ROOT=D:/CrisisMosaic/data/uploads
```

## 启动

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn crisis_mosaic.main:app --host 127.0.0.1 --port 8000 --workers 1
```

反向代理应负责 HTTPS、请求体上限和公网访问控制。不要启动第二个 worker 或第二个应用
实例；数据目录中的操作系统级锁会拒绝第二个运行进程，进程内写锁与 WebSocket 连接
中心也无法跨实例协调。

检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health/live
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health/ready
```

`ready` 将分别报告数据库和 AI。AI 未配置属于降级状态；数据库不可用会返回 503。

AI 提示词版本固定在代码中，运行时配置只选择模型、超时、JSON Schema 支持能力和
provider。分析状态接口会返回 `prompt_sha256`、token 用量、Schema 校验状态和引用校验
状态，便于审计同一模型在不同版本提示词下的输出。

## 媒体与 Kodo

旧 `/uploads/image-intents` 仍走本地代理图片链路。新版 `/uploads/media-intents` 默认
使用 `MEDIA_STORAGE_PROVIDER=qiniu_kodo_mock`。切换为 `qiniu_kodo` 时，后端使用七牛
标准算法签发短期上传 Token：策略限定 `bucket:object_key`、截止时间和防覆盖约束，策略
经 URL-safe Base64 后由 SK 做 HMAC-SHA1 签名，最终向客户端返回由 AK、签名和策略拼接
而成的 Token，以及对象 Key 和上传 Host。SK 不会出现在 API 响应、审计或日志中。

客户端创建媒体意图后的流程为：

1. `client_capabilities.resumable_upload=false`：图片和视频均获得 `KODO_FORM`，以响应中的
   `token`、`key` 和 `file` 字段向 `QINIU_UPLOAD_HOST` 发送流式 multipart。
2. `client_capabilities.resumable_upload=true`：图片和视频均获得 `KODO_RESUMABLE_V2`，并
   通过返回的会话入口维护分片检查点和续签。
3. 客户端直传完成后调用附件 `complete`；媒体处理就绪后，再用 `attachment_ids` 绑定上报
   或定向回答。文件字节不经过业务后端。

真实七牛接入时至少配置：

```dotenv
MEDIA_STORAGE_PROVIDER=qiniu_kodo
QINIU_ACCESS_KEY=...
QINIU_SECRET_KEY=...
QINIU_BUCKET=...
QINIU_UPLOAD_HOST=https://...
QINIU_PUBLIC_BASE_URL=https://...
QINIU_UPLOAD_TOKEN_TTL_SECONDS=600
```

应用启动时会拒绝缺少 AK、SK、bucket 或绝对 HTTPS `QINIU_UPLOAD_HOST` 的真实 provider
配置。`QINIU_PUBLIC_BASE_URL` 用于生成媒体访问地址；`QINIU_REGION` 当前不会自动推导
上传 Host，必须显式配置 bucket 所在区域对应的 Host。`QINIU_SECRET_KEY` 只允许留在后端
运行环境，不得写入客户端、日志、API 响应或仓库模板。

`QINIU_CALLBACK_URL` 是可选配置；设置后会写入上传策略，但本仓库当前没有七牛回调接收
路由，必须指向另行部署且可由七牛访问的接收端。当前 `complete` 不调用 Kodo Stat API
核实对象，远端媒体处理也没有完成真实恶意文件扫描、图片净化、视频转码和回调验收；当前
媒体访问 URL 还会附加 mock 签名，不具备生产级私有下载鉴权。视频默认保持
`ENABLE_VIDEO_UPLOAD=false`，只有在这些外部链路完成后才应开启：

```dotenv
ENABLE_VIDEO_UPLOAD=true
QINIU_CALLBACK_URL=https://your-callback.example/api/qiniu
```

上面的地址只是格式示例，不是本仓库提供的端点。真实上线验收至少应覆盖 bucket 写权限、
区域 Host、Token 过期、防覆盖、对象大小/MIME、回调重试和失败对象清理。

## Push 通知

指挥账号通过 `/api/v1/me/push-devices` 注册本 App 安装的 Push Token，通过
`/api/v1/me/notification-preferences/{incident_id}` 维护偏好。业务事务只写
`notification_outbox`；后台 worker 负责 Mock provider 投递和回执更新。

默认配置：

```dotenv
PUSH_NOTIFICATIONS_ENABLED=true
PUSH_PROVIDER_MODE=mock
PUSH_ALLOWED_APP_IDS=["com.srstudio.advx2team.crisismosaic"]
PUSH_ALLOWED_PROVIDERS=["fcm","apns","huawei","xiaomi","oppo","vivo","honor"]
```

真实 APNs、FCM 或厂商通道接入前，应补齐 provider 凭证、无效 Token 清理、错误码映射
和 Payload 扫描。Push Payload 只能包含通知 ID、业务事件 ID、资源引用、修订号和允许
scheme 的深链，不包含联系人、正文、精确地址、坐标、附件 URL 或认证 Token。

## 备份与恢复

一次一致的离线备份必须同时包含：

- `data/crisis_mosaic.db`
- `data/uploads/`
- 部署时使用的 `.env`（单独加密保管）

先停止服务，再复制整个 `data` 目录。WAL/SHM 文件仅是运行时文件，不应单独作为备份。
恢复时停止服务、还原数据库与上传目录、确认 `.env` 路径一致，再执行
`alembic upgrade head` 后启动。

可以用以下命令验证数据库完整性：

```powershell
python -c "import sqlite3; c=sqlite3.connect('data/crisis_mosaic.db'); print(c.execute('PRAGMA integrity_check').fetchone()[0])"
```

应输出 `ok`。

## 日志与监控

- 每个 HTTP 响应包含 `X-Request-Id`。
- 应用日志记录方法、路径、状态码、延迟和 request ID，不记录 Token、密码或 API Key。
- Prometheus 文本指标位于 `/api/v1/metrics`。
- 业务指标覆盖 HTTP 延迟/错误、幂等命中、实时连接/补发、Outbox/任务积压、AI 状态
  与延迟、冲突/盲区耗时、精确地图点数和事实版本。
- 审计 API：`GET /api/v1/incidents/{id}/audit-logs`。

## 故障排查

- `NO_ACTIVE_INCIDENT`：运行种子，或由管理员创建并启用事件。
- `AI_SERVICE_UNAVAILABLE`：检查 `AI_PROVIDER/AI_BASE_URL/AI_API_KEY`。
- `already has an active API process`：停止使用同一 `DATA_DIR` 的旧进程，并确保
  `--workers 1`。
- `database is locked`：确认没有长时间外部 SQLite 事务；应用自身写入已串行化。
- WebSocket `4409`：客户端游标超出 24 小时回放窗口，应重新拉取全量概览后重连。
