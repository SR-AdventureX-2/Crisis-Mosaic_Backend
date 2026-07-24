# 单机部署与运维

## 前置条件

- Windows 11 或 Windows Server，Python 3.12。
- 一个可写的本地数据目录。
- Windows Defender `MpCmdRun.exe`，或测试环境明确使用 fake scanner。
- OpenAI-compatible API Key（仅 AI 功能需要）。
- 真实 Kodo、FCM/APNs 或厂商 Push 凭证仅在接入生产通道时需要；默认使用 Mock。

不使用 Docker、Compose、Redis、Celery 或 PostGIS。默认媒体和 Push 使用 Mock，便于
单机联调；真实对象存储和 Push provider 仍需要独立凭证、回调和验收。

## 安装与升级

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
Copy-Item .env.example .env
alembic upgrade head
crisis-mosaic seed
```

已有 `.env` 时不要覆盖。部署升级前先备份数据库和上传目录，再执行：

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

`ready` 将分别报告数据库、图片扫描器和 AI。AI 未配置属于降级状态；数据库不可用会返回
503。扫描器不可用时图片处理失败关闭。

## Windows Defender

如果 `MpCmdRun.exe` 不在 PATH，设置：

```dotenv
MALWARE_SCANNER=windows_defender
DEFENDER_COMMAND=C:/Program Files/Windows Defender/MpCmdRun.exe
```

常规自动化测试设置 `MALWARE_SCANNER=fake`。`disabled` 不表示跳过扫描，而是使图片处理
返回不可用错误。

## 媒体与 Kodo

旧 `/uploads/image-intents` 仍走本地代理图片链路。新版 `/uploads/media-intents` 默认
使用 `MEDIA_STORAGE_PROVIDER=qiniu_kodo_mock`，返回短期 Upload Token、对象 Key、
上传 Host、策略快照和可恢复上传会话参数，文件字节不经过业务后端。

真实七牛接入时至少配置：

```dotenv
MEDIA_STORAGE_PROVIDER=qiniu_kodo
QINIU_ACCESS_KEY=...
QINIU_SECRET_KEY=...
QINIU_BUCKET=...
QINIU_UPLOAD_HOST=https://...
QINIU_PUBLIC_BASE_URL=https://...
QINIU_CALLBACK_URL=https://...
```

`QINIU_SECRET_KEY` 只允许留在后端运行环境；不得写入客户端、日志或 API 响应。视频默认
保持 `ENABLE_VIDEO_UPLOAD=false`，完成真实 Kodo 文件信息校验、扫描、转码和回调验收后
再开启。

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
- `MALWARE_SCANNER_UNAVAILABLE`：检查 Defender 路径和运行账号权限。
- `already has an active API process`：停止使用同一 `DATA_DIR` 的旧进程，并确保
  `--workers 1`。
- `database is locked`：确认没有长时间外部 SQLite 事务；应用自身写入已串行化。
- WebSocket `4409`：客户端游标超出 24 小时回放窗口，应重新拉取全量概览后重连。
