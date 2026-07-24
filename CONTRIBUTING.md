# 本地贡献指南

## 环境

使用 Python 3.12 和 PowerShell：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
alembic upgrade head
python -m pytest
```

不要提交 `.env`、SQLite 文件、WAL/SHM、上传内容或虚拟环境。

## 目录

- `src/crisis_mosaic/routers/`：HTTP 路由和权限边界。
- `src/crisis_mosaic/schemas/`：Pydantic 请求、响应和实时 JSON Schema。
- `src/crisis_mosaic/services/`：事务内业务服务、AI 和图片处理。
- `src/crisis_mosaic/domain/`：坐标、优先级等纯领域规则。
- `src/crisis_mosaic/models.py`：SQLAlchemy 数据模型。
- `src/crisis_mosaic/workers.py`：持久任务和 Outbox。
- `migrations/`：Alembic 迁移。
- `tests/`：与源码领域对应的单元/集成测试。

## 代码要求

- 四空格缩进，公共边界添加类型提示。
- 模块与函数使用 `snake_case`，类使用 `PascalCase`。
- API 成功响应使用 `responses.success`，业务错误使用 `ApiError`。
- 事件内请求必须校验 Token 权限、路径 ID 和 `X-Incident-Id`。
- 写事务必须使用共享 `write_lock`，并保持短小。
- 创建接口应支持 `Idempotency-Key`；更新接口使用 revision CAS。
- 禁止记录凭据、原始 Token、安装 ID 或敏感精确设备标识。
- 外部 AI 和网络服务必须在测试中替换为 fake/mock。

## 数据库变更

修改模型后生成迁移：

```powershell
alembic revision --autogenerate -m "Describe schema change"
alembic upgrade head
alembic check
```

检查自动生成内容，并保留 SQLite batch mode。迁移必须支持从空库升级，也要验证重复
`upgrade head` 不产生变更。

## 提交前验证

```powershell
python -m pytest
python -m ruff check src tests migrations
python -m mypy src\crisis_mosaic
python -m compileall -q src tests
alembic check
git diff --check
git status --short
```

行为变更和回归修复必须带测试。仓库没有覆盖率门槛，不要声称一个未配置的阈值。

提交主题使用简短祈使句，例如 `Add incident ingestion endpoint`。每个提交只包含一个逻辑
变更；除非用户明确要求，不要自动推送或发布。
