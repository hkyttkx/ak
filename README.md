# AK Vercel Server

这是将现有 FastAPI `route=a` / `route=k` 服务包装成 Vercel Python Function 的部署版本。

## 部署

1. 把整个目录上传到 GitHub 仓库。
2. 在 Vercel 中 Import 该 GitHub 仓库。
3. Framework Preset 保持自动检测即可。
4. 不需要填写 Build Command。
5. Deploy。

## route=a

入口保持：

`POST /4.1/index.php?__route=a`

Vercel rewrite 会将其转给 `api/index.py`。

当前实现保持已有协议代码：

- AES-256-CBC / 固定 IV
- 动态 request seed
- `sing = MD5(appid + time + langegeqq1587820860)`
- `H` 按原协议作为请求字段使用，不自行推导
- `haxi = RC4("M?C@x1B9" + cnm, H) + nibble-swap + hex`
- `+W-xD=` HMAC-SHA256
- 动态 HMAC key/value
- 动态 response seed

## 可选环境变量

`ROUTE_A_REQUEST_SKEW_MINUTES` 默认 `120`。

route=k 如需上游卡密接口，再配置：

- `ERUYI_API_URL`
- `ERUYI_APP_NAME`
- `ERUYI_TIMEOUT_SECONDS`

## 健康检查

部署后访问 `/health`。
