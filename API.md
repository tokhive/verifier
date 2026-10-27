# 普通买家证据查询协议 v1

## 查询

```http
GET /v1/verification/requests/{request_id}
Authorization: Bearer <buyer-api-key>
Accept: application/json
```

公开 API 指普通客户端可调用，不代表匿名访问。只接受有效、未撤销的买家 API Key；按买家身份限制为自己的请求，同一买家的其他有效 Key 也可读取。无需管理员会话，不要求余额大于零，不触发新的推理或结算。

返回：

```json
{
  "version": 1,
  "request_id": "<买家请求ID>",
  "attempts": [
    {
      "id": "<32位小写十六进制执行ID>",
      "receipt_sha256": "<64位小写十六进制SHA-256>",
      "receipt": "<原始canonical-CBOR回执的base64>",
      "evidence": "<可选：匹配回执evidence_hash的证据base64>",
      "job_spec": "<可选：匹配回执job_spec_hash的完整canonical-CBOR任务规格base64>"
    }
  ]
}
```

当前 Hive 实现返回 `id`、`receipt_sha256` 和原始 `receipt`。生产回执已内嵌硬件证明，客户端从回执中读取。可选的 `evidence`、`job_spec` 为协议扩展能力，不代表 Hive 已经归档这些外置文件。

不返回 API Key、供应方邮箱、计费 usage、价格或原始请求／响应正文，不返回可替代客户端验证的 `verified` 布尔值。原始回执不可删改，因此其中已经签名的供应方标识、上游路径等字段会交给该请求的买家；这是新增的买家证据读取权限，不是匿名数据发布。

一次买家请求可以有多次执行尝试。返回已有原始回执的尝试，包含签名的失败执行；不能只返回成功尝试而隐藏已签名失败。客户端必须逐份验证，不能把多个哈希或 usage 累加成一份证明。

## 客户端检查

1. HTTPS 及买家 API Key 鉴权，拒绝重定向；本地联调可使用 loopback HTTP。
2. 检查协议版本和返回 request ID 与查询一致；限制最多 32 份回执及 24 MiB JSON 包。
3. 检查每份 receipt SHA-256、签名和执行 ID 与 attempt ID 一致。
4. 用使用者自己的可信应用身份与内置 AMD／AWS 根证书执行完整验证。
5. 如提供本地请求／响应，独立计算哈希核对。将 model／usage 标为绑定内容中的声明，不以账单字段代替。

买家请求 ID 不是 TEE 回执字段，`request ID → attempt ID` 关系由 Hive 负责；请求 ID 查询不能消除这部分对 Hive 的信任。应用哈希不能从同一查询结果自动设为可信值。

## 错误与缓存

| HTTP | 含义 |
|---|---|
| 401 | 缺少、无效或已撤销的买家 API Key |
| 404 | 请求不存在或不属于该买家；不区分这两种情况 |
| 409 | 请求存在但尚无可下载的执行回执 |
| 429 | 查询限流 |
| 503 | 存储暂不可用、归档损坏或证据包过大 |

响应使用 `Cache-Control: no-store`，内容不得被共享缓存；凭证只在 Authorization header 传输，不得出现在 URL、访问日志或验证报告中。
