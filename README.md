# TokHive Verifier

独立的执行回执验证项目，提供 CLI 和网页两种 UI。两者共用 Go 验证核心；网页通过 WebAssembly 在浏览器 Web Worker 中验证，不上传本地回执、请求或响应文件。

## 功能

- 验证 canonical CBOR 格式、TEE 回执签名和签名公钥绑定。
- 复用 `tokhive/tee` 的验证库，检查 AWS SEV-SNP／NitroTPM 证据链、硬件策略和预期应用身份；拒绝 simulated 平台。
- 核对用户指定的应用哈希，以及可选的 policy hash、上游 host、执行 ID、最大回执年龄。
- 支持内嵌硬件证据和独立 evidence 文件两种回执形式。
- 可选核对原始响应的执行绑定哈希和字节数；支持 JSON 和 SSE 响应中的 model／usage 声明展示。
- 可选核对 `任务规格 → 请求体哈希 → 原始请求`，验证请求里的 model 等内容与回执的间接绑定。
- 支持回执文件入口，以及使用买家 API Key 按请求 ID 下载证据。多次执行尝试必须明确选择，不能将多份回执合成一次验证。
- 输出逐项检查、签名执行字段、内容核对范围；支持 JSON 报告下载和 CLI 退出码。

## 构建

需要 Go 1.27.3+、Make；Node.js 仅用于可选的 WASM 运行检查。当前开发依赖使用同级 `../tee` 仓库，因此目录应为：

```text
tokhive/
├── tee/
└── verifier/
```

```bash
cd /Users/panaw/Projects/tokhive/verifier
make build
./bin/tokhive-verify --help
```

`make build` 生成 `web/static/verifier.wasm` 和 Go 官方运行时，再将网页资源嵌入 CLI。最终二进制可单独分发，不需要用户安装 Go。生成资源不纳入版本管理。当前 WASM 因复用 TEE 的完整共享库约为 38 MiB，首次打开需加载；静态托管时建议启用 gzip／Brotli。

## CLI：文件验证

先从独立可信的发布来源取得完整应用身份，不能直接把回执自报的哈希当成预期值。

```bash
./bin/tokhive-verify verify \
  --expected-app "snp-app:<64位小写十六进制发布哈希>" \
  --expected-host api.anthropic.com \
  --response response.raw \
  receipt.cbor
```

若需核对输入：

```bash
./bin/tokhive-verify verify \
  --expected-app "$TOKHIVE_EXPECTED_APP" \
  --job-spec job-spec.cbor \
  --request request.raw \
  --response response.raw \
  --json \
  receipt.cbor
```

仅哈希回执可增加 `--evidence evidence.bin`。其他选项见 `verify --help`。所有选项放在回执路径之前。

## CLI：请求 ID 验证

在环境中设置买家 API Key，避免凭证出现在命令行参数／进程列表中：

```bash
# 将 TOKHIVE_API_KEY 设置为你自己的买家 API Key。
./bin/tokhive-verify verify \
  --request-id "$TOKHIVE_REQUEST_ID" \
  --expected-app "$TOKHIVE_EXPECTED_APP" \
  --json
```

默认访问 `https://api.tokhive.ai/v1/verification/requests/{id}`。`--api-base-url` 可指定 API origin；仅支持 HTTPS，本地联调允许 loopback HTTP。`--api-key-env` 可更改凭证变量名。需要多次尝试中的某一份回执时，增加 `--attempt-id <执行ID>`；若没有选择，CLI 列出可选 ID 后退出，不擅自挑选成功尝试。

可同时提供本地 `--request`、`--response`、`--job-spec` 或 `--evidence`。本地与远端同类证据冲突时拒绝验证。

公开接口的买家鉴权与归属校验由 Hive 实现，协议见 [API.md](API.md)。这里不使用管理员接口或管理员会话。接口需要随 Hive 发布部署后才能查询线上请求；没有证据或权限不足不会退回示例数据。

## 网页

```bash
./bin/tokhive-verify serve
# 本地 Hive 联调：
./bin/tokhive-verify serve --api-base-url http://127.0.0.1:5180
```

打开终端输出的 `http://127.0.0.1:8787`。选择「Receipt file」或「Request ID」，填入可信应用身份，再点击验证。

- 文件模式：文件留在浏览器内，验证引擎加载后可离线使用。
- 请求 ID 模式：买家 Key 仅用于本次向配置好的 Hive 下载证据。Key 不持久化、不放进 URL、不写入报告，下载完成后清空输入框。本机服务只代理这个固定来源的证据查询，不接受任意目标 URL。
- 原始请求／响应不会上传到本机服务或 Hive。
- 多次尝试会显示选择框；每份回执单独验证。结果包括通过／失败／跳过及补齐证据提示。
- 可导出 JSON 报告。修改输入会清除旧报告，避免把旧结论误认为新文件的结果。

网页静态资源可以单独托管，文件模式仍能工作；当前请求 ID 网页入口使用 `serve` 提供的本地桥接，以避免跨域配置和把 Key 发给任意来源。生产托管若需要该模式，应将同样受限的桥接部署在明确可信的 origin 下，不能直接公开当前仅供 loopback 的服务。

## 结果含义

| 状态 | 含义 | CLI 退出码 |
|---|---|---:|
| `verified` | 所有必要信任检查及已提供内容的核对均通过 | 0 |
| `failed` | 至少一项检查失败 | 1 |
| 使用／I/O／查询错误 | 参数错误、文件读取失败或证据下载失败 | 2 |
| `incomplete` | 没有失败，但缺必要的应用预期值、硬件证明或请求对应的任务规格 | 3 |

`verified` 不等于已核对所有内容：查看独立的 `request_verified`、`response_verified`。没有提供的内容不会标为通过。已签名的失败／截断执行仍可能有真实回执，报告中的 completion 和 HTTP 状态单独显示。

model 和 token 数是签名绑定内容中的声明：验证内容哈希后可确认它们未被改动，但验证器不独立识别厂商实际使用的模型，也不重新计算 token 数。非支持格式仍可核对完整字节，只是不提取声明字段。输入／输出 token 数以十进制字符串返回，避免 JavaScript 丢失大整数精度。

## 当前证据范围

- 只支持 AWS SEV-SNP 回执；硬件证书按当前时间检查，过期链拒绝。尚不支持带可信历史时间戳的归档证明。
- 请求 ID 与执行 ID 的映射来自已鉴权 Hive API，该买家请求 ID 本身不是 TEE 签名字段。
- API 不发布可信版本清单；预期应用哈希必须由使用者从可信发布来源提供。
- Hive 当前保存回执与任务哈希，未归档完整任务规格和原始上游正文。请求 ID 下载的回执可验证，但输入核对还需单独取得完整规格和原始请求；不能用账单 metadata 代替。
- 响应必须是 TEE 实际转发的上游正文。Hive 的协议转换、压缩解压或历史恢复可能改变请求／响应字节；客户端看到的正文不一定等于 TEE 签名内容，不能通过重新序列化 JSON 强行匹配。
- 文件上限：receipt／job spec 2 MiB、evidence 4 MiB、request 16 MiB、response 64 MiB。

## 检查

```bash
make test
make build
go run scripts/make-demo.go /tmp/tokhive-verifier-demo
node scripts/check-wasm.cjs /tmp/tokhive-verifier-demo
```

demo 使用软件密钥签名，故意没有真实硬件证明，正确结果是硬件验证失败；不能将其当作成功示例。单元测试通过私有测试 seam 验证成功路径的组合逻辑；公开 API 始终调用真实硬件验证库，没有跳过硬件检查的开关。真实生产回执的成功验收仍需要一份有效的、未过期的硬件证明及可信应用身份。

## 目录

```text
verify.go, content.go     共用验证核心与内容绑定
lookup/                  普通买家证据查询客户端
cmd/tokhive-verify/       CLI 入口
cmd/wasm/                相同核心的 WebAssembly 入口
internal/cli/            CLI 命令、本机静态 UI 与受限查询桥接
web/static/              网页、Web Worker 和构建后的 WASM
scripts/                 验证引擎一致性检查与拒绝示例生成器
```
