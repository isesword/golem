# golem 架构宪法（ARCHITECTURE.md）

本文档定义 golem 的分层不变量。**任何改动违反本文档的分层边界即架构回退**，
需要先修改本文档并说明理由。

## 分层图

```
┌─────────────────────────────────────────────────────────────┐
│ 上层（消费者，永不感知平台/CPU引擎差异）                        │
│   emulator / dvm / loader / kernel / vfs / Pool[T]           │
│   TrainApp 的 apseemu、mpaasrpc、未来的业务层                  │
├─────────────────────────────────────────────────────────────┤
│ emu 层（平台与引擎差异的唯一容身处）                            │
│   emu.Backend 接口（唯一契约，方法数以 backend.go 为准）       │
│   registry.go        引擎选择/平台感知（Windows 缺引擎→明确报错）│
│   unicorn_purego.go  POSIX 引擎（darwin/linux，已验证）        │
│   winengine/（规划）  Windows 引擎：CreateThread C 服务线程     │
│                      + 命令泵 + 回调事件回传                    │
└─────────────────────────────────────────────────────────────┘
```

## 不变量（逐条可测）

1. **上层只 import `emu.Backend` 接口，绝不 import purego/unicorn/C 绑定。**
   验证：`grep -rn "purego" emulator/ dvm/ internal/kernel/ internal/loader/`
   必须为空。当前已满足（32 处引用全部经由接口）。

2. **`emu.Backend` 是唯一契约。** 新平台 = 新 Backend 实现 + registry 注册，
   上层零改动。Windows 引擎（无论 C 线程泵还是预提交 patch）全部实现在
   `internal/emu` 包内。

3. **Windows 引擎级难题在 emu 层终结 —— 但解法尚未选定（2026-09-27 状态：待验证）。**
   已确认的背景（unicorn2 devblog、unicorn setjmp/longjmp devblog、golang/go#57050）：
   VEH 是 unicorn 内部 TCG 缓冲的按需提交机制；Go 运行时也安装 Windows 异常
   处理器，冲突点尚未用最小复现钉死。

   **待验证决策（禁止当作已定方案引用）：**
   - [ ] Windows 最小复现程序：原生 uc_open→map→execute、小 TCG buffer、
         预提交、hook 回调、callback 内反调 backend——固定版本收集崩溃栈，
         先钉死真实冲突点；
   - [ ] 若预提交可解，优先 Unicorn 分配路径 patch（注意：调小 buffer ≠
         预提交，首次写入仍触发提交异常；64MiB 是否够需按指令缓存实测）；
   - [ ] 若需 C 服务线程：**同步回调协议是关键未解问题**——现有 Backend 的
         hook 是同步的（hook 内可 RegRead/MemWrite/Stop，我们的测试与
         demand-map 都依赖此语义），C 线程方案必须提供可重入的请求/响应
         协议，或改为 Go 回调返回操作列表由 C 线程执行；golang/go#9240 只
         证明"纯 C 入口的线程合法"，不证明回调可从该线程直接进 Go；
         逐指令 trace 的事件吞吐需实测；
   - [ ] Windows 可用 cgo 时，复用 cgo fork 已验证的服务线程方案优于从零
         写 purego+命令泵；CGO_ENABLED=0 硬约束时，C DLL 预编译/版本锁定/
         分发纳入方案；
   - 上层永不出现 `GOOS == "windows"` 分支判断引擎能力——这条**已定**：
         能力差异只能表现为 Backend 接口的方法或注册与否。

   **registry 现状**：Windows 平台化错误指引尚未实现（registry.go 仅有
   注释占位）——落地 winengine 或明确放弃时一并实现。

4. **错误语义（388b76c 确立）：** 内存分配可恢复错误走 error 返回 +
   `Space.RollbackLast` 事务；不可验证的状态转换走 poison；
   ReplaceE 五步事务（privatize→存原指令→补丁→flush→注册）。
   后端实现必须满足三态契约（见 emulator/fakebe_test.go）。

5. **JNI 引用生命周期按 ART 语义（Phase A 确立）：** local 帧随调用回收、
   global 显式且值稳定、句柄单调不复用、stale 大声失败。兼容旋钮禁止。

6. **快照/Restore 只持久化确定性状态**（globals、地址空间布局、kernel 状态）；
   缓存类状态（classRefs）必须随 Restore 失效。

7. **性能契约：** 长生命周期引擎稳态 O(1)（arena 池 + 帧池 + 引用两域表）；
   共享只读页跨引擎一次物理驻留（loader Plan 缓存 + uc_mem_map_ptr）。

## 平台支持矩阵（随实现更新）

| 平台 | 编译 | 引擎运行 | 实现路径 |
|---|---|---|---|
| linux amd64/arm64 | ✅ CI | ✅ CI 实弹 | unicorn_purego |
| darwin amd64/arm64 | ✅ CI | ✅ 本机验证（e2e 1000） | unicorn_purego |
| windows amd64/arm64 | ✅ CI | **未验证**（先做最小复现，再选预提交或 C 线程） | 待验证决策，见上 |
| （全部平台兜底） | — | WSL2 / 进程外签名服务 | 部署形态，上层零改动 |

## 改动判据

- 给上层加功能：只许动 emulator/dvm/loader/kernel/vfs 的公开 API；
- 换/加 CPU 引擎：只许在 internal/emu 加文件并 Register；
- 加平台：只许加 Backend 实现 + registry 候选 + CI 矩阵行；
- 任何 PR 触碰以上边界之外的平台细节 = 设计错误。

## 宪法修订规则

已验证的机制（Phase A 引用生命周期、388b76c 错误语义、Phase B 共享页）
写为不变量；**未验证的设计假设只允许以"待验证决策"清单形式存在**，禁止
写成"已定方案"——原型失败时必须保留修改 Backend 契约或采用平台专用实现
的空间。把假设升级为不变量的唯一途径：原型实测通过 + 本文档修订。
