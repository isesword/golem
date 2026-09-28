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
│   emu.Backend 接口（15 方法，唯一契约）                        │
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

3. **Windows 引擎级难题在 emu 层终结，且一次性解决：**
   - unicorn 的 VEH 惰性提交与 Go 运行时异常处理器的冲突（调研结论见
     git log 与项目记忆：unicorn2 devblog 实证 VEH 是 unicorn 内部 TCG
     缓冲的按需提交机制；golang/go#9240 确认入口为纯 C 的 CreateThread
     合法；unicorn 自带 setjmp wrapper 处理 MSVC 展开差异）；
   - 解法容器化在 winengine 子包内：C 服务线程 + 命令泵 + 回调事件回传，
     TCG 缓冲预提交（上游 patch/构建开关，默认调小）作双保险；
   - 上层永不出现 `GOOS == "windows"` 之外的分支条件判断引擎能力——
     能力差异只能表现为 Backend 接口的方法或注册与否。

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
| windows amd64/arm64 | ✅ CI | 规划：winengine | CreateThread C 线程泵 |
| （全部平台兜底） | — | WSL2 / 进程外签名服务 | 部署形态，上层零改动 |

## 改动判据

- 给上层加功能：只许动 emulator/dvm/loader/kernel/vfs 的公开 API；
- 换/加 CPU 引擎：只许在 internal/emu 加文件并 Register；
- 加平台：只许加 Backend 实现 + registry 候选 + CI 矩阵行；
- 任何 PR 触碰以上边界之外的平台细节 = 设计错误。
