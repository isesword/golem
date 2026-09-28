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
│   windows 构建路径  unicorn.dll(预提交,PR #2364)+UC_CTL_UC_PREALLOC│
└─────────────────────────────────────────────────────────────┘
```

## 不变量（逐条可测）

1. **上层只 import `emu.Backend` 接口，绝不 import purego/unicorn/C 绑定。**
   验证：`grep -rn "purego" emulator/ dvm/ internal/kernel/ internal/loader/`
   必须为空。当前已满足（32 处引用全部经由接口）。

2. **`emu.Backend` 是唯一契约。** 新平台 = 新 Backend 实现 + registry 注册，
   上层零改动。Windows 引擎路径（上游预提交方案）全部实现在 `internal/emu`
   包内。

3. **Windows 引擎级难题在 emu 层终结。选定路线（2026-09-27 二轮调研定案）：上游预提交，**
   **放弃 C 服务线程方案。**

   **机制背景（已核实）：** unicorn 在 Windows 上对 `VirtualAlloc(MEM_RESERVE)` 的
   TCG 代码缓冲注册 `AddVectoredExceptionHandler(1, ...)` 惰性提交（unicorn2
   devblog）。VEH 是进程全局机制——Go 运行时启动时同样注册 first-priority VEH
   （`runtime/signal_windows.go`），对非 Go 信号按致命崩溃处理（golang/go#56082，
   至今 open；#56080 已由 CL 442896 部分修复，仅限 windows/arm64 非 Go 线程）。
   **线程归属与异常处理器链无关——任何 C 服务线程/命令泵方案都不消除该冲突**
   （且纯 C 线程的同步 hook 回调协议不可行：hook 必须能在未返回时反调 backend，
   而 go#9240 只保证纯 C 入口线程的创建合法，回调进 Go 无承诺）。C 线程泵
   方案自 2026-09-27 起从本架构删除。

   **选定方案 = unicorn 上游 PR #2364（wtdcode，2026-07 合入 dev）**：
   - 编译期 `-DWIN32_ENABLE_VEH=OFF`：编译掉 VEH，预分配成为强制；
   - 运行期 `UC_CTL_UC_PREALLOC`（write-only, int，**须在首次 uc_emu_start
     前设置**；仅 Windows+VEH 构建有意义，POSIX 返回 UC_ERR_ARG）：
     整个 TCG 缓冲 upfront 提交，"avoids installing a process-global
     vectored exception handler"；
   - 附带修复 unicorn 自身的 VEH 并发不可靠问题（#2264）；
   - 佐证：unidbg 在 Windows 量产分发 unicorn.dll 无 VEH 问题——坑在 Go
     侧的 VEH 优先级，unicorn.dll 本身可工作。

   **实施状态（2026-09-28）：**
   - [x] CI（win-dll workflow）从 unicorn 锁定 commit（938efd1）以
         `-DWIN32_ENABLE_VEH=OFF` 构建 unicorn.dll，artifact+provenance 分发；
   - [x] `unicorn_purego.go` build tag 放宽到 windows；`dlopenUnicorn`
         候选加 `unicorn.dll`；`uc_open` 后补 `UC_CTL_UC_PREALLOC=1`
         （值 19，经 dev 头文件核实；UC_ERR_ARG 容忍）；
   - [x] **Windows runner 上全套 fakebe/engine 测试 + CLI 实弹验收通过**
         （dvm 引用生命周期 15 测、privatize 三态、Pool 七态、ELF/syscall/
         hook 集成——VEH 消除实证完成）；
   - [x] TCG buffer 经 `UC_CTL_TCG_BUFFER_SIZE` 定值（2026-09-28 定案）：
         Windows+PREALLOC 下引擎默认 16 MiB（实测：16 MiB 即达吞吐平台期，
         256 MiB+ 反降 30-40%），POSIX 下引擎不管（惰性提交）；用户经
         `emulator.Config.TCGBufferMiB` 在构造期覆盖（boot 前应用，
         非 unicorn 引擎显式报错而非静默忽略）；实测工具 `cmd/tcgsizing`；
   - [ ] windows/arm64 DLL 实弹验证：win-dll workflow 已构建 arm64 DLL
         （fork = dev + PR #2286），但引擎测试仅在 amd64 runner 上跑——
         待 windows-11-arm runner 上加 smoke job 闭环。

   上层永不出现 `GOOS == "windows"` 分支判断引擎能力——**已定**：
   能力差异只能表现为 Backend 接口的方法或注册与否。

   **registry 现状**：`registry.go` 已实现引擎选择（显式参数 /
   `$GOLEM_ENGINE` / 默认序）与可操作的错误指引（请求了未编译的引擎时报
   "rebuild with -tags ..."）；Windows 缺 DLL 时的定位指引在
   `dlopenUnicorn` 的候选列表错误里。

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

8. **引擎能力差异经 `emu.ErrUnsupported` 哨兵表达，上层不做引擎名分支。**
   后端对不支持的操作返回包装该哨兵的错误；上层用 `errors.Is` 判定并包装成
   含引擎名的友好错误。禁止 `if engine != "unicorn"` 式字符串门控——能力
   探测走接口调用，不走名字。

## 平台支持矩阵（随实现更新）

| 平台 | 编译 | 引擎运行 | 实现路径 |
|---|---|---|---|
| linux amd64/arm64 | ✅ CI | ✅ CI 实弹 | unicorn_purego |
| darwin amd64/arm64 | ✅ CI | ✅ 本机验证（e2e 1000） | unicorn_purego |
| windows amd64 | ✅ CI | ✅ **CI 实弹全套绿**（VEH-off DLL + PREALLOC，win-dll workflow） | unicorn_purego + 版本锁定 unicorn.dll（unicorn@938efd1，WIN32_ENABLE_VEH=OFF） |
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
