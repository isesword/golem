**简体中文** | [English](README.en.md)

# golem

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

golem 是一个用纯 Go 编写的多平台 native 库模拟框架:在本机加载一个 Android AArch64 native 库(`.so`),不借助 JVM、真机或 Android 系统就能直接调用里面的函数。它给这个 `.so` 搭出一套够用的 Android 进程环境(动态链接器、真实的 bionic libc、一部分 Linux 系统调用、按 JNI 规范实现引用生命周期的 JavaVM),你就能从 Go 里调它的导出函数、读写它的内存、观察它的每条指令。

CPU 引擎通过接口抽象解耦,内置 [Unicorn](https://www.unicorn-engine.org/) 后端——用 [purego](https://github.com/ebitengine/purego) 在运行时 `dlopen` 原版 libunicorn,**构建期零 cgo**(`CGO_ENABLED=0` 即可构建,无需 C 编译器、无自编 shim 库)。Android 先行;iOS(Mach-O)与多架构在路线图上。

```go
e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so"})
defer e.Close()
sum, _ := e.CallSymbol("add", 2, 3) // -> 5,作为真实 AArch64 代码执行
```

> 当前状态:Unicorn(purego)后端完整跑通——加载并链接 bionic 和目标 `.so`、执行 `init_array` 与 `JNI_OnLoad`、调用导出函数、处理 syscall 与 JNI;引擎池支持多 goroutine 并发;常驻负载实测 10 万次签名 @ 100 QPS 延迟恒定、内存零增长。Linux / macOS / Windows(amd64 与 arm64)CI 实弹全绿——Windows 使用 CI 构建并经真机验证的 VEH-off unicorn.dll,随仓库分发。与 unidbg 的能力对照见 [与 unidbg 的关系](#与-unidbg-的关系)。

---

## 架构

分层不变量、平台支持矩阵与改动判据见 [ARCHITECTURE.md](ARCHITECTURE.md)——上层（emulator/dvm/loader/kernel/vfs 及一切消费者）只依赖 `emu.Backend` 接口，平台与 CPU 引擎差异全部封死在 `internal/emu` 层。

## 为什么

unidbg 是这个领域的事实标准,但它跑在 JVM 上,依赖偏重,且它的 JNI 引用表不回收(`DeleteLocalRef` 是空操作)、面向交互式分析而非常驻服务。golem 用 Go 重做了核心部分,并把**生产级长跑**作为一等公民:

- 不需要 JVM,也不需要 C 工具链。编译产物就是单个 Go 二进制(`CGO_ENABLED=0`),交叉编译就是原生 `go build`。
- 引擎可换。CPU 引擎藏在 `emu.Backend` 接口之后,Unicorn(purego 运行时 `dlopen`,GPLv2 留在库边界之外)作为内置默认。
- 复用真实 bionic。直接加载并模拟执行 AOSP sysroot 里的 `libc/libm/libdl`,省得自己重写一套 libc。
- **为常驻负载设计**:JNI 引用按规范回收(local ref 随调用帧消亡)、编译/实例化分离让引擎池共享只读页、引擎池带自动回收与故障重建。
- **诚实的失败语义**:内存/hook 操作错误返回或事务回滚;不可恢复的状态迁移会让模拟器进入 poison 态,后续调用明确拒绝,绝不"假装健康"。

## 特性

- AArch64 ELF 加载与动态链接(`RELATIVE` / `JUMP_SLOT` / `GLOB_DAT` / `ABS64`),`DT_INIT` + `init_array`。
- 复用真实 bionic `libc/libm/libdl`(内置 AOSP sdk23 sysroot),支持跨模块符号解析。
- Linux/AArch64 系统调用子集(mmap/mprotect/openat/read/write/clock_gettime/getrandom/futex/…),配一套小型虚拟文件系统(`/system/lib64`、`/proc/self/*`、属性、tzdata)。
- JNI/JavaVM:guest 的 `JNIEnv`/`JavaVM` 调用会陷回到你用 Go 实现的处理器(`FindClass`、`GetMethodID`、`Call*Method*`、`RegisterNatives`、字符串、字节数组等)。
- 按符号名或按模块偏移调用 native 函数,最多 8 个整型参数,可读取返回值。
- 用 Go 回调替换 native 函数(`ReplaceE` 事务化入口补丁,失败恢复原指令),或**内联 hook**(`HookAddr`,逐指令,Unicorn)改寄存器 / 重定向 PC;写内存的路径自动刷新代码缓存。
- **控制台调试器**:断点 / 单步 / 寄存器 / 内存(Unicorn,I/O 可注入便于脚本化)。
- 从 **classes.dex 加载真实类/方法/字段元数据**(`Config.Android.DexPath` / `LoadDex`):FindClass/GetMethodID/GetFieldID 按真实签名、父类解析(仅元数据,不执行字节码)。
- 内存助手:分配、读写字节、C 字符串、小端整数。
- 单指令 trace;以及完整指令流 trace(`TraceInsns`:每条指令的偏移 + 指令码 + 寄存器增量 + 调用/系统调用注解,Tenet 风格,可与真机 trace 对比;Unicorn)。
- 引擎可选:`-tags unicorn` 编入 purego 后端,运行期用 `-engine` / `$GOLEM_ENGINE` 选择。
- TCG 翻译缓存可调:`Config.TCGBufferMiB`(构造期生效;Windows 预提交模式下默认 16 MiB,由 `cmd/tcgsizing` 实测定值)。
- **JNI 引用生命周期按规范实现**:local ref 住在池化的调用帧里(随调用消亡,宿主读返回值有一拍宽限)、global ref 显式且句柄值稳定、句柄单调永不复用(陈旧句柄解析为 nil,绝不静默别名)。稳态内存 O(单次调用的对象数),长跑不涨。
- **引擎池(`emulator.Pool`)**:actor 模式——一个引擎同一时刻归一个 goroutine,并发靠堆引擎数而非锁;按 MaxUses 自动回收、panic 自动重建、池耗尽时 ctx deadline 生效。这是 golem 并发故事的核心:**guest 内部多线程**是引擎内的协作式调度,而 **N 个 goroutine 的并发请求**由 N 个引擎真并行承载(单核约 70 QPS,实测 12 核机 ~510 QPS)。
- **编译/实例化分离**:每个 `.so` 只解析一次(`loader.CompileOnce`),只读段经 `uc_mem_map_ptr` 零拷贝共享——N 个引擎的只读页在物理内存里只有一份(10 引擎实测 maxRSS -20%);宿主打补丁前自动私有化,绝不污染其他引擎。
- **错误语义**:分配返回 error(底层映射失败自动回滚地址空间簿记)、`ReplaceE` 五步事务(失败恢复原指令)、不可验证的状态迁移触发 poison 并拒绝后续调用。

## 快速开始

### 前置条件

- Go 1.26+
- 一个 CPU 引擎:Unicorn(默认)。构建**无需任何 C 编译器**;运行期需要 libunicorn——macOS/Linux 用系统安装(`brew install unicorn` / `apt install libunicorn2`)或 `$GOLEM_UNICORN` 指定路径;**Windows 无需安装**,CI 构建的 VEH-off `unicorn.dll` 随仓库在 `assets/windows/<arch>/` 下分发,开箱即用。详见 [BUILD.md](BUILD.md)。

### 构建并运行示例

```bash
# 纯 Go 构建,无 cgo、无 zig(Linux / macOS / Windows)
CGO_ENABLED=0 go build -tags unicorn -o bin/golem ./cmd/golem

# 运行(系统装有 libunicorn 时无需任何环境变量;找不到再用 GOLEM_UNICORN 指路)
./bin/golem examples/native/native.so fib 20                  # fib([20]) = 6765
# macOS 手动安装的 unicorn:GOLEM_UNICORN=$(brew --prefix unicorn)/lib/libunicorn.dylib
# Linux: apt install libunicorn2 即在默认搜索路径上
# Windows: 无需安装,自动使用 assets/windows/<arch>/unicorn.dll(VEH-off 构建)
```

完整演示(加载内置 `native.so`,调用导出函数、一个被 import 的 `strlen`、一个写指针的函数,以及一个 Go `Replace` hook):

```bash
CGO_ENABLED=0 go run -tags unicorn ./examples/run   # 运行期需能找到 libunicorn(见 BUILD.md)
# engine: unicorn
# add(2, 3)      = 5
# fib(20)        = 6765
# slen(...)      = 14
# sum_into -> *out = 42
# add(2, 3) after Replace = 23  (Go hook: a*10+b)
```

## 作为库使用

```go
import "github.com/isesword/golem/emulator"

e, err := emulator.New(emulator.Config{
    SOPath:    "libfoo.so",        // 启动时加载并跑 init_array + JNI_OnLoad
    AssetRoot: emulator.AssetsDir(), // 内置 bionic sysroot(按编译期路径自定位;可用 $GOLEM_ASSETS 覆盖)
    Engine:    "",                 // "unicorn" | "" = 自动
})
if err != nil { panic(err) }
defer e.Close()

// 按名调用导出函数(最多 8 个整型/指针参数,返回 X0)。
r, _ := e.CallSymbol("add", 2, 3)

// 按模块偏移调用非导出入口(= unidbg 的 callFunction(offset))。
r, _ = e.CallOffset(nil /*主模块*/, 0x1234, argPtr)

// 交换内存。
p := e.WriteCStringAlloc("hello")
n, _ := e.CallSymbol("strlen_wrapper", p)
out, err := e.Malloc(4)
if err != nil { panic(err) }
_, _ = e.CallSymbol("sum_into", out, 20, 22)
v, _ := e.ReadU32(out)

// 用 Go 替换一个 native 函数(hook)。ReplaceE 返回 error; ReplaceSymbol 同。
err = e.ReplaceSymbol("add", func(h *emulator.Hook) uint64 { return h.Arg(0) + h.Arg(1) })
```

### 给 Java 侧建模(JNI)

native 库会通过 JNI 回调 Java。实现 `dvm.Jni`(或 embed `dvm.AbstractJni`,只重写你的库会用到的那几个方法),再传进 `Config.Android.JNI`:

```go
type MyJni struct{ dvm.AbstractJni }

func (MyJni) CallStaticObjectMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) *dvm.Object {
    if sig == "com/example/App->token()Ljava/lang/String;" {
        return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: "secret"}
    }
    return nil
}

e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so", Android: emulator.AndroidConfig{JNI: MyJni{}}})
```

这就是 unidbg 里 `AbstractJni` 的用法:guest 的 `RegisterNatives`/`GetMethodID`/`Call*Method` 会按 `"类->方法(签名)"` 这样的字符串路由到你的 switch。

> 真实案例见 [`examples/douyin`](examples/douyin):用上面这套通用 API,在一个生产级混淆 `.so` 上复现请求签名头(该 `.so` 是第三方专有文件,不随仓库分发,需要自备)。

## CPU 引擎

| 引擎 | 构建标签 | 链接方式 | 速度(热路径,实测) | 许可证 |
|---|---|---|---|---|
| **Unicorn2** | `-tags unicorn` | purego 运行时 `dlopen` libunicorn | p50 ≈ 14–15 ms/次(10 万签 @100 QPS 实测) | GPLv2 |

- 当前内置 Unicorn 后端;接口(`emu.Backend`)与注册表机制保留了多引擎扩展点(如 dynarmic JIT)。
- 每个引擎首次调用要花几百毫秒(预热),之后复用同一引擎就很快;多引擎用 `emulator.Pool` 预热一组并发服务。
- 许可证提示:Unicorn 是 GPLv2,静态链接它会让整个二进制都变成 GPLv2,所以 golem 把它放在运行时 `dlopen` 的边界之后——purego 后端延续了这一设计。

## 工作原理

`emulator.New` 对照 unidbg `Emulator` 的启动流程:

1. 地址空间:铺好 guest 栈、TLS(`TPIDR_EL0` 加一个 `pthread_internal_t`)和 SVC 跳板区,并选定 CPU 后端。
2. 加载与链接:每个 `.so` 只解析一次并生成 Plan(`loader.CompileOnce`),各引擎按 Plan 实例化——只读段经 `uc_mem_map_ptr` 零拷贝共享,可写段匿名私有,重定位按引擎符号解析;未解析到的 import 指向 `svc` 跳板,陷回 Go。
3. 初始化:跑 `DT_INIT` 和 `init_array`,如果导出了 `JNI_OnLoad` 也一并调用(传入合成的 `JavaVM`)。
4. 调用:`CallSymbol`/`CallOffset` 把参数写进 `X0..X7`,把 `LR` 设成哨兵地址,然后一直跑到返回。SVC 陷入之后再分派给 syscall 层(`internal/kernel`)、JNI 层,或某个用 Go 实现的 libc 函数、被 Replace 的函数。

guest 的内存和寄存器通过 `Backend` 接口交换,Unicorn purego 后端实现了这个接口(运行时 `dlopen` 的 libunicorn 直接读写宿主侧映射的 guest 内存)。

### 目录结构

```
golem/
├── emulator/     公开 API:New、LoadLibrary、CallSymbol/CallOffset、ReplaceE、Pool、内存助手
├── dvm/          公开:假 Dalvik VM —— VM(JNI 规范引用生命周期)、Object、Class、Jni、AbstractJni、VaList
├── internal/
│   ├── emu/      CPU 后端接口 + 注册表;unicorn 后端(purego 运行时加载 libunicorn)
│   ├── loader/   ELF 解析 + 动态链接器 + Plan(编译/实例化分离、共享只读页)
│   ├── kernel/   AArch64 Linux 系统调用子集
│   ├── memory/   guest 地址空间分配器
│   └── vfs/      guest 虚拟文件系统(/system/lib64、/proc/self、属性、tzdata)
├── cmd/
│   ├── golem/  CLI:加载 .so 并调用某个符号
│   ├── elfscan/  分析 .so(导入/导出/init)
│   ├── loadplan/ 重定位直方图 / 链接复杂度
│   ├── bsmoke/   引擎自检
│   └── tcgsizing/ TCG 缓存尺寸实测曲线(吞吐/延迟/RSS)
├── examples/
│   ├── native/   一个自建的小 AArch64 .so(源码 + 预编译),供示例 + 测试用
│   └── douyin/   真实案例:在一个生产 .so 上复现签名(.so 需自备,不入库)
└── assets/android/sdk23/  内置 AOSP bionic sysroot(见 NOTICE)
```

## 与 unidbg 的关系

golem 的精神前身是 [unidbg](https://github.com/zhkl0228/unidbg)——加载/链接/bionic 复用/JNI 陷回这套骨架一脉相承,一并致谢。以下是实质差异:

**golem 不同的:**

- **纯 Go,零 cgo**:构建不需要任何 C 工具链;unidbg 依赖 JVM + Maven。
- **JNI 引用按规范回收**:unidbg 的 `DeleteLocalRef` 是空操作、local 表只进不出,常驻负载下无界增长;golem 按调用帧回收,稳态 O(1)。
- **错误返回 + 事务回滚 + poison**:内存分配、补丁替换失败有明确的可恢复/不可恢复语义;unidbg 风格是抛异常/吞错。
- **共享只读页**:`CompileOnce` + `uc_mem_map_ptr` 让引擎池的只读段在物理内存只有一份。

**golem 还没做的(unidbg 有):**

- ARM32 / x86(目前仅 AArch64);iOS / Mach-O 在路线图上。
- 完整 syscall 表与全部 ~232 个 JNI 槽位(覆盖常见用法,未实现返回 ENOSYS)。
- DEX 字节码执行(仅元数据级:类/方法/字段签名供解析;Java 行为用 `dvm.Jni` 建模)。

**并发模型(两边各说一句,免得误读):**

- golem 与 unidbg 的 guest 线程都是**协作式调度**:`pthread_create` 的线程作为 fiber 承载(独立栈、按系统调用数时间片轮转、futex/sleep 处保存恢复 CPU 上下文)——功能同级,均非引擎内多核并行(单 CPU 后端天然串行)。
- golem 的**吞吐并发**靠引擎层:`emulator.Pool` 让 N 个 goroutine 各持独立引擎真并行(~70 QPS/核,12 核实测 ~510 QPS)——这是并发请求的正确姿势,也是 golem 相对 unidbg 的结构性优势。

## 从源码构建 / 引擎

纯 Go 层与引擎层的构建、交叉编译以及 libunicorn 的运行期定位,都在 [BUILD.md](BUILD.md) 里。

```bash
# 纯 Go 层随处可 build/test(无引擎):
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...

# 引擎集成测试(加载内置 native.so 并运行;CGO_ENABLED=0 全程零 cgo):
CGO_ENABLED=0 go test -tags unicorn ./emulator
```

## 致谢与许可证

- [unidbg](https://github.com/zhkl0228/unidbg)(Apache-2.0):精神前身——领域模型与 JNI 陷回设计的灵感来源。
- [gonidbg](https://github.com/sisi0318/gonidbg)(Apache-2.0):本项目的直接起点——加载器、bionic 复用、协作式调度与 JNI 陷回的 Go 实现源自该 fork,在其基础上演化出 purego 引擎绑定、JNI 引用生命周期、引擎池与共享只读页。
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)(GPLv2):默认 CPU 后端,运行时加载。
- AOSP bionic(Apache-2.0)等:`assets/` 下内置的 sysroot,见 [NOTICE](NOTICE)。

golem 自身的代码采用 Apache-2.0(见 [LICENSE](LICENSE))。引擎的许可证见上表:Unicorn 后端走动态加载,把它的 GPLv2 限制在库边界之内。

## 免责声明

golem 是一个科研和教育用途的工具,用来分析你有权研究的 native 库。仓库里不含任何第三方应用的代码或专有二进制,只有一套通用的模拟框架,以及一个用本仓库源码自建的小示例库。请合理使用,并遵守适用的法律以及你所分析软件的相关条款。
