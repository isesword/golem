# 构建说明(纯 Go 变体)

本仓库是 golem 的**纯 Go 变体**:`-tags unicorn` 的 CPU 引擎后端改用
[purego](https://github.com/ebitengine/purego) 在**运行时** `dlopen` 原版
libunicorn——构建期零 cgo、零 C 编译器、零自编 shim 库,`CGO_ENABLED=0`
即可构建整个模块。运行期唯一依赖是系统里装有 libunicorn 本体。

| 引擎 | 构建标签 | 形态 | 平台 |
|---|---|---|---|
| **Unicorn2** | `-tags unicorn` | purego 运行时 `dlopen` libunicorn(解释执行,默认) | macOS / Linux |

> 与 cgo 原版的差异:dynarmic JIT 引擎(cgo/C++ 静态链接)未随本变体提供;
> Windows 暂不支持——unicorn 在 Windows 上靠 VEH 惰性提交 guest 内存页,
> 与 Go 运行时的异常处理器冲突,需要 cgo 原版的"专属 C 线程命令泵"方案
> 才能跑(见原 fork 的 `uc_shim.c`)。

## 1. 前置:装 libunicorn(只装库本体,无需头文件)

```bash
# macOS
brew install unicorn                     # -> /opt/homebrew/opt/unicorn/lib/libunicorn.2.dylib
# Linux
sudo apt install libunicorn2             # 或 pip install unicorn 取 libunicorn.so
```

## 2. 构建 / 测试

```bash
# 引擎版(CGO_ENABLED=0 是本变体的常态,不再需要 CC/zig/CGO_CFLAGS):
CGO_ENABLED=0 go build -tags unicorn -o bin/golem ./cmd/golem
CGO_ENABLED=0 go test  -tags unicorn ./...

# 纯 Go 层(无引擎,随处可编,创建模拟器时报"无引擎"):
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test  ./...

# 工具(纯 Go,无引擎标签):
go run ./cmd/elfscan                     # .so 导入面分析
go run ./cmd/loadplan                    # 重定位直方图
```

运行期定位 libunicorn 的顺序:

1. `$GOLEM_UNICORN`(显式路径,最可靠);
2. `libunicorn.2.dylib` / `libunicorn.dylib`(macOS)或 `libunicorn.so.2` / `libunicorn.so`(Linux),交由系统加载器搜索。

```bash
GOLEM_UNICORN=/opt/homebrew/opt/unicorn/lib/libunicorn.dylib ./bin/golem examples/native/native.so add 2 3
```

## 3. 交叉编译(纯 Go 的直接红利)

无 cgo 意味着交叉编译就是原生 `go build`,目标机只要带一份 libunicorn:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags unicorn -o golem-linux ./cmd/golem
# 目标机:apt install libunicorn2(或 LD_LIBRARY_PATH 指向随包的 libunicorn.so)
```

## 4. 引擎实现要点(unicorn_purego.go)

- C→Go 回调走三个**静态** `purego.NewCallback` 蹦床(code/intr/mem),hook 身份
  (cbid)经 unicorn 的 `user_data` 回传,不占用回调创建预算。
- 变参 C 函数(`uc_hook_add`/`uc_ctl`)按**定参签名**调用——arm64/amd64 SysV
  上整数参数列表的变参与定参调用序列一致,本后端只传整数。
- 引擎调用直接跑在调用方(Go)线程上:POSIX 上 unicorn 的 guest 内存缺页在
  软件层(softmmu)处理,不依赖信号/VEH,与 Go 线程无冲突。
