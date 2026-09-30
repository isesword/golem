# Contributing to golem

## 变更流程（PR-based）

所有变更走 PR——Release 的 "What's Changed" 由 GitHub 从合并的 PR 自动生成，
直接 push 的 commit 不会出现在里面。

```bash
# 1. 分支
git checkout -b feat/my-change main

# 2. 开发 + 测试（引擎路径需要 unicorn tag）
go test ./...
go test -tags unicorn ./...

# 3. push + 开 PR（标题即 release notes 条目，写 conventional 格式）
git push -u origin feat/my-change
gh pr create --title "feat(loader): RELR support" --fill

# 4. 打 label（决定 release 分组，见 .github/release.yml）
gh pr edit --add-label enhancement

# 5. squash 合并（PR = main 上的一条干净提交）
gh pr merge --squash
```

PR 模板已就位（`.github/PULL_REQUEST_TEMPLATE.md`）；未打 label 的 PR
落入 "📦 Other Changes" 平铺列表。

## 发版

```bash
# release.yml workflow 自动构建并附 unicorn.dll 资产 + 自动生成 notes：
gh workflow run release.yml -f tag=v0.x.0
# 或本地打 tag 推送触发。
```

- 自动笔记 = 两个 tag 之间合并的 PR（按 label 分组 + New Contributors）
- 大版本的亮点综述可以直接编辑 release body 追加在自动笔记之前

## 红线（改动前先读）

- 分层与不变量见 [ARCHITECTURE.md](ARCHITECTURE.md)——违反分层即回退
- `emu.Backend` 核心接口冻结：新增能力走 capability 小接口
- 公开 API 分 Portable / Advanced 两层（见 `emulator` 包文档），
  业务代码只写 Portable 面
