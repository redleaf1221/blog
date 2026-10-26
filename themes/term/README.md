# term

一个为“按文件夹归档 + 按标签横切检索”写的 Hexo 主题。深色终端风格，带固定目录（TOC）、分页、文件夹树和标签页。

> **版权说明**：本主题的模板、样式、脚本全部为原创实现，没有复制任何 AGPL / GPL 项目的代码、字体或图片。
> 交互与布局思路（顶部导航、文件夹树、终端窗口装饰）属于通用的界面惯例，不构成对原项目的衍生。
> 本主题以 MIT 许可发布，你可以随意修改、闭源、商用。

## 依赖

只用到 Hexo 自带能力，不需要额外插件（`hexo-renderer-ejs` 必须装）：

```bash
pnpm add hexo-renderer-ejs hexo-generator-index hexo-generator-archive hexo-generator-tag hexo-generator-category
```

## 启用

```yaml
# _config.yml
theme: term
language: zh-CN      # 必须是 languages/ 里真实存在的文件名
permalink: :year/:month/:day/:title/
```

> `language` 写 `zh` 而不是 `zh-CN` 会让 Hexo 回退到主题里“第一个被加载的语言文件”，
> 表现为页面上出现随机语言（阿拉伯语、孟加拉语……）。这是 Hexo 的 i18n 行为，不是主题 bug。

## 两个互相独立的轴

| | 文件夹 | 标签 |
| --- | --- | --- |
| 来源 | 文章在 `source/_posts/` 里的**位置**，或 front-matter 的 `folder:` | front-matter 的 `tags:` |
| 数量 | 一篇文章只属于一个文件夹（可以有子文件夹） | 一篇文章可以有任意多个 |
| 作用 | 组织浏览：在侧栏就地展开、直接列出文章 | 检索维度，跨文件夹聚合：`/tags/<标签>/` |
| 例子 | `TSCTF-J 2026/` | `CTF`、`Misc`、`AI` |

一篇文章可以既放在 `TSCTF-J 2026` 文件夹下，同时带有 `CTF`、`Misc`、`AI` 三个标签。

## 写文章

```text
source/_posts/
├── TSCTF-J 2026/            -> 侧栏「TSCTF-J 2026」组
│   ├── ez-sql.md
│   └── ai-forensics.md
├── 学习笔记/                 -> 侧栏「学习笔记」组
│   ├── hexo-theme.md
│   └── 算法/                 -> 侧栏嵌套「算法」组
│       └── dsu.md
└── 随笔.md                  -> 侧栏顶层，和文件夹并列（排在文件夹之后）
```

```yaml
---
title: "TSCTF-J 2026 — ez_sql"
date: 2026-10-20 21:40:00
tags: [CTF, Web, SQL]
---
```

- **不放在任何子目录**的文章不进任何分组：它自己在侧栏顶层占一行，文件夹在前、这些文章在后，日期新的靠上。
- 想让文件和位置分离时，用 front-matter 覆盖：

```yaml
---
title: 某篇平铺在 _posts 下的文章
folder: TSCTF-J 2026/Web
---
```

- 文件夹**没有独立页面**：它只是侧栏里的一个可展开分组，点文件夹就地展开/收起，文章标题直接列在树里，点标题才打开（并成为一个 tab）。**默认全部折叠**，只有打开文章时自动展开它所在的那条路径；手动展开的状态存在 `localStorage`。
- 点文件夹本身不会跳转，所以「按文件夹找文章」全程不需要把视线移到内容区。
- 侧栏分组后面的数字是含子树的合计；顶层的单篇文章和文件夹用不同的图标区分（文件夹 / 文件）。

## 文章图片放哪

图片不在 `source/_posts/` 里。默认放项目根目录的 `assets/` 下，用**和文章一样的相对路径**，这样一篇文章不用写任何额外配置：

```text
source/_posts/TSCTF-J 2026/ez-sql.md          ← 文章
assets/_posts/TSCTF-J 2026/ez-sql/pic.png     ← 它的图片
assets/_posts/TSCTF-J 2026/ez-sql/sub/a.png   ← 子目录也可以
```

markdown 里照旧写相对路径，不用关心最终 URL：

```markdown
![示意图](pic.png)
![子目录](sub/a.png)
{% asset_img pic.png "也可以用标签" %}
```

构建时 `scripts/assets.js` 会把这些文件登记成 PostAsset，Hexo 自动复制到 `public/<文章 URL>/`，所以 `pic.png` 正好落在文章 URL 下面，浏览器按相对路径就能取到。

### 用 Front-matter 覆盖

路径对不上时（文章改过名、几篇想共用一个目录、图片想放在 `assets/` 之外），在文章里用 `assets:` 显式指定。路径默认相对 `assets/`：

```yaml
assets: _posts/2026/ez-sql              # 一个目录
```

```yaml
assets: [_posts/shared, media/diagram]  # 多个目录
```

```yaml
assets: /media/screenshots              # 以 / 开头 = 相对站点根目录
```

```yaml
assets:                                 # 或者逐个文件映射：引用名 -> 文件
  pic.png: media/diagram.png
```

- 写了 `assets:` 就以它为准，这一篇不再走镜像目录；两者同时存在时只认显式的。
- 引用名（slug）决定最终 URL：目录形式取文件相对该目录的路径（`sub/a.png`），映射形式取冒号左边的键。所以正文里的 `![](pic.png)`、`{% asset_img pic.png %}` 一个字都不用改。
- 一个文件只属于一篇文章。两篇指到同一个目录时，后一篇会被忽略并打印警告。
- 目录/文件不存在、或者指到 `source/` 里（Hexo 会把那里的文件当页面处理）都会在构建时警告。
- PostAsset 记录每次构建都按当前文件和当前声明重建，删文件或删声明不留幽灵图片。

相关配置：

| 配置 | 值 | 原因 |
| --- | --- | --- |
| `post_asset_folder` | `false` | 不在 `.md` 旁边建资源目录，避免和文章文件夹混淆 |
| `marked.prependRoot` | `false` | 相对路径保持相对，交给文章的 URL 去解析 |
| `scripts/assets.js` | — | 按路径镜像注册 PostAsset，认 `assets:` 覆盖；`hexo new` 时自动建同名目录 |

## 全站资源（图片、字体、favicon…）

不属于任何文章的图也放 `assets/`，路径原样搬到站点根目录，所以以前写 `source/images/og.png` 的地方只是文件挪了个位置：

```text
assets/images/og.png      ->  /images/og.png
assets/fonts/ui.woff2     ->  /fonts/ui.woff2
```

正文里照旧写 `/images/og.png`，不用加 `assets/` 前缀。

- `assets/_posts/**` 是文章资源，走上面那套，不进这个镜像。
- 任意一层以 `_` 或 `.` 开头的文件/目录不发布，`assets/_drafts/` 这类可以当草稿区。
- 只复制不渲染：`assets/` 里的 `.md` 不会变成页面。
- 和主题自带文件撞路径时站点这份赢，比如 `assets/images/favicon.svg` 会替掉主题的默认图标。
- `assets/` 要放在**站点根目录**，别塞进 `source/`：`source/` 里的东西会被 Hexo 当页面处理，而且 `source/_posts` 和 `source/assets/_posts` 两个 `_posts` 很容易看混。
- `hexo server` 只监听 `source/` 和主题目录；往 `assets/` 里加**新**文件后重启一下才会出现（改已有文件同理）。

## 三个区域，三种职责

```text
┌────────────────────────────────────────────────────────────┐
│ 顶栏：头像 · 站名 · 文章 / 友链 / 关于           切换主题  │
├──────────────┬─────────────────────────────────────────────┤
│ 侧栏          │ 标签页条（只放已打开的文章）                │
│ 全部文章      ├─────────────────────────────────────────────┤
│ 按标签检索    │ 内容区（视图或文章）                        │
│ 搜索框        │                                             │
│ 文件夹树      │                                             │
└──────────────┴─────────────────────────────────────────────┘
```

| 区域 | 职责 | 什么时候出现 |
| --- | --- | --- |
| 顶栏 | 三个同级视图：**文章 / 友链 / 关于**。当前所在视图高亮 | 始终 |
| 侧栏 | 文章浏览专属：全部文章、按标签检索、搜索、文件夹树 | 只在文章浏览视图（首页、文章、文件夹、标签、归档）；友链和关于不显示 |
| 标签页（Tabs） | 已打开**文章**的切换条 | 至少打开一篇文章时；关掉最后一篇就整条隐藏 |

要点：

- **友链、关于不是标签页**。它们是和「文章浏览」同级的视图，点进去会替换内容区，不会在标签条里多出一个 tab。
- **标签也不是标签页**。标签入口在侧栏「按标签检索」，属于文章浏览的一部分。
- 侧栏高亮会跟着走：在文章页会高亮该文章所属的文件夹，在标签页高亮「按标签检索」。
- 标签页状态存在 `sessionStorage`，刷新不丢，关掉浏览器标签页就清空。
- 窄屏（≤1024px）侧栏变成抽屉：顶栏左边的 ☰ 打开/收起，点遮罩或按 Esc 关闭，点里面任意链接（文章、全部文章、标签）后自动收起，打开时页面本身不滚动。友链/关于没有侧栏，按钮也不显示。

## 导语（excerpt）

卡片上那句摘要，打开文章后也会以灰色导语出现在正文上方——从侧栏直接点开文章的人不会漏掉它。

```markdown
这是一句先说的话。

<!-- more -->

## 正文从这里开始
```

- 只有**显式**的摘要才当导语：`<!-- more -->` 之前的文字，或者 front-matter 里的 `excerpt:`（这个按 markdown 渲染）。
- 没有摘要的文章顶部不会多出任何东西；卡片上的自动摘要是截断的正文开头，搬到文章顶部只会和第一段重复。
- 有 `<!-- more -->` 时正文从标记之后开始，所以同一段不会出现两次；如果全文都在标记之前，就不渲染导语，正文照旧完整显示。
- 导语是灰色、比正文小一号、左边一条中性细线，不参与目录：目录只取正文里的标题。

## 页面

| 路径 | 布局 | 类型 | 说明 |
| --- | --- | --- | --- |
| `/` | `index.ejs` | view | 整屏欢迎页（终端卡片 + 统计），向下滚动进入时间线 |
| `/articles/` | `articles.ejs` | view | 全部文章（按年分组） |
| `/tags/` | `tags.ejs` | view | 标签云（从侧栏「按标签检索」进入） |
| `/tags/<tag>/` | `tag.ejs` | view | 单个标签，跨文件夹聚合 |
| `/archives/` | `archive.ejs` | view | 按年归档 |
| `/friends/` | `friends.ejs` | plain | 友链卡片，无侧栏 |
| 其他 `page` | `page.ejs` | plain | 关于等静态页，无侧栏，带 TOC |
| 文章页 | `post.ejs` | post | 打开即成为一个 tab |

`source/tags/index.md`：

```yaml
---
layout: tags
title: 标签
---
```

`source/friends/index.md`：

```yaml
---
layout: friends
title: 友链
friends:
  - name: 名字
    url: https://example.com/
    desc: 一句话简介
    # avatar: https://example.com/avatar.png   # 可选，没有则用首字母
---
```

## 配置

主题配置分两层，Hexo 会按名字自动加载并深度合并：

| 文件 | 作用 |
| --- | --- |
| `themes/term/_config.yml` | 主题自带的**默认值**，升级主题时会被覆盖，不要改 |
| `_config.term.yml`（站点根目录） | **你的设置**，覆盖默认值；只改这个 |

文件名里的 `term` 就是 `_config.yml` 里的 `theme` 值。只有站点根目录那份会跟着你的仓库走。

> 数组（比如 `footer_links`）是按**索引合并**的：同名索引会被覆盖，多出来的项会追加。主题默认给的是空数组，所以站点里想写几条就是几条。

| 键 | 说明 |
| --- | --- |
| `brand_name` | 顶栏的品牌文字，留空则用站点标题 |
| `avatar` | 顶栏头像 URL，留空用作者首字母 |
| `menu` | 顶栏视图，默认 文章 / 友链 / 关于（标签在侧栏，不在这里） |
| `folder_tree` | 是否在文章页显示左侧文件夹树 |
| `summary_length` | 列表卡片摘要长度（没有 `<!-- more -->` 时截断的字符数） |
| `accent` | 强调色 |
| `reading_time` / `reading_speed` | 阅读时长估算 |
| `code_copy` | 代码块复制按钮（脚本默认开启） |
| `social.github` | 顶栏 GitHub 链接 |
| `footer` | 版权起始年、ICP 备案号等 |
| `footer_links` | 页脚额外链接 |

## 结构

```text
themes/term/
├── _config.yml
├── languages/            zh-CN.yml, en.yml
├── layout/
│   ├── layout.ejs        壳：顶栏 + 侧栏 + 标签条 + 内容区 + 页脚
│   ├── index.ejs         欢迎页 + 时间线
│   ├── post.ejs          文章页（正文 + TOC + 上一篇/下一篇）
│   ├── page.ejs          静态页（关于等，无侧栏）
│   ├── articles.ejs      /articles/ 全部文章
│   ├── tags.ejs / tag.ejs
│   ├── archive.ejs / category.ejs
│   ├── friends.ejs       友链（无侧栏）
│   └── _partial/
│       ├── topbar.ejs    顶栏：头像、视图导航、主题切换
│       ├── sidebar.ejs   侧栏：全部文章、按标签检索、搜索
│       ├── tree.ejs      可折叠文件夹树
│       ├── tabbar.ejs    标签条（服务端只渲染当前文章）
│       ├── banner.ejs    视图页头
│       ├── timeline.ejs  按年分组的时间线卡片
│       └── head / footer / pager / icon …
├── scripts/
│   ├── folders.js        文件夹树 + /articles/ 生成器 + 页面类型/导航辅助函数
│   └── permalink.js      把 URL 里的空格换成 -
└── source/
    ├── css/term.css      设计令牌 + 深浅两套配色 + 三栏布局
    ├── js/term.js        文章标签页 / 视图切换 / 侧栏 / TOC / 搜索 / 复制
    └── images/favicon.svg
```

## 实现备注

- 页面类型由 `page_kind()` 判定，写进 `<body data-page-kind>` 和内容区的同名属性：`post` 进标签条，`view` 保留侧栏，`plain` 隐藏侧栏。前端导航时直接读新内容区的这个属性来决定行为。
- 文件夹树由 `scripts/folders.js` 基于 `post.source` 的目录现场计算，只生成 `/articles/` 一个页面；文件夹本身没有路由，展开状态存在 `localStorage`。
- 视图切换是 `fetch` + `DOMParser` 替换 `[data-tab-pane]`，没有整页刷新；失败时自动退回 `location.href`，禁用 JS 也能正常浏览。
- 主题 i18n 只认 `languages/` 下真实存在的文件名；缺失时 Hexo 会回退到第一个已加载的语言。
- `hexo-util` 的 `toc()` 直接吃渲染后的 HTML，配合 `IntersectionObserver` 做滚动高亮。
- 代码块配色随主题切换（`--code-bg` / `--tok-*` 令牌），浅色主题下不会出现深底深字。


## 文案从哪来，怎么覆盖 / 怎么置空

主题里**没有**写死的说明性文案（`languages/*.yml` 里只有菜单、按钮、状态这类固定标签）。页面上那些句子全部来自下面这些位置：

| 位置 | 来源 | 覆盖 | 置空 |
| --- | --- | --- | --- |
| 首页正文 | `source/_welcome.md` | 直接改这个文件；或改 `welcome_file:` 指向别的 md | 删掉文件 / `welcome_file: ""` → 只剩站点标题 |
| 首页副标题 | `_config.yml` 的 `description`（仅在没填 welcome 时使用） | 写 `description:` | 留空 |
| `/articles/` 横幅 | 主题 `_config.yml` 的 `articles_intro` | 写一行文字 | 留空 `""` |
| `/tags/` | `source/tags/index.md` 的 `description` | 加一行 front-matter | 删掉那行，或写 `""` |
| `/friends/` | `source/friends/index.md` 的 `description` | 同上 | 同上 |
| `/about/` | `source/about/index.md` 的 `description` | 同上 | 同上 |
| 单个标签页 / 归档 | 无 | — | — |

模板对所有这些字段都加了空值判断：为空时**整段不渲染**（不会留下空的 `<p>` 或多余间距）。

> ⚠️ 不要用「把 i18n 翻译改成空字符串」来隐藏文字。Hexo 的 `__()` 是 `data[key] || key`，空字符串是 falsy，结果会把 **key 本身**打到页面上（比如出现 `tag.axis`）。所以说明性文字根本不该放进 `languages/`：想加就写在上面那些字段里，想删就直接删。

## 首页 shell

首页右侧的终端是真的能用的（`source/js/term.js` 里的 `initShell`），数据来自构建时注入的 `#term-data`：

| 命令 | 作用 |
| --- | --- |
| `ls [目录]` | 列文件夹与文章（文章带序号） |
| `cd [目录]` | 切换目录，`..` 返回；`pwd` 看当前路径 |
| `cat <序号\|标题>` | 看文章标题 / 日期 / URL |
| `open <序号\|标题>` | 打开文章（走正常的标签页逻辑） |
| `tree` | 打印整棵树 |
| `tags` | 跳到 `/tags/` |
| `theme [dark\|light]` | 切换配色 |
| `whoami` / `date` / `clear` / `help` | — |

支持 `Tab` 补全文件夹名、`↑`/`↓` 翻历史命令。

## 时间与阅读时长

**发布时间**取 front-matter 的 `date`；**更新时间**只认显式写出的 `updated`：

```yaml
---
title: 某篇文章
date: 2026-10-20 21:40:00
updated: 2026-10-24 12:00:00   # 可选；不写就不显示「更新于」
---
```

站点 `_config.yml` 里 `updated_option: 'empty'`，所以不会再拿文件 mtime 当更新时间 —— 没更新过就没有「更新于」，不会因为碰了一下文件就冒出来。

**阅读时长**按「正文 + 代码」分别计：

| 配置 | 默认 | 含义 |
| --- | --- | --- |
| `reading_speed` | `500` | 正文字符 / 分钟 |
| `code_speed` | `300` | 代码行 / 分钟（`0` = 代码完全不计入） |

超过 60 分钟会自动显示成「约 2 小时 8 分钟」而不是「128 分钟」。
## 许可

MIT，见 [LICENSE](LICENSE)。
