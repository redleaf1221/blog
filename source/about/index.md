---
layout: page
title: 关于
---

## 这个站是什么

这里是 MathTangent 的笔记本：CTF 题解、学习记录，以及一些还没想清楚的东西。

站点用 [Hexo](https://hexo.io/) 生成，主题 `term` 是为这个站写的，强调两件事：

- **文件夹**决定文章放在哪里 —— 一次比赛、一门课、一个专题，各自一个文件夹。
- **标签**是横切维度 —— `CTF`、`Misc`、`AI` 这样的标签可以横跨所有文件夹。

## 怎么组织的

```text
source/_posts/
├── TSCTF-J 2026/          # 一次比赛一个文件夹
│   ├── ez_sql.md          # tags: [CTF, Web, SQL]
│   └── ai-forensics.md    # tags: [CTF, Misc, AI]
└── 学习笔记/
    ├── hexo-theme.md      # tags: [Hexo, 前端]
    └── 算法/
        └── dsu.md         # tags: [算法]
```

文件夹路径就是 URL 路径，所以 `/articles/TSCTF-J-2026/` 就是那个文件夹。

## 联系

- GitHub: 见右上角（在主题 `_config.yml` 里配置）
- Email: `mathtangent@example.com`
