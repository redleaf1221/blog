---
title: 严肃搭建blog中
date: 2026-10-26 17:23:16
updated: 2026-10-27 10:03:09
tags:
    - sh1t
excerpt: 没人能getshell的网站完成了,等等,原来主页上有个shell?
---

我有点难以理解Hexo这个弱智逻辑了.

![何语言](何语言.png "何语言")

为什么上我自己的blog还要学小语种.

我写了个`language: zh`到`_config.yml`里,也许是因为[hexo.io](https://hexo.io/zh-cn/docs/configuration)说:

> language	网站使用的语言。 使用 2 个字母的 ISO-639-1 代码，或 它的变体。 默认为 en。

我操,我觉得`zh`应该是两个字母.

但是`zh`似乎不太存在,而`hexo-i18n`里:
```js
const languages = [...new Set([].concat(lang, i18nConfigLanguages, i18nLanguages).filter(Boolean))];
```

fallback到随机语言??

改成`zh-CN`就好了.`zh-cn`都不行.我认为这实际上是4个字母5个字符,我应该比[溜溜梅](https://finance.sina.com.cn/wm/2026-06-17/doc-inicrumi4148208.shtml)更擅长字符计数吧.

总之,这是一个基于`Hexo`的纯静态博客,theme由`deepseek-v4.1-flash-1017`完成,参考了`ret2shell`.

大的要来了.
