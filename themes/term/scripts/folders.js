/* global hexo */
'use strict';

/**
 * Folder model.
 *
 * Folders and tags are two independent axes:
 *   - folder: where a post lives on disk (source/_posts/<folder>/...),
 *             or an explicit `folder:` field in the front-matter.
 *   - tags:   free-form cross-cutting labels from the front-matter.
 *
 * This script builds a folder tree out of all posts (the sidebar renders it)
 * and exposes the helpers used by the templates.
 */

const fs = require('fs');
const path = require('path');

const cache = { tree: null, index: null, welcome: null };

hexo.extend.filter.register('before_generate', () => {
  cache.tree = null;
  cache.index = null;
});

function themeConfig() {
  return hexo.theme.config || {};
}

function sanitizeSegment(name) {
  return String(name)
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[\\/:*?"<>|#%&{}$!'@+`=~^[\]]/g, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || 'folder';
}

function folderPathOf(post) {
  if (post.folder) {
    return String(post.folder).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  }
  const source = String(post.source || '').replace(/\\/g, '/');
  const rel = source.replace(/^_?posts\//, '');
  const segments = rel.split('/');
  segments.pop(); // drop the file name
  return segments.filter(Boolean).join('/');
}

function newNode(name, depth) {
  return {
    name,
    slug: sanitizeSegment(name),
    url: '',
    depth,
    children: [],
    posts: [],
    breadcrumb: [],
    total: 0
  };
}

function buildTree(posts) {
  const root = newNode('', 0);
  root.url = '/articles/';
  root.breadcrumb = [];

  const byPath = new Map();
  const index = new Map();

  posts.forEach((post) => {
    const folder = folderPathOf(post);
    let node = root;

    if (folder) {
      let acc = '';
      folder.split('/').filter(Boolean).forEach((segment, i) => {
        acc = acc ? `${acc}/${segment}` : segment;
        let child = byPath.get(acc);
        if (!child) {
          child = newNode(segment, i + 1);
          byPath.set(acc, child);
          node.children.push(child);
        }
        node = child;
      });
    }

    node.posts.push(post);
    index.set(String(post._id), node);
  });

  const byDate = (a, b) => b.date.valueOf() - a.date.valueOf();

  (function finalize(node, url, crumbs) {
    const used = new Set();
    node.children.sort((a, b) => a.name.localeCompare(b.name, 'zh-Hans-CN'));

    node.children.forEach((child) => {
      let slug = child.slug;
      let n = 2;
      while (used.has(slug)) slug = `${child.slug}-${n++}`;
      used.add(slug);
      child.slug = slug;
      child.url = `${url}${slug}/`;
      child.breadcrumb = crumbs.concat([{ name: child.name, url: child.url }]);
      child.pathLabel = child.breadcrumb.map((c) => c.name).join('/');
      child.key = child.pathLabel;
      finalize(child, child.url, child.breadcrumb);
    });

    node.posts.sort(byDate);
    node.total = node.posts.length + node.children.reduce((sum, c) => sum + c.total, 0);
  })(root, '/articles/', []);

  // Posts that live directly in _posts/ are not collected into a synthetic
  // folder: they sit at the top level of the sidebar, next to the folders.
  return { root, index };
}

function getModel() {
  if (!cache.tree) {
    const built = buildTree(hexo.locals.get('posts'));
    cache.tree = built.root;
    cache.index = built.index;
  }
  return cache.tree;
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

hexo.extend.helper.register('folder_model', function () {
  return getModel();
});

/** Folder node a post belongs to (root node for folder-less posts). */
hexo.extend.helper.register('folder_of', function (post) {
  getModel();
  const node = cache.index.get(String(post && post._id));
  return node || cache.tree;
});

/** Breadcrumb chain for a post, including the "Articles" root entry. */
hexo.extend.helper.register('folder_crumbs', function (post) {
  const node = this.folder_of(post);
  return node === cache.tree ? [] : node.breadcrumb;
});

/** Rough plain-text summary of a post. */
function decodeEntities(str) {
  return str
    .replace(/&#x([0-9a-f]+);/gi, (m, hex) => {
      const code = parseInt(hex, 16);
      return code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    })
    .replace(/&#(\d+);/g, (m, dec) => {
      const code = parseInt(dec, 10);
      return code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    })
    .replace(/&nbsp;/gi, ' ')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&apos;|&#39;/gi, "'")
    .replace(/&amp;/gi, '&');
}

/**
 * The excerpt the author wrote, as HTML: either `<!-- more -->` in the body or
 * an `excerpt:` field in front-matter.
 *
 * The card summary falls back to the first N characters of the body, which is
 * fine on a card but would be a duplicate at the top of the article, so the
 * lead only exists when an excerpt is explicit.
 */
function excerptHtml(post) {
  const excerpt = post && post.excerpt ? String(post.excerpt).trim() : '';
  if (!excerpt) return '';
  if (!excerpt.replace(/<[^>]*>/g, '').trim()) return '';

  // `<!-- more -->` is split after rendering, so `excerpt` is already HTML.
  // A front-matter `excerpt:` is handed over before rendering and is markdown.
  const rendered = String((post && post.content) || '').indexOf('<span id="more"></span>') !== -1;
  if (rendered) return excerpt;

  try {
    return hexo.render.renderSync({ text: excerpt, engine: 'markdown' });
  } catch (e) {
    return excerpt;
  }
}

hexo.extend.helper.register('post_lead', function (post) {
  return excerptHtml(post);
});

hexo.extend.helper.register('post_summary', function (post) {
  const limit = Number(themeConfig().summary_length) || 160;
  const excerpt = excerptHtml(post);
  if (excerpt) {
    return { html: true, text: excerpt };
  }
  let text = String(post.content || '')
    .replace(/<figure[\s\S]*?<\/figure>/gi, ' ')
    .replace(/<pre[\s\S]*?<\/pre>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  // marked escapes characters such as "/" into numeric entities; the browser
  // decodes them in the article body, but the card prints plain text, so the
  // entities have to be decoded here or they show up literally.
  text = decodeEntities(text).replace(/\s+/g, ' ').trim();
  return {
    html: false,
    text: text.length > limit ? `${text.slice(0, limit).trimEnd()}…` : text
  };
});

/**
 * Estimated reading time in minutes: prose characters at `reading_speed`,
 * plus code lines at `code_speed` (0 = ignore code entirely).
 */
hexo.extend.helper.register('reading_time', function (post) {
  const cfg = themeConfig();
  if (cfg.reading_time === false) return 0;

  const html = String((post && post.content) || '');
  const blocks = html.match(/<pre[\s\S]*?<\/pre>/g) || [];

  let codeChars = 0;
  let codeLines = 0;
  blocks.forEach((block) => {
    const text = block.replace(/<[^>]+>/g, '');
    codeChars += text.length;
    const spans = (block.match(/class="line"/g) || []).length;
    codeLines += spans || text.split('\n').length;
  });

  const proseChars = Math.max(0, html.replace(/<[^>]+>/g, '').length - codeChars);
  const proseSpeed = Number(cfg.reading_speed) || 500;
  const codeSpeed = cfg.code_speed == null ? 300 : Number(cfg.code_speed);

  const minutes = proseChars / proseSpeed + (codeSpeed > 0 ? codeLines / codeSpeed : 0);
  return Math.max(1, Math.ceil(minutes));
});

/** Reading time as a localised label ("12 分钟" / "2 小时 21 分钟"). */
hexo.extend.helper.register('reading_label', function (post) {
  const minutes = this.reading_time(post);
  if (!minutes) return '';
  if (minutes < 60) return this.__('reading.minutes', minutes);
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest
    ? this.__('reading.hours_minutes', hours, rest)
    : this.__('reading.hours', hours);
});

/** Simple counters used by the hero / articles header. */
hexo.extend.helper.register('blog_stats', function () {
  const root = getModel();
  const posts = hexo.locals.get('posts');
  const tags = hexo.locals.get('tags');
  return {
    posts: posts ? posts.length : 0,
    folders: root.children.reduce((sum, c) => {
      const count = (function walk(node) {
        return 1 + node.children.reduce((s, child) => s + walk(child), 0);
      })(c);
      return sum + count;
    }, 0),
    tags: tags ? tags.length : 0
  };
});

/** Marks the active nav entry. */
hexo.extend.helper.register('is_current', function (target) {
  const raw = String((this.page && this.page.path) || '');
  const current = `/${raw.replace(/index\.html$/, '')}`;
  const wanted = String(target).replace(/index\.html$/, '');
  if (wanted === '/' || wanted === '') return current === '/' || raw === 'index.html';
  return current.startsWith(wanted);
});

/** Human title of the current page, used by <title> and by the tab bar. */
hexo.extend.helper.register('tab_title', function () {
  const page = this.page || {};
  if (page.title) return page.title;
  if (page.tag) return `#${page.tag}`;
  if (page.category) return page.category;
  if (page.folder) return page.folder.name;
  if (page.folderRoot) return this.__('articles.title');
  if (page.archive) return this.__('archive.title');
  return this.config.title;
});
/**
 * Page kinds:
 *   post  - an article, opened as a tab
 *   plain - a standalone page (about, friends), no sidebar
 *   view  - an article-browsing view (home, folders, tags, archive), keeps sidebar
 */
hexo.extend.helper.register('page_kind', function (page) {
  if (!page) return 'view';
  if (page.layout === 'post') return 'post';
  if (page.layout === 'page' || page.layout === 'friends') return 'plain';
  return 'view';
});

/** Which top-bar entry should be highlighted for the current page. */
hexo.extend.helper.register('nav_active', function (key) {
  const page = this.page || {};
  const path = `/${String(page.path || '').replace(/index\.html$/, '')}`;
  const isFriends = path.indexOf('/friends') === 0;
  const isAbout = path.indexOf('/about') === 0;

  if (key === 'friends') return isFriends;
  if (key === 'about') return isAbout;
  if (key === 'tags') return path.indexOf('/tags') === 0;
  if (key === 'archives') return path.indexOf('/archives') === 0;
  return !isFriends && !isAbout;
});

/** Markdown shown on the home page, read from source/<welcome_file>. */
hexo.extend.helper.register('welcome_content', function () {
  const rel = themeConfig().welcome_file || '_welcome.md';
  const file = path.join(hexo.source_dir, rel);
  try {
    const stat = fs.statSync(file);
    if (!cache.welcome || cache.welcome.mtime !== stat.mtimeMs) {
      const html = hexo.render.renderSync({ text: fs.readFileSync(file, 'utf8'), engine: 'markdown' });
      cache.welcome = { mtime: stat.mtimeMs, html };
    }
    return cache.welcome.html || '';
  } catch (e) {
    return '';
  }
});

/** JSON blob consumed by the interactive shell on the home page. */
hexo.extend.helper.register('term_data', function () {
  const root = getModel();
  const mapPosts = (posts) => (posts || []).map((post) => ({
    title: post.title || 'untitled',
    path: `/${String(post.path || '').replace(/^\/+/, '')}`,
    date: post.date.format('YYYY-MM-DD')
  }));
  const walk = (nodes) => (nodes || []).map((node) => ({
    name: node.name,
    posts: mapPosts(node.posts),
    children: walk(node.children)
  }));
  return JSON.stringify({
    posts: mapPosts(root.posts),
    folders: walk(root.children)
  }).replace(/</g, '\\u003c');
});


/** Heading levels actually used in the rendered post body. */
function headingLevels(content) {
  const levels = [];
  const re = /<h([1-6])[\s>]/gi;
  let match;
  while ((match = re.exec(content)) !== null) levels.push(Number(match[1]));
  return levels;
}

/**
 * Table of contents.
 *
 * `min_depth: auto` starts at the shallowest heading the post actually uses,
 * so a post written with `#` sections still gets a TOC, while a normal post
 * (starting at `##`) keeps the page title out of it.
 */
hexo.extend.helper.register('toc_html', function (content) {
  const html = String(content || '');
  const levels = headingLevels(html);
  if (!levels.length) return '';

  const cfg = themeConfig().toc || {};
  const smallest = Math.min.apply(null, levels);

  let min = (cfg.min_depth === 'auto' || cfg.min_depth == null) ? smallest : Number(cfg.min_depth);
  min = Math.min(Math.max(min, 1), 6);

  const span = Math.max(1, Number(cfg.levels) || 2);
  const max = Math.min(6, min + span - 1);

  return this.toc(html, {
    list_number: false,
    min_depth: min,
    max_depth: max,
    class: 'toc'
  });
});
/* ------------------------------------------------------------------ */
/* generator: /articles/ (the folder list lives in the sidebar)        */
/* ------------------------------------------------------------------ */

hexo.extend.generator.register('folders', function (locals) {
  const root = getModel();
  const allPosts = locals.posts.sort('-date').toArray();

  // Folders are not pages: they expand in the sidebar and list their posts there.
  return [{
    path: 'articles/index.html',
    layout: 'articles',
    data: {
      folderRoot: true,
      folders: root.children,
      posts: allPosts,
      totalPosts: allPosts.length
    }
  }];
});

/* Expose the tree to every template (nav, rail, footer). */
hexo.extend.filter.register('template_locals', function (locals) {
  locals.folderTree = getModel();
  return locals;
});
