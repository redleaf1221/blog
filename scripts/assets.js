/* global hexo */
'use strict';

/**
 * Post assets live outside source/_posts, so an asset folder can never be
 * mistaken for an article folder:
 *
 *   source/_posts/TSCTF-J 2026/ez-sql.md     <- the article
 *   assets/_posts/TSCTF-J 2026/ez-sql/*.png  <- its images
 *
 * Matching is by path, so most posts need no configuration at all. A post can
 * override it in its front-matter with `assets:`:
 *
 *   assets: _posts/2026/ez-sql             # one directory (relative to assets/)
 *   assets: [_posts/shared, media/diagram] # several directories
 *   assets: /media/screenshots             # leading / = relative to the site root
 *   assets:                                # explicit file -> reference mapping
 *     pic.png: media/diagram.png
 *
 * Files are registered as PostAssets, so Hexo copies each one to
 * `<post url>/<slug>` — exactly where a relative reference such as
 * `![](pic.png)` resolves to. The asset_img tag keeps working too, since it
 * looks posts up in the same PostAsset model.
 *
 * The filter is registered with priority 5 (lower runs first) because Hexo
 * renders posts in its own before_generate filter at priority 10: the tags
 * need these records before that.
 */

const fs = require('fs');
const path = require('path');

const ASSET_ROOT = 'assets';
const FRONT_MATTER_KEY = 'assets';

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function assetsRoot() {
  return path.join(hexo.base_dir, ASSET_ROOT);
}

function sitePath(abs) {
  return toPosix(path.relative(hexo.base_dir, abs));
}

function insideSite(abs) {
  const rel = path.relative(hexo.base_dir, abs);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function insideSource(abs) {
  const rel = path.relative(path.join(hexo.base_dir, 'source'), abs);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

/**
 * `media/diagram.png`        -> <site>/assets/media/diagram.png
 * `assets/media/...`, `/media/...` -> relative to the site root
 */
function targetPath(value) {
  let raw = toPosix(value).trim().replace(/^\.\//, '');
  if (!raw) return null;

  const fromSite = raw.startsWith('/') || raw === ASSET_ROOT || raw.startsWith(`${ASSET_ROOT}/`);
  raw = raw.replace(/^\/+/, '');

  return fromSite ? path.resolve(hexo.base_dir, raw) : path.resolve(assetsRoot(), raw);
}

function label(post) {
  return toPosix(post.source || post.title || post._id || '?');
}

function statOrNull(target) {
  try {
    return fs.statSync(target);
  } catch (e) {
    return null;
  }
}

function registerAssets() {
  const PostAsset = hexo.model('PostAsset');
  const posts = [];
  hexo.locals.get('posts').forEach((post) => posts.push(post));

  const wanted = new Map(); // _id (path from the site root) -> { post, slug }
  const claimed = []; // explicitly declared directories: the mirror pass skips them
  const explicit = new Set(); // posts that declared something: they ignore the mirror pass

  function add(absFile, post, slug) {
    if (!insideSite(absFile)) {
      hexo.log.warn('[assets] %s: %s 不在站点目录里，已忽略', label(post), absFile);
      return;
    }
    if (insideSource(absFile)) {
      hexo.log.warn(
        '[assets] %s: %s 在 source/ 里，会被 Hexo 当成页面处理，请移到 assets/ 或站点根目录的其他位置',
        label(post),
        sitePath(absFile)
      );
      return;
    }

    const id = sitePath(absFile);
    const taken = wanted.get(id);
    if (taken) {
      if (taken.post !== post) {
        hexo.log.warn(
          '[assets] %s 已经属于 %s，%s 里对它的引用被忽略（一个文件只能属于一篇文章）',
          id,
          label(taken.post),
          label(post)
        );
      }
      return;
    }
    wanted.set(id, { post, slug: toPosix(slug) });
  }

  function collectDir(absDir, post) {
    const stat = statOrNull(absDir);
    if (!stat || !stat.isDirectory()) {
      hexo.log.warn('[assets] %s: 找不到资源目录 %s', label(post), sitePath(absDir));
      return;
    }

    (function walk(dir, prefix) {
      fs.readdirSync(dir, { withFileTypes: true }).forEach((entry) => {
        if (entry.name.startsWith('.')) return;
        const abs = path.join(dir, entry.name);
        const slug = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) walk(abs, slug);
        else if (entry.isFile()) add(abs, post, slug);
      });
    })(absDir, '');
  }

  function isClaimed(abs) {
    return claimed.some((dir) => abs === dir || abs.startsWith(dir + path.sep));
  }

  // 1. explicit front-matter declarations
  posts.forEach((post) => {
    const declared = post[FRONT_MATTER_KEY];
    if (declared == null || declared === '' || declared === false) return;

    if (typeof declared === 'string' || Array.isArray(declared)) {
      [].concat(declared).forEach((item) => {
        if (typeof item !== 'string') return;
        const abs = targetPath(item);
        if (!abs) return;
        explicit.add(post._id);
        claimed.push(abs);
        collectDir(abs, post);
      });
      return;
    }

    if (typeof declared === 'object') {
      explicit.add(post._id);
      Object.keys(declared).forEach((slug) => {
        const abs = targetPath(declared[slug]);
        if (!abs) return;
        const stat = statOrNull(abs);
        if (!stat || !stat.isFile()) {
          hexo.log.warn('[assets] %s: assets.%s 指向的 %s 不存在', label(post), slug, sitePath(abs));
          return;
        }
        add(abs, post, slug);
      });
    }
  });

  // 2. the default convention: assets/_posts mirrors source/_posts
  const root = assetsRoot();
  if (fs.existsSync(root)) {
    const bySource = new Map();
    posts.forEach((post) => bySource.set(toPosix(post.source), post));

    (function walk(dir, rel) {
      fs.readdirSync(dir, { withFileTypes: true }).forEach((entry) => {
        if (entry.name.startsWith('.')) return;
        const relPath = rel ? `${rel}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
          walk(path.join(dir, entry.name), relPath);
          return;
        }
        if (!relPath.startsWith('_posts/')) return;
        if (isClaimed(path.join(root, relPath))) return;

        // walk up until the path matches a post:
        // "_posts/foo/bar/pic.png" -> "_posts/foo/bar.md"
        let dirPath = path.posix.dirname(relPath);
        while (dirPath && dirPath !== '.' && dirPath !== '/') {
          const post = bySource.get(`${dirPath}.md`);
          if (post) {
            if (explicit.has(post._id)) return;
            add(path.join(root, relPath), post, path.posix.relative(dirPath, relPath));
            return;
          }
          const parent = path.posix.dirname(dirPath);
          if (parent === dirPath) break;
          dirPath = parent;
        }
      });
    })(root, '');
  }

  wanted.forEach((entry, id) => {
    PostAsset.save({
      _id: id,
      post: entry.post._id,
      slug: entry.slug,
      modified: false,
      renderable: false
    });
  });

  // forget records whose files were deleted or that lost their declaration
  if (!hexo.config.post_asset_folder) {
    PostAsset.forEach((asset) => {
      if (!wanted.has(String(asset._id))) asset.remove();
    });
  }
}

hexo.extend.filter.register('before_generate', registerAssets, 5);

/**
 * Site-wide assets: everything under assets/ that is not private mirrors into
 * the web root, so `source/images/og.png` simply becomes `assets/images/og.png`
 * and the URL stays `/images/og.png`:
 *
 *   assets/images/og.png     -> /images/og.png
 *   assets/fonts/ui.woff2    -> /fonts/ui.woff2
 *
 * Only per-post assets live under `assets/_posts/`; anything whose name starts
 * with `_` or `.` is not published, so that subtree stays out of the mirror.
 * These are copied as-is — nothing under assets/ is rendered.
 *
 * Registered after Hexo's own generators, so a site file wins over a theme
 * file with the same path (e.g. a custom `assets/images/favicon.svg`).
 */
hexo.extend.generator.register('global_assets', function () {
  const root = assetsRoot();
  if (!fs.existsSync(root)) return [];

  const routes = [];

  (function walk(dir, rel) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach((entry) => {
      if (entry.name.startsWith('.') || entry.name.startsWith('_')) return;
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(abs, relPath);
      } else if (entry.isFile()) {
        routes.push({ path: relPath, data: () => Promise.resolve(fs.createReadStream(abs)) });
      }
    });
  })(root, '');

  return routes;
});

// `hexo new` also creates the matching folder under assets/
hexo.on('new', (post) => {
  try {
    const file = String((post && post.path) || '');
    const sourceDir = String(hexo.source_dir);
    if (!file.startsWith(sourceDir)) return;

    const rel = file.slice(sourceDir.length).replace(/\\/g, '/');
    if (!rel.startsWith('_posts/')) return;

    fs.mkdirSync(path.join(assetsRoot(), rel.replace(/\.md$/i, '')), { recursive: true });
  } catch (e) {
    /* never break `hexo new` because of this */
  }
});
