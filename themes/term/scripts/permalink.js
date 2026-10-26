/* global hexo */
'use strict';

/**
 * Keep post URLs free of whitespace.
 *
 * A post nested in `source/_posts/TSCTF-J 2026/ez-sql.md` gets the permalink
 * `/2026/10/20/TSCTF-J 2026/ez-sql/`, and Hexo happily writes a directory with
 * a literal space in it. This filter slugifies every URL segment instead:
 *
 *   /2026/10/20/TSCTF-J 2026/ez-sql/  ->  /2026/10/20/TSCTF-J-2026/ez-sql/
 *
 * Folder names are untouched on disk — only the generated URL changes.
 */
hexo.extend.filter.register('post_permalink', function (permalink) {
  if (typeof permalink !== 'string' || !/\s/.test(permalink)) return permalink;
  return permalink
    .split('/')
    .map((segment) => segment.replace(/\s+/g, '-'))
    .join('/');
});
