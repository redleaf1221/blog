/* global hexo */
'use strict';

/**
 * GFM footnotes for hexo-renderer-marked.
 *
 * marked has no footnote support, so `[^1]` was read as an ordinary link
 * reference and `[^1]: 一句话` as its URL — the reference ended up pointing at
 * "<post url>/<the note text>".
 *
 * hexo-renderer-marked runs two filters before rendering each post:
 *
 *   marked:use         - receives marked.use, so hooks can be added
 *   marked:extensions  - an array of marked extensions
 *
 * Two extensions do the parsing (`[^1]: ...` as a block, `[^1]` as an inline
 * reference); the hooks reset the per-parse state and glue the notes onto the
 * end of the HTML. Both run inside one synchronous `marked.parse`, which is why
 * the state cannot leak between posts.
 */

const path = require('path');

/** The exact marked instance the renderer uses, for `use.call(...)`. */
function markedInstance() {
  const rendererDir = path.dirname(require.resolve('hexo-renderer-marked'));
  return require(require.resolve('marked', { paths: [rendererDir] })).marked;
}

const definitions = new Map(); // label -> footnote text (at lex time)
const rendered = new Map(); // label -> footnote html (at render time)
const order = []; // labels in order of first reference
const refCount = new Map(); // label -> how many times it was referenced
const rDefinitionStart = /^\[\^[^\]\s]+\]:/m;

function reset() {
  definitions.clear();
  rendered.clear();
  order.length = 0;
  refCount.clear();
}

function dedent(line) {
  if (line.startsWith('    ')) return line.slice(4);
  if (line.startsWith('\t')) return line.slice(1);
  return line.replace(/^ {1,2}/, '');
}

/** `[^label]: text` plus its indented continuation lines. */
function readDefinition(src) {
  const head = /^\[\^([^\]\s]+)\]:[ \t]*([^\n]*)/.exec(src);
  if (!head) return null;

  const label = head[1];
  let raw = head[0];
  const lines = [head[2]];

  const cont = /^(?:\n[ \t]{2,}[^\n]*)+/.exec(src.slice(raw.length));
  if (cont) {
    raw += cont[0];
    cont[0]
      .split('\n')
      .slice(1)
      .forEach((line) => lines.push(dedent(line)));
  }

  const tail = /^\n/.exec(src.slice(raw.length));
  if (tail) raw += tail[0];

  return { label, raw, text: lines.join('\n') };
}

const definition = {
  name: 'fnDefinition',
  level: 'block',
  start(src) {
    const match = rDefinitionStart.exec(src);
    return match ? match.index : undefined;
  },
  tokenizer(src) {
    const note = readDefinition(src);
    if (!note) return undefined;
    definitions.set(note.label, note.text);
    return {
      type: 'fnDefinition',
      raw: note.raw,
      label: note.label,
      tokens: this.lexer.blockTokens(note.text)
    };
  },
  renderer(token) {
    rendered.set(token.label, this.parser.parse(token.tokens));
    return '';
  }
};

const reference = {
  name: 'fnReference',
  level: 'inline',
  start(src) {
    const at = src.indexOf('[^');
    return at === -1 ? undefined : at;
  },
  tokenizer(src) {
    const match = /^\[\^([^\]\s]+)\]/.exec(src);
    if (!match) return undefined;
    return { type: 'fnReference', raw: match[0], label: match[1] };
  },
  renderer(token) {
    // no matching definition: leave the text alone, like GFM does
    if (!definitions.has(token.label)) return token.raw;

    let index = order.indexOf(token.label);
    if (index === -1) {
      order.push(token.label);
      index = order.length - 1;
    }
    const n = index + 1;

    const count = (refCount.get(token.label) || 0) + 1;
    refCount.set(token.label, count);
    const id = count === 1 ? `fnref${n}` : `fnref${n}-${count}`;

    return `<sup class="fn-ref" id="${id}"><a href="#fn${n}">${n}</a></sup>`;
  }
};

/** The notes block, appended to the rendered HTML of one post. */
function notesHtml() {
  if (!order.length) return '';

  const items = order.map((label, i) => {
    const n = i + 1;
    const count = refCount.get(label) || 1;
    const backrefs = [];
    for (let k = 1; k <= count; k += 1) {
      const id = k === 1 ? `fnref${n}` : `fnref${n}-${k}`;
      backrefs.push(`<a class="fn-backref" href="#${id}" aria-label="back">↩</a>`);
    }
    const arrows = backrefs.join(' ');
    let html = rendered.get(label) || '';
    // keep the backref on the last line of the note instead of below it
    const paragraphEnd = /<\/p>\s*$/;
    html = paragraphEnd.test(html)
      ? html.replace(paragraphEnd, ` ${arrows}</p>`)
      : `${html} ${arrows}`;
    return `<li id="fn${n}">${html}</li>`;
  }).join('\n');

  return `\n<section class="footnotes"><ol>\n${items}\n</ol></section>`;
}

hexo.extend.filter.register('marked:extensions', function (extensions) {
  extensions.push(definition, reference);
});

hexo.extend.filter.register('marked:use', function (use) {
  use.call(markedInstance(), {
    hooks: {
      preprocess(markdown) {
        reset();
        return markdown;
      },
      postprocess(html) {
        const notes = notesHtml();
        reset();
        return notes ? html + notes : html;
      }
    }
  });
});
