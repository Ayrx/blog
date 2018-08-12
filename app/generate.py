import arrow

from jinja2 import Environment, FileSystemLoader, select_autoescape

import mistune

from yaml import load

import os

from pathlib import Path

import pygments
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import html

import shutil

import re


env = Environment(loader=FileSystemLoader("layouts"))


class CustomRenderer(mistune.Renderer):
    def codespan(self, text):
        return "<code class=\"highlight\">{}</code>".format(text)

    def link(self, link, title, content):
        if link.startswith("http://") or link.startswith("https://"):
            return super().link(link, title, content)
        else:
            fname, _ = parse_post_filename(link)
            return super().link(fname, title, content)

    def block_code(self, code, lang):
        if not lang:
            return "\n<pre><code>{}</code></pre>\n".format(
                mistune.escape(code)
            )
        lexer = get_lexer_by_name(lang, stripall=True)
        formatter = html.HtmlFormatter()
        return highlight(code, lexer, formatter)

    def toc(self):
        return self.render_toc()

    def reset_toc(self):
        self.toc_tree = []
        self.toc_count = 0

    def header(self, text, level, raw=None):
        rv = '<h%d id="toc-%d">%s</h%d>\n' % (
            level, self.toc_count, text, level
        )
        self.toc_tree.append((self.toc_count, text, level, raw))
        self.toc_count += 1
        return rv

    def render_toc(self, level=3):
        return "".join(self._iter_toc(level))

    def _iter_toc(self, level):
        first_level = 0
        last_level = 0

        yield "<ul id=\"table-of-content\">\n"

        for toc in self.toc_tree:
            index, text, l, raw = toc

            if l > level:
                continue

            if first_level == 0 :
                # based on first level
                first_level = l
                last_level = l
                yield "<li><a href=\"#toc-{0}\">{1}</a>".format(
                    index, text)
            elif last_level == l:
                yield "</li>\n<li><a href=\"#toc-{0}\">{1}</a>".format(
                    index, text)
            elif last_level == l - 1:
                last_level = l
                yield "<ul>\n<li><a href=\"#toc-{0}\">{1}</a>".format(
                    index, text)
            elif last_level > l:
                # close indention
                yield "</li>"
                while last_level > l:
                    yield "</ul>\n</li>\n"
                    last_level -= 1
                yield "<li><a href=\"#toc-{0}\">{1}</a>".format(
                    index, text)

        # close tags
        yield "</li>\n"
        while last_level > first_level:
            yield "</ul>\n</li>\n"
            last_level -= 1

        yield "</ul>\n"


custom_renderer = CustomRenderer()
ms_markdown = mistune.Markdown(renderer=custom_renderer)


def render_post_html(markdown, post_title, post_date):
    template = env.get_template("post.html")
    custom_renderer.reset_toc()
    content = ms_markdown(markdown)

    # Substitute the {:toc} place holder with our generated TOC.
    toc = custom_renderer.render_toc(level=1)
    content = re.sub(r"\{:toc\}", toc, content)

    return template.render(
        post_title=post_title,
        post_content=content,
        page_title=post_title,
        post_date=post_date.format("DD MMMM YYYY")
    )


def render_page_html(markdown, post_title):
    template = env.get_template("page.html")
    custom_renderer.reset_toc()
    content = ms_markdown(markdown)

    return template.render(
        post_title=post_title,
        post_content=content,
        page_title=post_title,
    )


def render_index_page(posts):
    template = env.get_template("index.html")
    return template.render(posts=posts, page_title="Home")


def parse_frontmatter(frontmatter):
    return load(frontmatter)


def read_file(f):
    first = f.readline()
    if first == "---\n":
        frontmatter = ""
        while True:
            line = f.readline()
            if line == "---\n":
                break
            frontmatter += line

        markdown = f.read()
        return frontmatter, markdown
    else:
        return None, first + f.read()


def parse_post_filename(fname):
    url = fname[11:]
    date = fname[:10]
    return url, arrow.get(date, "YYYY-MM-DD")


def build_site():
    posts = []

    # Make output directory
    try:
        shutil.rmtree("output")
    except FileNotFoundError:
        pass

    os.makedirs("output", exist_ok=True)
    shutil.copytree("public", "output/public")
    shutil.copytree("assets", "output/assets")
    shutil.copy("favi.ico", "output/favi.ico")

    # Iterate and render all files in the pages/ directory.
    p = Path("pages")
    for i in p.glob("*.md"):
        with i.open("r") as f:
            frontmatter, markdown = read_file(f)
            fname = i.stem
            frontmatter = parse_frontmatter(frontmatter)
            html = render_page_html(markdown, frontmatter["title"])

            with open("output/{}.html".format(fname), "w") as f:
                f.write(html)

    # Iterate and render all files in the posts/ directory.
    p = Path("posts")
    for i in p.glob("*.md"):
        with i.open("r") as f:
            frontmatter, markdown = read_file(f)
            fname, date = parse_post_filename(i.stem)
            frontmatter = parse_frontmatter(frontmatter)
            html = render_post_html(markdown, frontmatter["title"], date)

            with open("output/{}.html".format(fname), "w") as f:
                f.write(html)

        posts.append({
            "title": frontmatter["title"],
            "url": fname,
            "date": date
        })

    posts.sort(key=lambda i: i["date"], reverse=True)
    for i in posts:
        i["date"] = i["date"].format("YYYY-MM-DD")
    html = render_index_page(posts)
    with open("output/index.html", "w") as f:
        f.write(html)
