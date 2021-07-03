---
layout: post
title: Generating Binary Ninja Dash Docset
---

The [default method](https://github.com/Vector35/binaryninja-api/blob/dev/api-docs/Makefile#L227-L234)
to generate [Dash](https://kapeli.com/dash) docsets for Binary Ninja does not
work with a personal license as it requires the ability to run Binary Ninja in
headless mode, a capability only available with the commercial license.

Luckily, Binary Ninja ships the API documentation as HTML files  found at
`$BINARY_NINJA_INSTALL_PATH/Contents/Resources/api-docs` which can be easily
converted to Dash docsets with [doc2dash](https://github.com/hynek/doc2dash).

```bash
cp -r /Applications/Binary\ Ninja.app/Contents/Resources/api-docs /tmp
echo ".wy-nav-side {display: none;}.wy-nav-content-wrap {margin-left: 0;}" >> /tmp/api-docs/_static/css/theme.css
doc2dash \
    --destination ~/Documents/Dash\ Docsets \
    --name "Binary Ninja" \
    --icon ~/Documents/Dash\ Docsets/binja-icon-180x180.png \
    /tmp/api-docs
rm -rf /tmp/api-docs
```

The icon image was grabbed from the Binary Ninja [website](https://binary.ninja/ico/apple-icon-180x180.png).
