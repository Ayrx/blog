---
layout: post
title: A faster PBKDF2 for Python
---
I came across a [blog post][blog-post] titled "PBKDF2: performance matters"
where the author discusses how most implementations of PBKDF2 are slower than
it otherwise could be.

After reading the blog post, I decided to write some Python bindings to
see how much of a performance increase I can obtain over the standard library's
`hashlib.pbkdf2_hmac` implementation. My goal is a library with an interface
that is compatible with `hashlib.pbkdf2_hmac`.

The results are surprisingly good. With a basic [benchmarking script][benchmark]
on CPython 3.4.1, my implementation is about 3 times as fast as the standard
library.

```bash
$ ./bench.sh
Benchmark hashlib...
100 loops, best of 3: 60.2 msec per loop
Benchmark fastpbkdf2...
100 loops, best of 3: 20.3 msec per loop
```

With PyPy 2.6.0, the results are even better.

```bash
$ ./bench.sh
Benchmark hashlib...
100 loops, best of 3: 242 msec per loop
Benchmark fastpbkdf2...
100 loops, best of 3: 19.2 msec per loop
```

I have since release my library as a PyPI package and the code is available on
[GitHub][python-fastpbkdf2].

Simply install the package with `pip`,

```bash
pip install fastpbkdf2
```

and import the function

```python
from fastpbkdf2 import pbkdf2_hmac
```

The interface is exactly the same as `hashlib.pbkdf2_hmac` and should be a
drop-in replacement.

[blog-post]: https://jbp.io/2015/08/11/pbkdf2-performance-matters.html
[benchmark]: https://github.com/Ayrx/python-fastpbkdf2/blob/master/bench.sh
[python-fastpbkdf2]: https://github.com/Ayrx/python-fastpbkdf2
