---
layout: post
title: Semgrep - Matching JavaScript Imports
---

[Semgrep](https://semgrep.dev/) is a great tool to add into a code review
workflow as Semgrep is aware of language semantics and automatically handles
things like different import styles and aliases well.


However, when writing rules for JavaScript, I noticed that the following import
pattern was not handled by semgrep automatically.

```js
const exec = require('child_process').exec;
exec(cmd);
```

As an example, the following Semgrep rule did not match the above code block:

```yaml
rules:
- id: child-process
  message: |
    Test
  severity: WARNING
  languages:
  - javascript
  - typescript
  patterns:
    - pattern: child_process.exec($CMD, ...)
    - pattern-not: child_process.exec("...", ...)
```

```shell
$ semgrep --config test.yaml test.js
running 1 rules...
ran 1 rules on 1 files: 0 findings
```

Until the bug is [fixed](https://github.com/returntocorp/semgrep/issues/3115)
in Semgrep, the workaround is fairly simple. Simply add the following pattern
to the rule, replacing `child_process` and `exec` with the relevant library
and function. `metevariable-regex` is used so multiple functions can be
specified at the same time:

```yaml
- patterns:
  - pattern-either:
    - pattern: $FUNC($CMD, ...)
  - pattern-not: $FUNC("...", ...)
  - pattern-inside: |
      $FUNC = require('child_process').$F
      ...
  - metavariable-regex:
      metavariable: $F
      regex: (exec|execSync)
```

Putting everything together, we get the following rule:

```yaml
rules:
- id: child-process
  message: |
    Test
  severity: WARNING
  languages:
  - javascript
  - typescript
  pattern-either:
    - patterns:
      - pattern: child_process.exec($CMD, ...)
      - pattern-not: child_process.exec("...", ...)
    - patterns:
      - pattern-either:
        - pattern: $FUNC($CMD, ...)
      - pattern-not: $FUNC("...", ...)
      - pattern-inside: |
          $FUNC = require('child_process').$F
          ...
      - metavariable-regex:
          metavariable: $F
          regex: (exec)
```

```shell
$ semgrep --config test.yaml test.js
running 1 rules...
test.js
severity:warning rule:child-process: Test

2:exec(cmd);
ran 1 rules on 1 files: 1 findings
```
