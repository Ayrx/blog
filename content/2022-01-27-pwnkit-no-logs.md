---
layout: post
title: PwnKit Exploit Without Logs (CVE-2022-4034)
---

This post describes an alternative method of exploiting
[PwnKit (CVE-2022-4034)](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)
from Qualys without leaving behind logs.

The exploit method described in the Qualys advisory suggests triggering a call
to `g_printerr` call within the `validate_environment_variable` function. As a
result, most POCs set either the `SHELL` environmental or `XAUTHORITY`
environmental variable to trigger the following code path:

```c
  /* special case $SHELL */
if (g_strcmp0 (key, "SHELL") == 0)
{
  /* check if it's in /etc/shells */
  if (!is_valid_shell (value))
    {
      log_message (LOG_CRIT, TRUE,
                   "The value for the SHELL variable was not found the /etc/shells file");
      g_printerr ("\n"
                  "This incident has been reported.\n");
      goto out;
    }
}
else if ((g_strcmp0 (key, "XAUTHORITY") != 0 && strstr (value, "/") != NULL) ||
       strstr (value, "%") != NULL ||
       strstr (value, "..") != NULL)
{
  log_message (LOG_CRIT, TRUE,
               "The value for environment variable %s contains suscipious content",
               key);
  g_printerr ("\n"
              "This incident has been reported.\n");
  goto out;
}
```

However, this has the side effect of calling the `log_message` function, which
logs either the "The value for the SHELL variable was not found the /etc/shells file"
or "The value for environment variable %s contains suscipious content" error
messages to syslog.

```c
static void
log_message (gint     level,
             gboolean print_to_stderr,
             const    gchar *format,
             ...)
{
<snip>
  /* first complain to syslog */
  syslog (level,
          "%s: %s [USER=%s] [TTY=%s] [CWD=%s] [COMMAND=%s]",
          original_user_name,
          s,
          pw->pw_name,
          tty,
          original_cwd,
          command_line);

  /* and then on stderr */
  if (print_to_stderr)
    g_printerr ("%s\n", s);

  g_free (s);
}
```

The Qualys advisory hinted at another exploitation technique that does not
leave traces in the log:

> Important: this exploitation technique leaves traces in the logs (either
"The value for the SHELL variable was not found the /etc/shells file" or
"The value for environment variable [...] contains suscipious content").
However, please note that this vulnerability is also exploitable without
leaving any traces in the logs, but this is left as an exercise for the
interested reader.

Inspecting the code, we notice the following code path that calls `g_printerr`:

```c
if (access (path, F_OK) != 0)
{
  g_printerr ("Error accessing %s: %s\n", path, g_strerror (errno));
  goto out;
}
```

This can be triggered if the `path` variable, which is the
`GCONV_PATH=./value` file is not present on the file system. However, the
out-of-bounds write that triggers the vulnerability only happens if the same
file _is_ present on the file system.

```c
if (path[0] != '/')
{
  /* g_find_program_in_path() is not suspectible to attacks via the environment */
  s = g_find_program_in_path (path);
  if (s == NULL)
    {
      g_printerr ("Cannot run program %s: %s\n", path, strerror (ENOENT));
      goto out;
    }
  g_free (path);
  argv[n] = path = s;
}
```

This means that we need to remove the file after `g_find_program_in_path` was
called but before the `access` check happens. A classic race condition exploit.

A final hurdle block successful exploitation using this technique. If we lose
the race, `pkexec` brings up the PolKit prompt asking for a password which
also leaves traces syslog. We can avoid this by calling `execve` in a child
process and exploiting the following code path which exits early if the parent
process of `pkexec` is dead:

```c
pid_of_caller = getppid ();
if (pid_of_caller == 1)
{
  /* getppid() can return 1 if the parent died (meaning that we are reaped
   * by /sbin/init); In that case we simpy bail.
   */
  g_printerr ("Refusing to render service to dead parents.\n");
  goto out;
}
```

A proof-of-concept exploit with this technique can be found on my Github
repository: [https://github.com/Ayrx/CVE-2021-4034](https://github.com/Ayrx/CVE-2021-4034).
