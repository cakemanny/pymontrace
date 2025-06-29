# The pymontrace Command

## Name

**pymontrace** - A production oriented Python debugger.

## Synopsis

**pymontrace** \[**-h**\] (**-c** _pyprog_ | **-p** _pid_) (**-e** _prog_text_ | **-l** _probe_filter_)

## Description

The **pymontrace** utility attaches to a running python program or starts ones
and injects debugging statements into selected probe sites.

## Options

<dt>

**-c** _pyprog_

</dt>
<dd>

Runs a Python program with the the specificed tracing enabled. _pyprog_ is
Python script file and any command arguments to be provided to it.

</dd>
<dt>

**-e** _prog_text_

</dt>
<dd>

Install the probes specified by the given **pymontrace** program into the target.
_prog_text_ must be quoted to prevent interpretation by the shell.
See [pymontrace programs](./programs.md) for a
reference on how to write pymontrace programs.

</dd>
<dt>

**-h**

</dt>
<dd>

Print a short help message.

</dd>
<dt>

**-l** _probe_filter_

</dt>
<dd>

Prints a list of detectable probe sites and then exits.
_probe_filter_ is of the form

  _probe_ \[ ':' _glob pattern_ \[ ':' _glob pattern_ \] \]

The **func** probe and **line** probes are listed based on modules that have
been imported thus far in the target.

> Note: The **-l** isn't very effective with the **-c** option as the listing
> happens before the target program has had a chance to import modules.

</dd>


## Bugs

The **-l** option is unable to find nested functions nor functions in modules
that have not yet been imported by the target program.
