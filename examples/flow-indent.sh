#!/bin/sh

if [ "$1" = '-h' ]; then
    cat <<EOF

$(basename "$0") shows an example of using func probes with increasing \
and decreasing indentation to show the execution flow of a script.

In this case, the tracing also shows pymontrace using runpy to start the \
provided script.

Probes installed. Hit CTRL-C to end...
 -> threading.settrace
 <- threading.settrace
[...]
     -> runpy._run_code
       -> __main__.<module>
         -> __main__.main
           -> __main__.f
             -> __main__.g
             <- __main__.g
             -> __main__.g
             <- __main__.g
             -> __main__.g
             <- __main__.g
             -> __main__.g
^CRemoving probes...
             <- __main__.g
           <- __main__.f
         <- __main__.main
       <- __main__.<module>
     <- runpy._run_code
[...]
EOF
    exit 0
fi

pymontrace -c "$(dirname "$0")/script_to_debug.py" -e '
pymontrace::BEGIN {{
    vars.indent = 0
}}

func:*:start {{
    print("  " * vars.indent, "->", qualname())
    vars.indent += 1
}}
func:*:return {{
    vars.indent -= 1
    print("  " * vars.indent, "<-", qualname())
}}
'
