

def parse_probe(probe_spec):
    probe_name, probe_args = probe_spec.split(':', 1)
    if probe_name == 'line':
        filename, lineno = probe_args.split(':')
        return (probe_name, filename, int(lineno))
    else:
        raise ValueError('only "line" probe supported right now')


def format_bootstrap_snippet(parsed_probe, action, comm_file):
    user_break = parsed_probe[1:]
    return ('import pymontrace.tracee; '
            f'pymontrace.tracee.settrace({user_break!r}, {action!r}, {comm_file!r})')


def format_untrace_snippet():
    return 'import pymontrace.tracee; pymontrace.tracee.unsettrace()'
