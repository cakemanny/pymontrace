# Known Issues

## macOS

* Tracing a python process on macOS which has either its binary or shared
  objects under a system path is not possible unless
  [SIP](https://support.apple.com/en-gb/102149) is
  [disabled](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection).
  This includes
    1. The system python (`/usr/bin/python3`)
    2. Python installed via the macOS universal installer found on https://python.org

  Versions installed via Homebrew should work

* Attaching to [uv builds] of Python 3.11 and 3.12 may never succeed.
  These builds appear to have inlined calls to `PyEval_SaveThread`.

[uv builds]: https://docs.astral.sh/uv/concepts/python-versions/#cpython-distributions
