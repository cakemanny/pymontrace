from typing import Sequence

def attach_and_exec(pid: int, python_code: str, /) -> None: ...
def exec_in_threads(pid: int, tids: Sequence[int], python_code: str, /) -> None: ...
