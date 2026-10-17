"""Request-local monotonic provider I/O spans; never change provider responses."""
from contextlib import contextmanager
from contextvars import ContextVar
import time
from typing import Iterator

provider_spans: ContextVar[list[tuple[int,int]] | None]=ContextVar('provider_spans',default=None)


@contextmanager
def provider_span() -> Iterator[None]:
    """Measure actual provider request/response I/O on the executing process clock."""
    started=time.perf_counter_ns()
    try:
        yield
    finally:
        spans=provider_spans.get()
        if spans is not None:
            spans.append((started,time.perf_counter_ns()))


def duration_ns(spans: list[tuple[int,int]]) -> int:
    """Measure the union of intervals so nested/overlapping spans never double count."""
    total=0
    end=0
    for left,right in sorted(spans):
        if left<0 or right<left:
            raise ValueError('invalid timing interval')
        total+=max(0,right-max(left,end))
        end=max(end,right)
    return total
