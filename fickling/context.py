import fickling.hook as hook
from fickling.analysis import Severity


class FicklingContextManager:
    """Context manager that activates fickling's safety hooks on enter and removes them on exit."""

    def __init__(self, max_acceptable_severity=Severity.LIKELY_SAFE):
        self.max_acceptable_severity = max_acceptable_severity

    def __enter__(self):
        hook.run_hook(max_acceptable_severity=self.max_acceptable_severity)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        hook.remove_hook()


def check_safety():
    return FicklingContextManager()
