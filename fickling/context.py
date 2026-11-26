from fickling import hook


class FicklingContextManager:
    def __init__(self, *, warn_on_stale_references: bool = False):
        self.warn_on_stale_references = warn_on_stale_references
        self.previous_entry_points = None

    def __enter__(self):
        if self.warn_on_stale_references:
            hook._warn_stale_references()
        # Snapshot instead of calling remove_hook() on exit, so we restore a
        # hook that was already installed rather than unhooking pickle.
        self.previous_entry_points = hook.snapshot_entry_points()
        hook.run_hook()
        return self

    def __exit__(self, *exc_info):
        if self.previous_entry_points is not None:
            hook.restore_entry_points(self.previous_entry_points)
            self.previous_entry_points = None


def check_safety(*, warn_on_stale_references: bool = False):
    return FicklingContextManager(warn_on_stale_references=warn_on_stale_references)
