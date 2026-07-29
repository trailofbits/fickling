import fickling.hook as hook


class FicklingContextManager:
    def __init__(self):
        self.previous_entry_points = None

    def __enter__(self):
        # Snapshot instead of calling remove_hook() on exit, so we restore a
        # hook that was already installed rather than unhooking pickle.
        self.previous_entry_points = hook.snapshot_entry_points()
        hook.run_hook()
        return self

    def __exit__(self, *exc_info):
        if self.previous_entry_points is not None:
            hook.restore_entry_points(self.previous_entry_points)
            self.previous_entry_points = None


def check_safety():
    return FicklingContextManager()
