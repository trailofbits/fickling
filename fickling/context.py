import pickle

from fickling.hook import core_load, hook_pickle_load


class FicklingContextManager:
    def __init__(self, run_after_analysis=True, block=[3, 4, 5]):
        self.original_pickle_load = pickle.load
        self.run_after_analysis = run_after_analysis
        self.block = block

    def __enter__(self):
        # Modify the `hook_pickle_load` function to use the imported `core_load`
        wrapped_load = lambda file, *args, **kwargs: core_load(  # noqa
            file, run_after_analysis=self.run_after_analysis, block=self.block
        )
        pickle.load = hook_pickle_load(wrapped_load)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pickle.load = self.original_pickle_load
