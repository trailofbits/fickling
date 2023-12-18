import pickle

from fickling.hook import hook_pickle_load
import fickling.loader as loader


class FicklingContextManager:
    def __init__(self, run_after_analysis=True, block=[3, 4, 5]):
        # TODO Determine what the best defaults for block are
        self.original_pickle_load = pickle.load
        self.run_after_analysis = run_after_analysis
        self.block = block

    def __enter__(self):
        # Modify the `hook_pickle_load` function to use the imported loader
        wrapped_load = lambda file, *args, **kwargs: loader.load(  # noqa
            file, run_after_analysis=self.run_after_analysis, block=self.block
        )
        pickle.load = hook_pickle_load(wrapped_load)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pickle.load = self.original_pickle_load
