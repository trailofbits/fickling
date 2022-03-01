from fickling.pickle import Pickled
import pickle
import numpy as np


arr = np.array([1, 2, 3])
fickled = Pickled.load(pickle.dumps(arr))
fickled.vetted_dependencies = ["numpy"]
fickled.vetted_calls = ["ndarray", "dtype"]

is_safe = fickled.is_likely_safe
if is_safe:
    print("✅")
else:
    print("❌")
