import numpy
import os
import pickle
from fickling.fickle import Pickled


class Test(object):
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'Now I can run malicious code! Never trust a pickle.'",))


payload = Test()

with open("a-file.pickle", "wb") as f:
    pickle.dump(payload, f)

numpy.load("a-file.pickle", allow_pickle=True)

fickled_payload = Pickled.load(pickle.dumps(payload))

safety = fickled_payload.is_likely_safe

#print(dir(safety))

#print(safety.severity)

print(safety)