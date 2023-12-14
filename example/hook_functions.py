import fickling.hook as hook
import pickle
import numpy 
import os

hook.run_hook()

test_list = [1, 2, 3]
with open('safe.pkl', 'wb') as file:
    pickle.dump(test_list, file)

with open("safe.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)

class Payload(object):
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'I should have been stopped by the hook'",))

payload = Payload()

with open("unsafe.pickle", "wb") as f:
    pickle.dump(payload, f)

numpy.load("unsafe.pickle", allow_pickle=True)
