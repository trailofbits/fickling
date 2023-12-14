from fickling.hook import run_hook

import pickle

run_hook()

with open("test.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)

