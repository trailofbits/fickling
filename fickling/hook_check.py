from fickling.hook import run_hook

run_hook()

import pickle

with open("test.pkl", "rb") as file:
    loaded_data = pickle.load(file)
    print("Loaded data:", loaded_data)

