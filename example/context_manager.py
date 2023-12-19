import pickle

import fickling

test_list = [1, 2, 3]

with open("safe.pkl", "wb") as file:
    pickle.dump(test_list, file)

# This context manager scans the file
# It will halt unpickling for files of high severity
with fickling.check_safety():
    with open("safe.pkl", "rb") as file:
        safe_data = pickle.load(file)
        print(safe_data)
