from fickling.pickle import Pickled
import numpy as np
import pickle
from sklearn import svm, datasets

def check_vetted(p: Pickled):
    if p.has_unvetted_dependency:
        print(f"unvetted deps : {p.unvetted_dependencies}")

# sklearn
clf = svm.SVC()
X, y = datasets.load_iris(return_X_y=True)
clf.fit(X, y)
s = pickle.dumps(clf)

p = Pickled.load(s)
p.vetted_dependencies = ["numpy.ndarray", "sklearn.svm._classes.SVC", "numpy.core.multiarray._reconstruct", "numpy.dtype", "numpy.core.multiarray.scalar"]
check_vetted(p)

# numpy
arr = np.ndarray([1, 2, 3])
p = Pickled.load(pickle.dumps(arr))
p.vetted_dependencies = ["numpy.ndarray"]
check_vetted(p)

