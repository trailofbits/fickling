from setuptools import setup, find_packages
from sys import version_info

if version_info >= (3, 9):
    # ast.unparse was added in Python 3.9
    requirements = []
else:
    requirements = ["astunparse~=1.6.3"]

setup(
    name="fickling",
    description="A static analyzer and interpreter for Python pickle data",
    license="LGPL-3.0-or-later",
    url="https://github.com/trailofbits/fickling",
    author="Trail of Bits",
    version="0.0.3",
    packages=find_packages(exclude=["test"]),
    python_requires=">=3.6",
    install_requires=requirements,
    extras_require={
        "dev": ["flake8", "pytest", "twine"],
        # Dependencies necessary to run the examples:
        "examples": [
            "numpy",
            "pytorchfi~=0.4.1",
            "torch~=1.9.0",
            "torchvision~=0.10.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "fickling = fickling.__main__:main"
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Utilities"
    ]
)
