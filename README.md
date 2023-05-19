# Fickling

Fickling is a decompiler, static analyzer, and bytecode rewriter for Python
[pickle](https://docs.python.org/3/library/pickle.html) object serializations.

Pickled Python objects are in fact bytecode that is interpreted by a stack-based
virtual machine built into Python called the "Pickle Machine". Fickling can take
pickled data streams and decompile them into human-readable Python code that,
when executed, will deserialize to the original serialized object.

The authors do not prescribe any meaning to the “F” in Fickling; it could stand
for “fickle,” … or something else. Divining its meaning is a personal journey
in discretion and is left as an exercise to the reader.

Learn more about it in our [blog post](https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/)
and [DEF CON 2021 talk](https://www.youtube.com/watch?v=bZ0m_H_dEJI).

## Installation

Fickling has been tested on Python 3.6 through Python 3.9 and has very few dependencies.
It can be installed through pip:

```bash
python -m pip install fickling
```

This installs both the library and the command line utility.

## Usage

Fickling can be run programmatically:

```python
>>> import ast
>>> import pickle
>>> from fickling.pickle import Pickled
>>> print(ast.dump(Pickled.load(pickle.dumps([1, 2, 3, 4])).ast, indent=4))
Module(
    body=[
        Assign(
            targets=[
                Name(id='result', ctx=Store())],
            value=List(
                elts=[
                    Constant(value=1),
                    Constant(value=2),
                    Constant(value=3),
                    Constant(value=4)],
                ctx=Load()))])
```

Fickling can also be run as a command line utility:

```console
$ fickling pickled.data
result = [1, 2, 3, 4]
```

This is of course a simple example. However, Python pickle bytecode can run
arbitrary Python commands (such as `exec` or `os.system`) so it is a security
risk to unpickle untrusted data. You can test for common patterns of
malicious pickle files with the `--check-safety` option:

```console
$ fickling --check-safety pickled.data
Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may still be unsafe.
Do not unpickle this file if it is from an untrusted source!
```

You can also safely trace the execution of the Pickle virtual machine without
exercising any malicious code with the `--trace` option.

Finally, you can inject arbitrary Python code that will be run on unpickling
into an existing pickle file with the `--inject` option.

## License

This utility was developed by [Trail of Bits](https://www.trailofbits.com/).
It is licensed under the [GNU Lesser General Public License v3.0](LICENSE).
[Contact us](mailto:opensource@trailofbits.com) if you're looking for an
exception to the terms.

© 2021, Trail of Bits.
