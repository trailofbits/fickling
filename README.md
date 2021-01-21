# Fickling

Fickling is a decompiler and static analyzer for Python Python [pickle](https://docs.python.org/3/library/pickle.html)
object serializations. Pickled Python objects are in fact bytecode that is interpreted by a stack-based virtual machine
built into Python called the "Pickle Machine". It can take pickled data streams and decompile them into human-readable
Python code that, when executed, will deserialize to the original serialized object.

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

Fickling can also be run as a commandline utility:
```bash
$ fickling pickled.data
result = [1, 2, 3, 4]
```

This is of course a simple example. However, Python pickle bytecode can run arbitrary Python commands (such as 
`exec` or `os.system`) so it is a security risk to unpickle untrusted data.

## Future Directions

Fickling will soon have support for editing and injecting Pickle bytecode, as well as static analysis detectors that can
identify certain types of malicious pickle bytecode.

## License

This utility was developed by [Trail of Bits](https://www.trailofbits.com/).
It is licensed under the [GNU Lesser General Public License v3.0](LICENSE).
[Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
© 2020, Trail of Bits.
