import sys
from typing import Optional, Set, TextIO, Tuple

if sys.version_info < (3, 9):
    from astunparse import unparse
else:
    from ast import unparse

from .pickle import Interpreter, Pickled, Proto


def check_safety(
    pickled: Pickled, stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None
) -> bool:
    if stdout is None:
        stdout = sys.stdout
    if stderr is None:
        stderr = sys.stderr

    properties = pickled.properties
    likely_safe = True
    reported_shortened_code = set()

    def shorten_code(ast_node) -> Tuple[str, bool]:
        code = unparse(ast_node).strip()
        if len(code) > 32:
            cutoff = code.find("(")
            if code[cutoff] == "(":
                shortened_code = f"{code[:code.find('(')].strip()}(...)"
            else:
                shortened_code = code
        else:
            shortened_code = code
        was_already_reported = shortened_code in reported_shortened_code
        reported_shortened_code.add(shortened_code)
        return shortened_code, was_already_reported

    had_proto = False
    proto_versions: Set[int] = set()
    for i, opcode in enumerate(pickled):
        if isinstance(opcode, Proto):
            if had_proto:
                likely_safe = False
                if i == 2:
                    suffix = "rd"
                elif i == 1:
                    suffix = "nd"
                elif i == 0:
                    suffix = "st"
                else:
                    suffix = "th"
                if opcode.version in proto_versions:
                    stdout.write(
                        f"The {i+1}{suffix} opcode is a duplicate PROTO, which is unusual and may"
                        f"be indicative of a tampered pickle\n"
                    )
                else:
                    stdout.write(
                        f"The {i+1}{suffix} opcode is a duplicate PROTO with a different version "
                        "than reported in the previous PROTO opcode, which is almost certainly a "
                        "sign of a tampered pickle\n"
                    )
            else:
                had_proto = True
            if opcode.version >= 2 and i > 0:
                likely_safe = False
                stdout.write(
                    f"The protocol version is {opcode.version}, but the PROTO opcode is not the"
                    "first opcode in the pickle, as required for versions 2 and later; this may be "
                    "indicative of a tampered pickle\n"
                )
            proto_versions.add(opcode.version)

    for node in pickled.non_standard_imports():
        likely_safe = False
        shortened, already_reported = shorten_code(node)
        if not already_reported:
            stdout.write(
                f"`{shortened}` imports a Python module that is not a part of "
                "the standard library; this can execute arbitrary code and is "
                "inherently unsafe\n"
            )
    overtly_bad_evals = []
    for node in properties.non_setstate_calls:
        if hasattr(node.func, "id") and node.func.id in properties.likely_safe_imports:
            # if the call is to a constructor of an object imported from the Python
            # standard library, it's probably okay
            continue
        likely_safe = False
        shortened, already_reported = shorten_code(node)
        if (
            shortened.startswith("eval(")
            or shortened.startswith("exec(")
            or shortened.startswith("compile(")
            or shortened.startswith("open(")
        ):
            # this is overtly bad, so record it and print it at the end
            overtly_bad_evals.append(shortened)
        elif not already_reported:
            stdout.write(
                f"Call to `{shortened}` can execute arbitrary code and is inherently unsafe\n"
            )
    for node in pickled.unsafe_imports():
        likely_safe = False
        shortened, _ = shorten_code(node)
        stdout.write(
            f"`{shortened}` is suspicious and indicative of an overtly malicious pickle file\n"
        )
    for overtly_bad_eval in overtly_bad_evals:
        stdout.write(
            f"Call to `{overtly_bad_eval}` is almost certainly evidence of a "
            "malicious pickle file\n"
        )
    interpreter = Interpreter(pickled)
    for varname, asmt in interpreter.unused_assignments().items():
        likely_safe = False
        shortened, _ = shorten_code(asmt.value)
        stderr.write(
            f"Variable `{varname}` is assigned value `{shortened}` but unused afterward; "
            f"this is suspicious and indicative of a malicious pickle file\n"
        )
    if likely_safe:
        stderr.write(
            "Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may "
            "still be unsafe.\n\nDo not unpickle this file if it is from an untrusted source!\n"
        )
        return True
    else:
        return False
