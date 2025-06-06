import ast
from ast import unparse
from typing import Union

from .fickle import Interpreter, MarkObject, Opcode, Stack


class Trace:
    def __init__(self, interpreter: Interpreter):
        self.interpreter: Interpreter = interpreter

    def on_pop(self, popped_value: Union[ast.expr, MarkObject]):
        if isinstance(popped_value, MarkObject):
            value = "MARK"
        else:
            value = unparse(popped_value).strip()
        print(f"\tPopped {value}")

    def on_push(self, pushed_value: Union[ast.expr, MarkObject]):
        if isinstance(pushed_value, MarkObject):
            value = "MARK"
        else:
            value = unparse(pushed_value).strip()
        print(f"\tPushed {value}")

    def on_memoize(self, index: int, value: ast.expr):
        print(f"\tMemoized {index} -> {unparse(value).strip()}")

    def on_update_memo(self, index: int, old_value: ast.expr, new_value: ast.expr):
        print(f"\tMemo index {index} changed from {unparse(old_value).strip()} to " f"{unparse(new_value).strip()}")

    def on_statement(self, statement: ast.stmt):
        print(f"\t{unparse(statement).strip()}")

    def on_opcode(self, opcode: Opcode):
        print(opcode.name)

    def run(self) -> ast.AST:
        while True:
            memory_before = dict(self.interpreter.memory)
            stack_before = Stack(self.interpreter.stack)
            len_module_before = len(self.interpreter.module_body)
            try:
                opcode = self.interpreter.step()
            except StopIteration:
                break
            self.on_opcode(opcode)
            for added in self.interpreter.module_body[len_module_before:]:
                self.on_statement(added)
            common_prefix_length = 0
            for before, after in zip(stack_before, self.interpreter.stack):
                if before != after:
                    break
                common_prefix_length += 1
            for before in reversed(stack_before[common_prefix_length:]):
                self.on_pop(before)
            for after in self.interpreter.stack[common_prefix_length:]:
                self.on_push(after)
            for k, v in self.interpreter.memory.items():
                if k not in memory_before:
                    self.on_memoize(k, v)
                elif v != memory_before[k]:
                    self.on_update_memo(k, memory_before[k], v)
        return self.interpreter.to_ast()
