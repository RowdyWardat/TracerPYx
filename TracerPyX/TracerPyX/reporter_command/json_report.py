from dataclasses import asdict, is_dataclass
from enum import Enum

def to_jsonable(value):
    if isinstance(value, Enum): return value.value
    if is_dataclass(value): return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict): return {k: to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)): return [to_jsonable(v) for v in value]
    return value
