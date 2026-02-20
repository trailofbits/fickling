class UnsafeFileError(Exception):
    def __init__(self, filepath, info):
        super().__init__()
        self.filepath = filepath
        self.info = info

    def __str__(self):
        return f"Safety results for {self.filepath} : {self.info!s}"


class WrongMethodError(Exception):
    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __str__(self):
        return self.msg


class ResourceExhaustionError(Exception):
    """Raised when resource limits are exceeded during analysis."""

    def __init__(self, resource_type: str, limit: int, actual: int):
        self.resource_type = resource_type
        self.limit = limit
        self.actual = actual
        super().__init__(
            f"Resource limit exceeded: {resource_type} (limit={limit}, actual={actual})"
        )


class ExpansionAttackError(ResourceExhaustionError):
    """Raised when exponential expansion attack (Billion Laughs style) is detected."""

    def __init__(self, limit: int, actual: int):
        super().__init__("get_ratio", limit, actual)
