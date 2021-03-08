import pkg_resources


def version() -> str:
    return pkg_resources.require("fickling")[0].version
