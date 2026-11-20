"""PTX support removed from the public standalone build; generic binary paths only."""


def detect_file_type(_path: str) -> str:
    return "binary"


class PTXFile:
    """Legacy placeholder so imports do not break; public build does not open PTX."""

    def __init__(self, _path: str):
        self.path = _path
        self.timecodes = []

    def parse(self) -> bool:
        return False