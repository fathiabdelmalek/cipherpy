class NegativeNumberException(Exception):
    def __init__(self, number: int) -> None:
        super().__init__(f"Invalid number {number}, must be greater than 0")


class InvalidAlgorithmException(Exception):
    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        super().__init__(f"Invalid algorithm: '{algorithm}'")
