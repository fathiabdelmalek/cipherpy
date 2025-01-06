from abc import ABC


class BaseCipherAlgorithm(ABC):
    def __init__(self, name: str):
        self._name = name

    @property
    def name(self):
        return self._name

    def encrypt(self, plaintext):
        pass

    def decrypt(self, ciphertext):
        pass