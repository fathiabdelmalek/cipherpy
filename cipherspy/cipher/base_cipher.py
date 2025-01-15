from abc import ABC, abstractmethod


class BaseCipherAlgorithm(ABC):
    def __init__(self, name: str):
        self._name = name

    @property
    def name(self):
        return self._name

    @abstractmethod
    def encrypt(self, plaintext):
        pass

    @abstractmethod
    def decrypt(self, ciphertext):
        pass