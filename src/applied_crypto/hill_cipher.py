"""The Hill cipher: a polygraphic substitution cipher over ``Z_26``.

Lester Hill, 1929. Plaintext is split into blocks of ``n`` letters, each block
is read as a column vector ``x``, and the ciphertext block is the matrix
product

    y = K · x  (mod 26)

Decryption multiplies by the modular inverse of ``K``, which only exists when
``det(K)`` is coprime with 26 — that is, when it is not divisible by 2 or 13.
Roughly a third of all matrices fail that test, so the key is validated
explicitly rather than failing later inside the inverse.

Every step uses exact integer arithmetic. The original coursework version
recovered the determinant through ``numpy.linalg.det``, whose floating-point
rounding breaks on larger keys.

The classic weaknesses are inherent to the cipher and not fixed here: it is
linear, it leaks letter frequencies of the plaintext modulo the block size, and
a known-plaintext attack recovers the key from ``n`` blocks.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
MODULUS = len(ALPHABET)
# Letter used to pad the final block; a real deployment would use a random one.
DEFAULT_PADDING = "x"


class InvalidKeyError(ValueError):
    """Raised when a key matrix cannot be used for a Hill cipher."""


# --- exact integer linear algebra -----------------------------------------


def _bareiss_determinant(matrix: np.ndarray) -> int:
    """Determinant of an integer matrix, exactly, via Bareiss elimination.

    Fraction-free Gaussian elimination keeps every intermediate value an
    integer, so there is no floating-point rounding to recover from.

    Args:
        matrix: Square integer matrix.

    Returns:
        The determinant as a Python int.
    """
    work = matrix.astype(np.int64).copy()
    size = work.shape[0]
    sign = 1
    previous = 1

    for pivot_index in range(size - 1):
        if work[pivot_index, pivot_index] == 0:
            swap = next(
                (row for row in range(pivot_index + 1, size) if work[row, pivot_index] != 0),
                None,
            )
            if swap is None:
                return 0
            work[[pivot_index, swap]] = work[[swap, pivot_index]]
            sign = -sign

        pivot = work[pivot_index, pivot_index]
        for row in range(pivot_index + 1, size):
            for column in range(pivot_index + 1, size):
                work[row, column] = (
                    work[row, column] * pivot - work[row, pivot_index] * work[pivot_index, column]
                ) // previous
        previous = pivot

    return int(sign * work[size - 1, size - 1])


def _minor(matrix: np.ndarray, drop_row: int, drop_column: int) -> np.ndarray:
    """Matrix with one row and one column removed."""
    return np.delete(np.delete(matrix, drop_row, axis=0), drop_column, axis=1)


def _adjugate(matrix: np.ndarray) -> np.ndarray:
    """Transposed cofactor matrix, built from exact integer minors."""
    size = matrix.shape[0]
    if size == 1:
        return np.ones((1, 1), dtype=np.int64)

    cofactors = np.zeros((size, size), dtype=np.int64)
    for row in range(size):
        for column in range(size):
            sign = -1 if (row + column) % 2 else 1
            cofactors[row, column] = sign * _bareiss_determinant(_minor(matrix, row, column))
    return cofactors.T


def _inverse_modulo(value: int, modulus: int) -> int:
    """Modular multiplicative inverse, or raise when it does not exist."""
    value %= modulus
    if value == 0:
        raise InvalidKeyError("determinant is divisible by 26: the key has no inverse")
    try:
        return pow(int(value), -1, modulus)
    except ValueError as error:  # raised when gcd(value, modulus) != 1
        raise InvalidKeyError(
            f"determinant {value} is not coprime with {modulus}: the key is not invertible"
        ) from error


def inverse_modulo_matrix(matrix: np.ndarray, modulus: int = MODULUS) -> np.ndarray:
    """Invert a square integer matrix modulo ``modulus``.

    Args:
        matrix: Square integer matrix.
        modulus: Modulus to invert under.

    Returns:
        The inverse matrix, with every entry in ``[0, modulus)``.

    Raises:
        InvalidKeyError: If the determinant shares a factor with ``modulus``.
    """
    determinant = _bareiss_determinant(matrix)
    determinant_inverse = _inverse_modulo(determinant, modulus)
    inverse = (determinant_inverse * _adjugate(matrix)) % modulus
    return inverse % modulus


# --- the cipher ------------------------------------------------------------


class HillCipher:
    """Encrypt and decrypt text with an ``n x n`` Hill key matrix.

    Example:
        >>> cipher = HillCipher([[3, 3], [2, 5]])
        >>> ciphertext = cipher.encrypt("help")
        >>> ciphertext
        'hiat'
        >>> cipher.decrypt(ciphertext)
        'help'
    """

    def __init__(self, key: Sequence[Sequence[int]], padding: str = DEFAULT_PADDING) -> None:
        """
        Args:
            key: Square integer matrix. Its determinant must be coprime with 26.
            padding: Letter appended to fill the final block.

        Raises:
            InvalidKeyError: If the matrix is not square, is empty, contains a
                non-integer entry, or has a determinant that is not invertible
                modulo 26.
        """
        matrix = np.asarray(key)
        if matrix.ndim != 2 or matrix.shape[0] != matrix.shape[1]:
            raise InvalidKeyError("key must be a square matrix")
        if matrix.shape[0] < 2:
            raise InvalidKeyError("key must be at least 2x2")
        if not np.issubdtype(matrix.dtype, np.integer):
            if not np.all(np.equal(np.mod(matrix, 1), 0)):
                raise InvalidKeyError("key entries must be integers")
            matrix = matrix.astype(np.int64)

        self.padding = padding
        self.key = matrix % MODULUS
        self._determinant = _bareiss_determinant(self.key)
        # Raises InvalidKeyError when the determinant is not coprime with 26.
        self.inverse = inverse_modulo_matrix(self.key)

    # -- properties -------------------------------------------------------

    @property
    def block_size(self) -> int:
        """Number of letters processed per block (the key order)."""
        return int(self.key.shape[0])

    @property
    def determinant(self) -> int:
        """Determinant of the key matrix, exactly."""
        return self._determinant

    @property
    def is_invertible(self) -> bool:
        """Whether the key can decrypt as well as encrypt."""
        return self.determinant % 2 != 0 and self.determinant % 13 != 0

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _to_numbers(text: str) -> list[int]:
        try:
            return [ALPHABET.index(character) for character in text]
        except ValueError as error:
            raise ValueError(f"input must contain only {ALPHABET!r}") from error

    @staticmethod
    def _to_text(numbers: Sequence[int]) -> str:
        return "".join(ALPHABET[int(number) % MODULUS] for number in numbers)

    def _blocks(self, numbers: Sequence[int]) -> np.ndarray:
        size = self.block_size
        padded = list(numbers)
        while len(padded) % size:
            padded.append(ALPHABET.index(self.padding))
        return np.array(padded, dtype=np.int64).reshape(-1, size)

    def _apply(self, matrix: np.ndarray, text: str) -> str:
        cleaned = "".join(character for character in text.lower() if character in ALPHABET)
        if not cleaned:
            return ""
        transformed = (self._blocks(self._to_numbers(cleaned)) @ matrix.T) % MODULUS
        return self._to_text(transformed.reshape(-1))

    # -- public API -------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Encrypt ``plaintext``.

        Characters outside ``a-z`` are removed and the input is lower-cased, so
        ``"Kita lawan!"`` and ``"kitalawan"`` produce the same ciphertext. The
        final block is padded with :attr:`padding`.
        """
        return self._apply(self.key, plaintext)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ``ciphertext`` produced by :meth:`encrypt`."""
        return self._apply(self.inverse, ciphertext)
