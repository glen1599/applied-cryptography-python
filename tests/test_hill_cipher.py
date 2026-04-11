"""Tests for the Hill cipher.

The known-answer case is the textbook 2x2 example: the key [[3, 3], [2, 5]]
maps "help" to "hiat".
"""

from __future__ import annotations

import numpy as np
import pytest

from applied_crypto.hill_cipher import (
    MODULUS,
    HillCipher,
    InvalidKeyError,
    _bareiss_determinant,
    inverse_modulo_matrix,
)

TEXTBOOK_KEY = [[3, 3], [2, 5]]
COURSEWORK_KEY = [[3, 10, 20], [20, 9, 17], [9, 4, 17]]


# --- known answers ---------------------------------------------------------


def test_textbook_key_encrypts_help_to_hiat():
    assert HillCipher(TEXTBOOK_KEY).encrypt("help") == "hiat"


def test_textbook_key_round_trips():
    cipher = HillCipher(TEXTBOOK_KEY)
    assert cipher.decrypt(cipher.encrypt("help")) == "help"


def test_coursework_key_round_trips():
    cipher = HillCipher(COURSEWORK_KEY)
    message = "kitalawan"
    assert cipher.decrypt(cipher.encrypt(message)) == message


@pytest.mark.parametrize(
    "message",
    ["a", "abcd", "serangsubuh", "thequickbrownfoxjumpsoverthelazydog"],
)
def test_round_trip_for_many_lengths(message):
    cipher = HillCipher(COURSEWORK_KEY)
    assert cipher.decrypt(cipher.encrypt(message)).startswith(message)


# --- normalisation ---------------------------------------------------------


def test_input_is_lower_cased_and_stripped():
    cipher = HillCipher(TEXTBOOK_KEY)
    assert cipher.encrypt("Kita lawan!") == cipher.encrypt("kitalawan")


def test_non_alpha_characters_are_ignored():
    cipher = HillCipher(COURSEWORK_KEY)
    assert cipher.encrypt("kita-lawan 123") == cipher.encrypt("kitalawan")


def test_empty_input_encrypts_to_empty():
    assert HillCipher(TEXTBOOK_KEY).encrypt("") == ""


def test_digits_only_input_is_rejected_when_nothing_remains():
    assert HillCipher(TEXTBOOK_KEY).encrypt("12345") == ""


# --- structure -------------------------------------------------------------


def test_block_size_follows_the_key_order():
    assert HillCipher(COURSEWORK_KEY).block_size == 3
    assert HillCipher(TEXTBOOK_KEY).block_size == 2


def test_ciphertext_length_is_a_multiple_of_the_block_size():
    cipher = HillCipher(COURSEWORK_KEY)
    for message in ("a", "ab", "abc", "abcd"):
        assert len(cipher.encrypt(message)) % 3 == 0


def test_padding_fills_the_last_block():
    cipher = HillCipher(COURSEWORK_KEY)
    assert cipher.encrypt("kita") == cipher.encrypt("kitaxx")


def test_determinant_is_computed_exactly():
    assert HillCipher(TEXTBOOK_KEY).determinant == 9
    assert _bareiss_determinant(np.array(COURSEWORK_KEY)) == HillCipher(COURSEWORK_KEY).determinant


def test_four_by_four_determinant_has_no_float_drift():
    matrix = np.array([[2, 0, 0, 0], [0, 3, 0, 0], [0, 0, 5, 0], [0, 0, 0, 7]], dtype=np.int64)
    assert _bareiss_determinant(matrix) == 210


def test_singular_matrix_has_zero_determinant():
    assert _bareiss_determinant(np.array([[1, 2], [2, 4]])) == 0


# --- key validation --------------------------------------------------------


def test_key_with_even_determinant_is_rejected():
    # det([[1, 2], [3, 4]]) == -2, which shares a factor with 26.
    with pytest.raises(InvalidKeyError, match=r"coprime|divisible"):
        HillCipher([[1, 2], [3, 4]])


def test_key_with_determinant_divisible_by_thirteen_is_rejected():
    matrix = np.array([[1, 0], [13, 1]], dtype=np.int64)  # determinant 1 is fine
    assert HillCipher(matrix).is_invertible
    with pytest.raises(InvalidKeyError):
        HillCipher([[13, 0], [0, 1]])  # determinant 13


def test_non_square_key_is_rejected():
    with pytest.raises(InvalidKeyError, match="square"):
        HillCipher([[1, 2, 3], [4, 5, 6]])


def test_one_by_one_key_is_rejected():
    with pytest.raises(InvalidKeyError, match="2x2"):
        HillCipher([[3]])


def test_fractional_key_is_rejected():
    with pytest.raises(InvalidKeyError, match="integers"):
        HillCipher([[1.5, 2], [3, 5]])


def test_is_invertible_reports_true_for_a_valid_key():
    assert HillCipher(TEXTBOOK_KEY).is_invertible


# --- modular inverse -------------------------------------------------------


def test_inverse_times_key_is_identity():
    key = np.array(COURSEWORK_KEY, dtype=np.int64) % MODULUS
    inverse = inverse_modulo_matrix(key)
    assert np.array_equal((key @ inverse) % MODULUS, np.eye(key.shape[0], dtype=np.int64))


def test_inverse_entries_are_reduced():
    inverse = inverse_modulo_matrix(np.array(TEXTBOOK_KEY, dtype=np.int64))
    assert inverse.min() >= 0
    assert inverse.max() < MODULUS
