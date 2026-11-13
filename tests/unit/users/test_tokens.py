"""Unit tests for one-time token generation and hashing."""

from restling_server.users.tokens import generate_token, hash_token


def test_generated_tokens_are_unique() -> None:
    first_token = generate_token()
    second_token = generate_token()

    assert first_token != second_token


def test_generated_token_has_sufficient_entropy() -> None:
    token = generate_token()

    assert len(token) >= 43


def test_token_hash_is_deterministic() -> None:
    token = generate_token()

    assert hash_token(token) == hash_token(token)


def test_different_tokens_produce_different_hashes() -> None:
    first_token = generate_token()
    second_token = generate_token()

    assert hash_token(first_token) != hash_token(second_token)


def test_token_hash_does_not_reveal_original_token() -> None:
    token = generate_token()
    token_hash = hash_token(token)

    assert token != token_hash
    assert token not in token_hash
    assert len(token_hash) == 64
