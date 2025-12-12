import os
import tempfile
import json
from password_checker import (
    entropy_bits, contains_sequence, long_repetitions,
    score_password, SimpleBloom, save_bloom_to_file, load_bloom_from_file,
    process_passwords
)

def test_entropy_monotonicity():
    a = entropy_bits("aaaa")
    b = entropy_bits("aA1!")
    assert b > a, "Mixed-char password should have higher entropy than single-char"

def test_contains_sequence_true_false():
    assert contains_sequence("abcd") is True
    assert contains_sequence("1234") is True
    assert contains_sequence("qwe") is True  # keyboard sequence
    assert contains_sequence("xkcd42") is False

def test_long_repetitions_detected():
    assert long_repetitions("aaaa1111") is True
    assert long_repetitions("ababab") is True
    assert long_repetitions("abcabc") is False

def test_score_common_password_penalty():
    r = score_password("password")
    assert r["score"] < 10
    assert "penalty=common_password" in ", ".join(r["reasons"])

def test_process_passwords_batch_and_json_shape(tmp_path):
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text("weakpass\nStrongPass123!\n")
    results = process_passwords(["weakpass", "StrongPass123!"], json_out=False, suppress_prints=True)
    assert isinstance(results, list) and len(results) == 2
    # ensure JSON serializable
    json_str = json.dumps(results)
    assert isinstance(json_str, str)

def test_bloom_save_load(tmp_path):
    b = SimpleBloom(capacity=1000, error_rate=0.01)
    b.add("secret_password")
    path = tmp_path / "bloom.gz"
    save_bloom_to_file(b, str(path))
    loaded = load_bloom_from_file(str(path))
    assert isinstance(loaded, SimpleBloom)
    assert "secret_password" in loaded
