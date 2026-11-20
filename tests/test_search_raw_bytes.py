from src.search import SearchWorker, classify_search_query


def _run(worker):
    completed = []
    failed = []
    worker.search_finished.connect(completed.append)
    worker.search_failed.connect(failed.append)
    worker.run()
    assert failed == []
    assert len(completed) == 1
    return completed[0]


def test_text_search_uses_absolute_raw_byte_offsets_and_crosses_display_lines():
    needle = b"Blue Cat's PatchWork Synth 1"
    data = (b"." * 15) + needle + b"." + needle

    results = _run(SearchWorker(data, needle.decode("ascii"), search_type="text"))

    assert [result.position for result in results] == [15, 15 + len(needle) + 1]


def test_text_search_is_case_insensitive_without_changing_offsets():
    results = _run(SearchWorker(b"xxBLUE Catxxblue cat", "Blue Cat", search_type="text"))

    assert [result.position for result in results] == [2, 12]


def test_hex_search_operates_on_bytes_not_rendered_hex_text():
    results = _run(SearchWorker(b"\x00\xde\xad\xbe\xef\x00", "DE AD BE EF", search_type="hex"))

    assert [result.position for result in results] == [1]


def test_search_box_auto_detects_spaced_hex_bytes():
    assert classify_search_query("42 6C 75 65") == ("hex", "42 6C 75 65")
    assert classify_search_query("Blue Cat's PatchWork Synth 1") == (
        "text", "Blue Cat's PatchWork Synth 1"
    )


def test_search_box_explicit_prefix_resolves_ambiguous_input():
    assert classify_search_query("text: DE AD") == ("text", "DE AD")
    assert classify_search_query("hex: DE AD") == ("hex", "DE AD")
