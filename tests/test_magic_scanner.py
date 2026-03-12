from firmtriage.magic_scanner import scan_magic

def test_detect_elf():
    data = b"\x7fELF" + b"\x00" * 100
    result = scan_magic(data)

    assert result["count_total"] == 1
    assert "ELF Executable" in result["matches"]

def test_detect_multiple_signatures():
    data = b"\x7fELF" + b"\x00" * 20 + b"hsqs" + b"\x00" * 20 + b"UBI#"
    result = scan_magic(data)

    assert result["count_total"] == 3
    assert "ELF Executable" in result["matches"]
    assert "SquashFS" in result["matches"]
    assert "UBIFS" in result["matches"]

def test_detect_none():
    data = b"this is plain text data"
    result = scan_magic(data)

    assert result["count_total"] == 0
    assert result["matches"] == []