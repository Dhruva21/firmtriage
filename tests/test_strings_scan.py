from firmtriage.strings_scan import strings_scan

def test_basic_strings():
    data = b"hello firmware update system debug console"

    result = strings_scan(data)

    assert result["count_total"] > 0
    assert "hello firmware update system debug console" in result["top_samples"]

def test_url_detection():
    data = b"Connect to https://example.com/api now"

    result = strings_scan(data)

    assert "https://example.com/api" in result["urls"]

def test_ip_detection():
    data = b"server address 192.168.1.10 connected"

    result = strings_scan(data)

    assert "192.168.1.10" in result["ips"]

def test_crypto_marker():
    data = b"-----BEGIN CERTIFICATE-----"

    result = strings_scan(data)

    assert "BEGIN CERTIFICATE" in result["crypto_markers"]

def test_debug_marker():
    data = b"UART debug console active"

    result = strings_scan(data)

    assert "UART" in result["debug_markers"]

def test_empty_input():
    data = b""

    result = strings_scan(data)

    assert result["count_total"] == 0