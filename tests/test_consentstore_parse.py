from spyscan.collectors.consentstore import parse


def test_in_use_when_stop_zero():
    rows = [("HKCU", "webcam", "SomeStoreApp_8wekyb3d8bbwe", 132000000000000, 0)]
    f = parse(rows)[0]
    assert f.kind == "device_use"
    assert f.attrs["in_use_now"] is True
    assert f.attrs["capability"] == "webcam"
    assert f.attack_id == "T1125"


def test_not_in_use_when_stop_nonzero():
    rows = [("HKCU", "microphone", "App", 132000000000000, 132000000000001)]
    assert parse(rows)[0].attrs["in_use_now"] is False


def test_nonpackaged_leaf_decodes_to_exe_path_and_keeps_container_in_key():
    rows = [("HKCU", "microphone",
             "NonPackaged\\C:#Program Files#Google#chrome.exe", 133000000000000, 0)]
    f = parse(rows)[0]
    assert f.attrs["app"] == r"C:\Program Files\Google\chrome.exe"
    assert f.attrs["packaged"] is False
    assert f.label == r"microphone: C:\Program Files\Google\chrome.exe"
    assert f.entity_key == (
        "consentstore::microphone::HKCU::NonPackaged::"
        r"C:\Program Files\Google\chrome.exe")
    assert f.attrs["in_use_now"] is True


def test_packaged_app_key_and_attrs():
    rows = [("HKLM", "webcam", "Microsoft.WindowsCamera_8wekyb3d8bbwe", None, None)]
    f = parse(rows)[0]
    assert f.attrs["packaged"] is True
    assert f.attrs["app"] == "Microsoft.WindowsCamera_8wekyb3d8bbwe"
    assert f.entity_key == (
        "consentstore::webcam::HKLM::Microsoft.WindowsCamera_8wekyb3d8bbwe")
    assert f.attrs["in_use_now"] is False  # missing stop is unknown, not in-use


def test_scope_is_identity_hkcu_hklm_do_not_collide():
    rows = [("HKCU", "microphone", "NonPackaged\\svchost.exe", 1, 2),
            ("HKLM", "microphone", "NonPackaged\\svchost.exe", 3, 4)]
    facts = parse(rows)
    keys = {f.entity_key for f in facts}
    assert len(keys) == 2
    scopes = {f.attrs["scope"] for f in facts}
    assert scopes == {"HKCU", "HKLM"}


def test_keys_unique_per_scan_for_realistic_rowset():
    # one packaged + two NonPackaged leaves across both hives, same cap
    rows = [
        ("HKCU", "microphone", "SomeStoreApp_x", 1, 2),
        ("HKCU", "microphone", "NonPackaged\\C:#tools#rec.exe", 1, 2),
        ("HKLM", "microphone", "NonPackaged\\svchost.exe", 1, 2),
    ]
    facts = parse(rows)
    assert len(facts) == 3
    assert len({f.entity_key for f in facts}) == 3
