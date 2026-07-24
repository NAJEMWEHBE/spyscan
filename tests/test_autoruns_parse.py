from pathlib import Path
from spyscan.collectors.autoruns import parse

def test_parse_maps_rows_to_facts():
    raw = (Path(__file__).parent / "fixtures/autorunsc_sample.csv").read_bytes()
    facts = parse(raw)
    by_label = {f.attrs["entry"]: f for f in facts}
    assert "Updater" in by_label
    upd = by_label["Updater"]
    assert upd.kind == "autostart"
    assert upd.attack_id == "T1547.001"
    assert upd.attrs["sha256"] == "2222"
    assert upd.attrs["verified"] is False
    assert "temp" in upd.attrs["image_path"].lower()

def test_parse_marks_microsoft_signed_verified_true():
    raw = (Path(__file__).parent / "fixtures/autorunsc_sample.csv").read_bytes()
    facts = parse(raw)
    sec = next(f for f in facts if f.attrs["entry"] == "SecurityHealth")
    assert sec.attrs["verified"] is True
    assert sec.attrs["signer"] == "Microsoft Windows"


def test_from_temp_flags_temp_resident_autostart():
    # #02 fix: a temp-resident autostart (classic persistence) must set from_temp
    # -- via the image path OR the launch string (autorunsc often leaves Image
    # Path blank while the real path sits in the launch command).
    hdr = "Entry Location,Entry,Signer,Company,Image Path,Launch String,SHA-256\n"
    rows = [
        r'"HKCU\Run","TempImg","(Not verified)","","C:\Users\x\AppData\Local\Temp\a.exe","C:\Users\x\AppData\Local\Temp\a.exe","h1"',
        r'"HKCU\Run","TempLaunchOnly","(Not verified)","","","C:\Windows\Temp\b.exe --run","h2"',
        r'"HKCU\Run","Normal","(Verified) Microsoft Windows","","C:\Windows\System32\svc.exe","C:\Windows\System32\svc.exe","h3"',
    ]
    facts = {f.attrs["entry"]: f for f in parse((hdr + "\n".join(rows)).encode("utf-8"))}
    assert facts["TempImg"].attrs["from_temp"] is True          # temp image path
    assert facts["TempLaunchOnly"].attrs["from_temp"] is True   # blank image, temp launch string
    assert facts["Normal"].attrs["from_temp"] is False          # system32, signed


HDR = "Entry Location,Entry,Signer,Company,Image Path,Launch String,SHA-256\n"


def test_location_header_rows_are_skipped():
    # autorunsc -a * emits one header row per ASEP location: Entry, Image Path,
    # Launch String all empty. Headers are containers, not autostarts.
    rows = [
        r'"HKLM\System\CurrentControlSet\Services","","","","",""," "',
        r'"HKCU\Run","Real","(Verified) X","","C:\p\a.exe","C:\p\a.exe","h"',
    ]
    facts = parse((HDR + "\n".join(rows)).encode("utf-8"))
    assert len(facts) == 1
    assert facts[0].attrs["entry"] == "Real"


def test_empty_signer_is_unknown_not_unsigned():
    # verified must be None (unknown) for a row autorunsc did not sign-check --
    # False is a determinate +2 penalty (score.py `verified is False`)
    rows = [r'"HKCU\Run","NoSigner","","","C:\p\a.exe","C:\p\a.exe","h"']
    f = parse((HDR + "\n".join(rows)).encode("utf-8"))[0]
    assert f.attrs["verified"] is None
    assert f.attrs["signer"] == ""


def test_launch_string_is_identity():
    # distinct real records can share location+entry+image and differ only by
    # launch (Active Setup GUID pairs, multi-action tasks): keys must not collide
    rows = [
        r'"Task","MareBackup","(Verified) MS","","C:\w\ctr.exe","C:\w\ctr.exe -m:aeinv.dll","h1"',
        r'"Task","MareBackup","(Verified) MS","","C:\w\ctr.exe","C:\w\ctr.exe -m:appraiser.dll","h2"',
    ]
    facts = parse((HDR + "\n".join(rows)).encode("utf-8"))
    assert len(facts) == 2
    assert len({f.entity_key for f in facts}) == 2
