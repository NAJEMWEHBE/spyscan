from pathlib import Path
from spyscan.collectors.drivers import parse

FIX = Path(__file__).parent / "fixtures"

def _raw():
    return (FIX / "driverquery_sample.csv").read_bytes()

def test_parses_drivers_to_facts():
    facts = parse(_raw())
    by_name = {f.attrs["module"]: f for f in facts}
    assert "evilrk" in by_name
    assert by_name["evilrk"].kind == "driver"

def test_driver_fields_and_temp_signal():
    facts = parse(_raw())
    rk = next(f for f in facts if f.attrs["module"] == "evilrk")
    assert "temp" in rk.attrs["path"].lower()
    assert rk.attrs["from_temp"] is True
    assert rk.attrs["start_mode"] == "Auto"
    assert rk.observed["state"] == "Running"     # runtime state: never diffed
    assert "state" not in rk.attrs
    assert rk.attrs["driver_type"] == "Kernel"   # trailing space trimmed
    assert rk.entity_key == "drivers::evilrk"    # module only -- path is an attr


def test_driver_update_is_changed_not_add_remove_pair():
    # a DriverStore update moves the .sys to a new versioned dir; the entity must
    # keep its key (diff -> 'changed'), not mint an added+removed phantom pair
    from spyscan.diff import diff_facts
    hdr = (b'"Module Name","Display Name","Description","Driver Type","Start Mode",'
           b'"State","Status","Accept Stop","Accept Pause","Paged Pool(bytes)",'
           b'"Code(bytes)","BSS(bytes)","Link Date","Path","Init(bytes)"\n')
    v1 = hdr + (b'"acpi","ACPI","d","Kernel","Boot","Running","OK","TRUE","FALSE",'
                b'"0","0","0","1/1/2025",'
                b'"C:\\W\\DriverStore\\FileRepository\\acpi.inf_amd64_aaaa\\acpi.sys","0"\n')
    v2 = hdr + (b'"acpi","ACPI","d","Kernel","Boot","Running","OK","TRUE","FALSE",'
                b'"0","0","0","2/2/2026",'
                b'"C:\\W\\DriverStore\\FileRepository\\acpi.inf_amd64_bbbb\\acpi.sys","0"\n')
    d = diff_facts(parse(v1), parse(v2))
    assert (len(d["added"]), len(d["removed"]), len(d["changed"])) == (0, 0, 1)


def test_state_flip_alone_is_not_changed():
    hdr = (b'"Module Name","Display Name","Description","Driver Type","Start Mode",'
           b'"State","Status","Accept Stop","Accept Pause","Paged Pool(bytes)",'
           b'"Code(bytes)","BSS(bytes)","Link Date","Path","Init(bytes)"\n')
    stopped = hdr + (b'"cam","Cam","d","Kernel","Manual","Stopped","OK","TRUE","FALSE",'
                     b'"0","0","0","1/1/2025","C:\\W\\system32\\drivers\\cam.sys","0"\n')
    running = stopped.replace(b'"Stopped"', b'"Running"')
    from spyscan.diff import diff_facts
    d = diff_facts(parse(stopped), parse(running))
    assert (len(d["added"]), len(d["removed"]), len(d["changed"])) == (0, 0, 0)

def test_clean_driver_not_temp():
    facts = parse(_raw())
    ohci = next(f for f in facts if f.attrs["module"] == "1394ohci")
    assert ohci.attrs["from_temp"] is False

def test_skips_blank_rows():
    raw = (b'"Module Name","Display Name","Description","Driver Type","Start Mode",'
           b'"State","Status","Accept Stop","Accept Pause","Paged Pool(bytes)",'
           b'"Code(bytes)","BSS(bytes)","Link Date","Path","Init(bytes)"\n'
           b'"","","","","","","","","","","","","","",""\n')
    assert parse(raw) == []
