from spyscan.collectors.processes import parse


def sample():
    return [
        {"pid": 1000, "name": "u.exe", "exe": r"C:\Users\n\AppData\Local\Temp\u.exe",
         "ppid": 4, "pname": "services.exe", "cmdline": ["u.exe", "-hidden"]},
        {"pid": 1, "name": "explorer.exe", "exe": r"C:\Windows\explorer.exe",
         "ppid": 800, "pname": "userinit.exe", "cmdline": ["explorer.exe"]},
    ]


def by_name(facts):
    return {f.entity_key.split("::")[1]: f for f in facts}


def test_flags_temp_path_attr():
    facts = by_name(parse(sample()))
    assert facts["u.exe"].attrs["from_temp"] is True
    assert facts["explorer.exe"].attrs["from_temp"] is False


def test_kind_and_key_uses_full_path():
    f = by_name(parse(sample()))["u.exe"]
    assert f.kind == "process"
    assert f.entity_key == (
        r"processes::u.exe::c:\users\n\appdata\local\temp\u.exe")


def test_same_name_same_path_folds_to_one_fact():
    rows = [
        {"pid": p, "name": "svchost.exe", "exe": r"C:\Windows\System32\svchost.exe",
         "ppid": 4, "pname": "services.exe", "cmdline": ["svchost.exe", f"-k{p}"]}
        for p in (100, 200, 300)
    ]
    facts = parse(rows)
    assert len(facts) == 1
    f = facts[0]
    assert f.observed["instance_count"] == 3
    assert f.observed["pids"] == [100, 200, 300]
    assert "pid" not in f.attrs and "cmdline" not in f.attrs  # volatile -> observed
    assert f.label == "svchost.exe (3 instances)"


def test_same_name_different_path_stays_distinct():
    rows = [
        {"pid": 1, "name": "svchost.exe", "exe": r"C:\Windows\System32\svchost.exe",
         "ppid": 4, "pname": "services.exe", "cmdline": []},
        {"pid": 2, "name": "svchost.exe", "exe": r"C:\Users\n\AppData\Local\Temp\svchost.exe",
         "ppid": 4, "pname": "", "cmdline": []},
    ]
    facts = parse(rows)
    assert len(facts) == 2
    assert len({f.entity_key for f in facts}) == 2


def test_fold_is_row_order_independent():
    rows = [
        {"pid": 9, "name": "a.exe", "exe": r"C:\a.exe", "ppid": 1,
         "pname": "x.exe", "cmdline": ["a.exe", "-z"]},
        {"pid": 3, "name": "a.exe", "exe": r"C:\a.exe", "ppid": 1,
         "pname": "y.exe", "cmdline": ["a.exe"]},
    ]
    f1 = parse(rows)[0]
    f2 = parse(list(reversed(rows)))[0]
    assert f1 == f2


def test_empty_exe_gets_sentinel_key_not_empty_identity():
    rows = [{"pid": 4, "name": "System", "exe": "", "ppid": 0,
             "pname": "", "cmdline": []}]
    f = parse(rows)[0]
    assert f.entity_key == "processes::System::(unknown-path)"


def test_hidden_flag_any_instance():
    rows = [
        {"pid": 1, "name": "h.exe", "exe": r"C:\h.exe", "ppid": 1,
         "pname": "x", "cmdline": ["h.exe"]},
        {"pid": 2, "name": "h.exe", "exe": r"C:\h.exe", "ppid": 1,
         "pname": "x", "cmdline": ["h.exe", "-hidden"]},
    ]
    assert parse(rows)[0].attrs["hidden_flag"] is True
