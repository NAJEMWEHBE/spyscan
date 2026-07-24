from spyscan.collectors.netconns import parse


def test_remote_conn_becomes_fact():
    snaps = [{"pid": 1000, "laddr": "192.168.1.5:55000", "raddr": "13.37.13.37:443",
              "status": "ESTABLISHED", "pname": "u.exe"}]
    f = parse(snaps)[0]
    assert f.kind == "connection"
    assert f.attrs["remote_ip"] == "13.37.13.37"
    assert f.attrs["remote_port"] == 443


def test_listening_has_no_remote():
    snaps = [{"pid": 5, "laddr": "0.0.0.0:3389", "raddr": "", "status": "LISTEN", "pname": "svc"}]
    f = parse(snaps)[0]
    assert f.attrs["listening"] is True
    assert f.entity_key == "netconns::svc::listen 0.0.0.0:3389"


def test_many_sockets_one_endpoint_fold_to_one_fact():
    snaps = [{"pid": p, "laddr": f"192.168.0.2:{50000+p}", "raddr": "160.79.104.10:443",
              "status": "ESTABLISHED", "pname": "claude.exe"} for p in range(1, 6)]
    facts = parse(snaps)
    assert len(facts) == 1
    f = facts[0]
    assert f.observed["conn_count"] == 5
    assert f.observed["pids"] == [1, 2, 3, 4, 5]
    assert "pid" not in f.attrs and "local" not in f.attrs   # volatile -> observed
    assert f.label == "claude.exe -> 160.79.104.10:443 (x5)"


def test_fold_is_row_order_independent():
    snaps = [
        {"pid": 1, "laddr": "10.0.0.1:50001", "raddr": "1.2.3.4:443",
         "status": "ESTABLISHED", "pname": "a.exe"},
        {"pid": 2, "laddr": "10.0.0.1:50002", "raddr": "1.2.3.4:443",
         "status": "CLOSE_WAIT", "pname": "a.exe"},
    ]
    assert parse(snaps) == parse(list(reversed(snaps)))


def test_unowned_socket_gets_sentinel_not_empty_key():
    snaps = [{"pid": 0, "laddr": "192.168.0.2:50000", "raddr": "142.251.38.3:80",
              "status": "CLOSE_WAIT", "pname": ""}]
    f = parse(snaps)[0]
    assert f.attrs["process"] == "(unowned)"
    assert f.entity_key == "netconns::(unowned)::142.251.38.3:80"
    assert f.label.startswith("(unowned) -> ")


def test_unresolved_owner_distinct_from_unowned():
    # a live pid whose name lookup failed (AccessDenied) is not kernel-unowned
    snaps = [{"pid": 4321, "laddr": "192.168.0.2:50000", "raddr": "8.8.8.8:53",
              "status": "ESTABLISHED", "pname": ""}]
    assert parse(snaps)[0].attrs["process"] == "(unresolved)"


def test_outbound_and_listener_on_same_addr_stay_distinct():
    snaps = [
        {"pid": 1, "laddr": "127.0.0.1:9000", "raddr": "", "status": "LISTEN",
         "pname": "srv.exe"},
        {"pid": 2, "laddr": "127.0.0.1:51000", "raddr": "127.0.0.1:9000",
         "status": "ESTABLISHED", "pname": "srv.exe"},
    ]
    facts = parse(snaps)
    assert len(facts) == 2
    assert len({f.entity_key for f in facts}) == 2
