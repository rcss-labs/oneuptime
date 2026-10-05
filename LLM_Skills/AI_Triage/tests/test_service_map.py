import pytest

from triage.config import parse_config
from triage.service_map import MapError, MatchKeys, load_map, match_incident, parse_map


@pytest.fixture
def config(config_data):
    return parse_config(config_data)


def test_example_map_is_valid(map_data, config):
    smap = parse_map(map_data, config)
    assert set(smap.services) == {"checkout-api", "payments-api"}
    prod = smap.services["checkout-api"].environments["prod"]
    assert prod.account == "prod-main" and prod.depends_on == ("payments-api",)
    assert smap.services["checkout-api"].last_verified == "2026-10-04"


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"].update(account="nope"), "unknown account 'nope'"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"].update(region="us-west-2"), "is not listed for account"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"]["resources"].update(mainframe="x"), "unknown resource key"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"]["resources"]["opensearch"].update(cluster="nope"), "unknown cluster 'nope'"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"]["resources"]["opensearch"].update(index_pattern="other-*"), "outside the allowed patterns"),
        (lambda d: d["services"]["payments-api"]["environments"]["prod"]["resources"]["eks"].update(cluster="nope"), "unknown cluster 'nope'"),
        (lambda d: d["services"]["payments-api"]["environments"]["prod"]["resources"]["eks"].pop("namespace"), "eks.namespace: must be set"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"].update(depends_on=["ghost"]), "unknown service 'ghost'"),
        (lambda d: d["services"]["checkout-api"].update(source="guessed"), "source: must be one of"),
        (lambda d: d["services"]["checkout-api"].update(last_verified="yesterday"), "last_verified: must be a date"),
        (lambda d: d["services"]["payments-api"].pop("match"), "needs a match block"),
        (lambda d: d["services"]["payments-api"].update(environments={}), "at least one environment is required"),
        (lambda d: d["services"]["payments-api"]["match"].update(urls=["x"]), "match.urls: unknown key"),
    ],
)
def test_invalid_map_is_rejected(map_data, config, mutate, expected):
    mutate(map_data)
    with pytest.raises(MapError) as excinfo:
        parse_map(map_data, config)
    assert expected in "\n".join(excinfo.value.errors)


def test_environment_match_selects_one_environment(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(monitors=["checkout api"], labels=["Checkout"]))
    assert result.status == "one"
    candidate = result.candidates[0]
    assert (candidate.service, candidate.environment) == ("checkout-api", "prod")
    assert "label:checkout" in candidate.reasons and "monitor:checkout api" in candidate.reasons


def test_service_level_match_alone_is_ambiguous_when_every_environment_has_its_own(map_data, config):
    smap = parse_map(map_data, config)
    assert match_incident(smap, MatchKeys.build(labels=["checkout"])).status == "none"


def test_service_level_match_covers_environments_without_their_own(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(hostnames=["Payments.Example.com."]))
    assert result.status == "one"
    assert (result.candidates[0].service, result.candidates[0].environment) == ("payments-api", "prod")


def test_several_services_matching_is_reported_as_many(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(monitors=["Checkout API", "Payments API"]))
    assert result.status == "many"
    assert {c.service for c in result.candidates} == {"checkout-api", "payments-api"}


def test_no_match(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(monitors=["Unknown"]))
    assert result.status == "none" and result.candidates == ()


def test_empty_map_file_is_an_empty_map(tmp_path, config):
    path = tmp_path / "service-map.yaml"
    path.write_text("")
    assert load_map(path, config).services == {}


def test_missing_map_file_is_reported(tmp_path, config):
    with pytest.raises(MapError) as excinfo:
        load_map(tmp_path / "absent.yaml", config)
    assert "file not found" in excinfo.value.errors[0]


def _prod_resources(map_data, service, key):
    return map_data["services"][service]["environments"]["prod"]["resources"][key]


@pytest.mark.parametrize("pattern", ["app-logs-*,other-*", "app-logs-1,app-logs-2", "*,*", "app-logs-*\n"])
def test_comma_list_or_odd_index_pattern_is_rejected(map_data, config, pattern):
    _prod_resources(map_data, "checkout-api", "opensearch")["index_pattern"] = pattern
    with pytest.raises(MapError) as excinfo:
        parse_map(map_data, config)
    assert (
        "must start with a lower-case letter or digit, hold at least three characters from a-z, 0-9, "
        "dot, underscore, and dash, and may end in one *, for example app-logs-*"
    ) in "\n".join(excinfo.value.errors)


def test_index_pattern_outside_the_cluster_patterns_is_rejected(map_data, config):
    _prod_resources(map_data, "checkout-api", "opensearch")["index_pattern"] = "billing-logs-*"
    with pytest.raises(MapError) as excinfo:
        parse_map(map_data, config)
    assert "outside the allowed patterns" in "\n".join(excinfo.value.errors)


@pytest.mark.parametrize("pattern", ["app-logs-*", "app-logs-prod", "app-logs-prod-*"])
def test_index_pattern_inside_the_cluster_patterns_is_accepted(map_data, config, pattern):
    _prod_resources(map_data, "checkout-api", "opensearch")["index_pattern"] = pattern
    parse_map(map_data, config)


@pytest.mark.parametrize("namespace", ["Payments", "pay_ments", "-pay", "pay ments", "pay,other", "pay\n", "kube-system "])
def test_bad_namespace_is_rejected(map_data, config, namespace):
    _prod_resources(map_data, "payments-api", "eks")["namespace"] = namespace
    with pytest.raises(MapError) as excinfo:
        parse_map(map_data, config)
    assert "eks.namespace: must use lower-case letters, digits, and dashes only" in "\n".join(excinfo.value.errors)


SERVICE_NAME_RULE = (
    "name must start with a lower-case letter or digit, use only lower-case letters, digits, and dashes, "
    "and be at most 63 characters"
)


def _rename_service(map_data, new_name):
    map_data["services"][new_name] = map_data["services"].pop("payments-api")
    for service in map_data["services"].values():
        for env in service["environments"].values():
            env["depends_on"] = [new_name if d == "payments-api" else d for d in env.get("depends_on") or []]


@pytest.mark.parametrize("name", ["Bad Name", "Payments", "pay_ments", "-pay", "pay.ments", "pay,x", "a" * 64, "pay\n", "", True, 12, None])
def test_bad_service_names_are_rejected(map_data, config, name):
    _rename_service(map_data, name)
    with pytest.raises(MapError) as excinfo:
        parse_map(map_data, config)
    assert any(SERVICE_NAME_RULE in e or "every service name must be a string" in e for e in excinfo.value.errors)


@pytest.mark.parametrize("name", ["a", "payments-api", "9lives", "a" * 63])
def test_good_service_names_are_accepted(map_data, config, name):
    _rename_service(map_data, name)
    assert name in parse_map(map_data, config).services


def test_alarms_ecr_repository_and_opensearch_domain_are_accepted(map_data, config):
    resources = map_data["services"]["checkout-api"]["environments"]["prod"]["resources"]
    resources.update(alarms=["checkout-5xx"], ecr_repository="checkout-api", opensearch_domain="logs-domain")
    smap = parse_map(map_data, config)
    assert smap.services["checkout-api"].environments["prod"].resources["alarms"] == ["checkout-5xx"]


@pytest.mark.parametrize("resources", [{"alarms": "one"}, {"alarms": [1]}, {"ecr_repository": ["x"]}, {"opensearch_domain": 5}])
def test_a_wrong_shape_for_the_new_keys_is_rejected(map_data, config, resources):
    map_data["services"]["checkout-api"]["environments"]["prod"]["resources"].update(resources)
    with pytest.raises(MapError) as excinfo:
        parse_map(map_data, config)
    assert next(iter(resources)) in str(excinfo.value)
