import json
import re

from fakes import FakeAws, access_denied
from helpers import WINDOW_START, assert_read_only, fact_summaries, make_context
from triage.collectors.rds import COLLECTOR, _mask_values
from triage.window import parse_time

TARGETS = {"db": "orders-db"}
IN_WINDOW = "2026-10-04T10:42:10.123000+00:00"
OUTSIDE = "2026-10-04T07:00:00+00:00"
WINDOW_START_MILLIS = int(parse_time(WINDOW_START).timestamp() * 1000)
NOT_FOUND = (254, "An error occurred (DBInstanceNotFound) when calling the DescribeDBInstances operation: not found")


def instance(name="orders-db", **overrides):
    body = {
        "DBInstanceIdentifier": name, "DBInstanceStatus": "available", "DBInstanceClass": "db.r6g.large",
        "Engine": "postgres", "EngineVersion": "15.4", "MultiAZ": True, "AllocatedStorage": 200,
        "PendingModifiedValues": {}, "PerformanceInsightsEnabled": False, "DbiResourceId": "db-ABCDEFG",
        "DBParameterGroups": [{"DBParameterGroupName": "orders-pg", "ParameterApplyStatus": "in-sync"}],
    }
    body.update(overrides)
    return {"DBInstances": [body]}


def healthy_answers(**extra):
    answers = {
        "rds describe-db-instances": instance(),
        "rds describe-events": {"Events": []},
        "rds describe-db-log-files": {"DescribeDBLogFiles": []},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


class ByArgument(FakeAws):
    """Answers by service, operation, and the value of one option, for calls that differ per resource."""

    def __init__(self, answers, option, per_value):
        super().__init__(answers)
        self.option, self.per_value = option, per_value

    def __call__(self, argv, timeout):
        key = f"{argv[1]} {argv[2]}"
        if key in self.per_value and self.option in argv:
            self.answers[key] = self.per_value[key][argv[argv.index(self.option) + 1]]
        return super().__call__(argv, timeout)


def run(config_data, tmp_path, answers, fake=None):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="rds")
    if fake is not None:
        ctx.runner, aws = fake, fake
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, aws


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "rds"
    assert COLLECTOR.required == ("db",)
    assert COLLECTOR.optional == ()


def test_healthy_instance(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers())
    state = next(f for f in ctx.evidence.facts if f.kind == "current")
    for word in ("orders-db", "available", "db.r6g.large", "postgres 15.4", "multi-AZ yes", "200 GiB", "orders-pg in-sync"):
        assert word in state.summary
    assert "no pending" in state.summary
    assert ctx.evidence.errors == []
    assert ctx.evidence.facts[0].id == "rds-0001"
    assert aws.called("pi", "get-resource-metrics") == []
    assert aws.called("rds", "describe-db-clusters") == []
    assert_read_only(ctx, aws)


def test_unhealthy_instance_states_pending_changes(config_data, tmp_path):
    answers = healthy_answers(**{"rds describe-db-instances": instance(
        DBInstanceStatus="storage-full", MultiAZ=False, PendingModifiedValues={"DBInstanceClass": "db.r6g.xlarge"},
        DBParameterGroups=[{"DBParameterGroupName": "orders-pg", "ParameterApplyStatus": "pending-reboot"}])})
    ctx, aws = run(config_data, tmp_path, answers)
    state = ctx.evidence.facts[0]
    assert "storage-full" in state.summary and "multi-AZ no" in state.summary
    assert "DBInstanceClass=db.r6g.xlarge" in state.summary
    assert "orders-pg pending-reboot" in state.summary


def test_events_in_window_become_incident_facts(config_data, tmp_path):
    events = {"Events": [
        {"Message": "DB instance restarted", "Date": IN_WINDOW, "SourceIdentifier": "orders-db"},
        {"Message": "old event", "Date": OUTSIDE},
    ]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"rds describe-events": events}))
    facts = by_summary(ctx, "DB instance restarted")
    assert len(facts) == 1 and facts[0].kind == "incident_time" and facts[0].time == "2026-10-04T10:42:10Z"
    assert by_summary(ctx, "old event") == []
    call = aws.called("rds", "describe-events")[0]
    assert call[call.index("--source-identifier") + 1] == "orders-db"
    assert call[call.index("--source-type") + 1] == "db-instance"
    assert call[call.index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-time") + 1] == "2026-10-04T12:00:00Z"


def test_events_are_capped(config_data, tmp_path):
    events = {"Events": [{"Message": f"event {n}", "Date": f"2026-10-04T10:{n:02d}:00+00:00"} for n in range(40)]}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"rds describe-events": events}))
    event_facts = [f for f in ctx.evidence.facts if f.summary.startswith("Instance event")]
    assert len(event_facts) == 30
    assert "event 39" in event_facts[0].summary


def log_answers(files, data):
    return healthy_answers(**{
        "rds describe-db-log-files": {"DescribeDBLogFiles": files},
        "rds download-db-log-file-portion": {"LogFileData": data, "AdditionalDataPending": False},
    })


def error_file(name, offset_millis):
    return {"LogFileName": name, "LastWritten": WINDOW_START_MILLIS + offset_millis, "Size": 10}


def hourly(hour, last_written_minute=59):
    """A PostgreSQL hourly error file: covers [hour, hour + 1) and was last written near its end."""
    millis = WINDOW_START_MILLIS + (hour - 10) * 3_600_000 + last_written_minute * 60_000
    return {"LogFileName": f"error/postgresql.log.2026-10-04-{hour:02d}", "LastWritten": millis, "Size": 10}


def downloaded(aws):
    return [c[c.index("--log-file-name") + 1] for c in aws.called("rds", "download-db-log-file-portion")]


def test_error_log_files_are_read_and_filtered(config_data, tmp_path):
    data = "\n".join([
        "2026-10-04 10:41:00 UTC::@:[1]:LOG:  checkpoint complete",
        "2026-10-04 10:42:11 UTC:10.0.0.5(1234):app@orders:[7]:ERROR:  deadlock detected",
        "plain line with FATAL: too many connections",
        "2026-10-04 10:43:00 UTC::@:[1]:LOG:  all fine",
    ])
    ctx, aws = run(config_data, tmp_path, log_answers([hourly(10), hourly(11)], data))
    download = aws.called("rds", "download-db-log-file-portion")
    assert len(download) == 2
    assert download[0][download[0].index("--number-of-lines") + 1] == "200"
    assert "--no-paginate" in download[0]
    listing = aws.called("rds", "describe-db-log-files")[0]
    assert listing[listing.index("--file-last-written") + 1] == str(WINDOW_START_MILLIS)
    assert listing[listing.index("--filename-contains") + 1] == "error"
    assert "--max-items" in listing
    timed = [f for f in ctx.evidence.facts if "deadlock detected" in f.excerpt]
    assert timed and timed[0].kind == "incident_time" and timed[0].time == "2026-10-04T10:42:11Z"
    assert not any("too many connections" in f.excerpt for f in ctx.evidence.facts)
    assert not any("checkpoint complete" in f.excerpt or "all fine" in f.excerpt for f in ctx.evidence.facts)
    assert_read_only(ctx, aws)


def test_no_error_log_in_the_window_is_stated_and_no_other_file_is_read(config_data, tmp_path):
    files = [{"LogFileName": "audit/b.log", "LastWritten": WINDOW_START_MILLIS + 2000, "Size": 1}]
    ctx, aws = run(config_data, tmp_path, log_answers(files, "PANIC: out of memory"))
    assert aws.called("rds", "download-db-log-file-portion") == []
    fact = by_summary(ctx, "No error log")[0]
    assert fact.kind == "derived" and "orders-db" in fact.summary and fact.command


def test_empty_listing_states_no_error_log(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers())
    assert by_summary(ctx, "No error log")
    assert aws.called("rds", "download-db-log-file-portion") == []


def test_a_window_ending_on_a_rotation_boundary_does_not_read_the_next_hours_file(config_data, tmp_path):
    line = "2026-10-04 11:59:58 UTC::@:[1]:ERROR:  late in window"
    _, aws = run(config_data, tmp_path, log_answers([hourly(10), hourly(11), hourly(12)], line))
    assert downloaded(aws) == ["error/postgresql.log.2026-10-04-10", "error/postgresql.log.2026-10-04-11"]


def test_a_file_that_ends_exactly_at_the_window_start_is_not_read(config_data, tmp_path):
    _, aws = run(config_data, tmp_path, log_answers([hourly(9), hourly(10)], ""))
    assert downloaded(aws) == ["error/postgresql.log.2026-10-04-10"]


def test_a_file_without_an_hour_in_its_name_covers_the_hour_before_it_was_last_written(config_data, tmp_path):
    early = {"LogFileName": "error/early.log", "LastWritten": WINDOW_START_MILLIS + 60_000, "Size": 1}
    active = {"LogFileName": "error/active.log", "LastWritten": WINDOW_START_MILLIS + 7_200_000 + 600_000, "Size": 1}
    later = {"LogFileName": "error/later.log", "LastWritten": WINDOW_START_MILLIS + 7_200_000 + 9_000_000, "Size": 1}
    _, aws = run(config_data, tmp_path, log_answers([early, active, later], ""))
    assert downloaded(aws) == ["error/early.log", "error/active.log"]


def test_no_line_in_the_window_is_stated_with_the_files_that_were_read(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, log_answers([hourly(11)], "2026-10-04 18:05:00 UTC::@:[1]:ERROR:  much later"))
    fact = by_summary(ctx, "No error line inside the window")[0]
    assert fact.kind == "derived" and "error/postgresql.log.2026-10-04-11" in fact.summary and fact.command


def test_no_such_fact_when_a_line_inside_the_window_was_found(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, log_answers([hourly(11)], "2026-10-04 11:05:00 UTC::@:[1]:ERROR:  in window"))
    assert by_summary(ctx, "No error line inside the window") == []


def test_log_lines_outside_the_window_are_dropped(config_data, tmp_path):
    files = [error_file("error/e.log", 60_000)]
    data = "2026-10-04 18:05:00 UTC::@:[1]:ERROR:  late failure\n2026-10-04 10:05:00 UTC::@:[1]:ERROR:  in window failure"
    ctx, _ = run(config_data, tmp_path, log_answers(files, data))
    assert [f.excerpt for f in ctx.evidence.facts if "failure" in f.excerpt] == ["2026-10-04 10:05:00 UTC::@:[1]:ERROR:  in window failure"]


def test_log_lines_are_capped_at_twenty(config_data, tmp_path):
    files = [error_file("error/e.log", 1000)]
    data = "\n".join(f"2026-10-04 10:{n:02d}:00 UTC::@:[1]:ERROR:  failure {n}" for n in range(30))
    ctx, _ = run(config_data, tmp_path, log_answers(files, data))
    lines = [f for f in ctx.evidence.facts if "failure" in f.excerpt]
    assert len(lines) == 20 and "failure 29" in lines[-1].excerpt


def test_data_values_never_reach_a_log_fact(config_data, tmp_path):
    phone, name = "+44 7700 900" + "123", "Ada" + "Lovelace"
    files = [error_file("error/e.log", 1000)]
    data = "\n".join([
        f"2026-10-04 10:05:00 UTC::@:[1]:ERROR:  duplicate key value violates unique constraint \"users_phone_key\" Key (phone)=({phone}) already exists",
        f"2026-10-04 10:06:00 UTC::@:[1]:STATEMENT:  INSERT INTO users (name) VALUES ('{name}') ERROR",
    ])
    ctx, _ = run(config_data, tmp_path, log_answers(files, data))
    document = ctx.evidence.to_json()
    assert phone not in document and name not in document
    assert "violates unique constraint" in document and "users_phone_key" not in document and "Key (phone)=(<value>)" in document


def test_mask_values_hides_single_quoted_strings_with_both_escapes():
    assert _mask_values("ERROR: INSERT INTO t (a, b) VALUES ('x y', 'it''s') failed") == "ERROR: INSERT INTO t (a, b) VALUES (<value>, <value>) failed"
    line = "ERROR: Duplicate entry 'O" + "\\'" + "Brien-" + "5550" + "199' for key 'users.name'"
    assert _mask_values(line) == "ERROR: Duplicate entry <value> for key <value>"


def test_mask_values_hides_the_escape_string_form():
    line = "ERROR: bad literal E'123-45-" + "\\'" + "67" + "89' near"
    assert _mask_values(line) == "ERROR: bad literal <value> near"


def test_mask_values_hides_double_quoted_values():
    assert _mask_values('ERROR:  invalid input syntax for type integer: "' + "4111" * 4 + '"') == "ERROR:  invalid input syntax for type integer: <value>"
    assert _mask_values('ERROR: value "a ""quoted"" one" and "b' + "\\" + '"c" end') == "ERROR: value <value> and <value> end"


def test_mask_values_hides_backtick_quoted_text():
    assert _mask_values("ERROR: unknown column `secret col` in table") == "ERROR: unknown column <value> in table"


def test_mask_values_hides_dollar_quoted_strings():
    line = "ERROR: near $$Dollar Secret Value$$, $tag$tagged Value$tag$ and more"
    assert _mask_values(line) == "ERROR: near <value>, <value> and more"
    assert _mask_values("ERROR: near $1 and $2") == "ERROR: near $1 and $2"


def test_mask_values_masks_an_unterminated_quote_to_the_end_of_the_line():
    assert _mask_values("ERROR: syntax error near 'secret value") == "ERROR: syntax error near <value>"
    assert _mask_values('ERROR: near "secret value') == "ERROR: near <value>"


def test_mask_values_hides_the_row_in_a_detail_line_but_keeps_the_column_list():
    phone = "+44 7700 900" + "123"
    assert _mask_values(f"DETAIL:  Key (phone)=({phone}) already exists.") == "DETAIL:  Key (phone)=(<value>) already exists."
    assert _mask_values("DETAIL:  Failing row contains (1, " + "Ada" + ", x@example.org).") == "DETAIL:  Failing row contains (<value>)."


def test_mask_values_hides_nested_parentheses_in_a_key_group():
    line = "ERROR: Key (name)=(Bob (Jr) +44 7700 900" + "123) already exists"
    assert _mask_values(line) == "ERROR: Key (name)=(<value>) already exists"


def test_mask_values_hides_long_digit_runs_but_keeps_the_leading_timestamp():
    assert _mask_values("2026-10-04 10:42:11.123456 UTC ERROR: user " + "12345678" + " missing, retry 3 of 4") == \
        "2026-10-04 10:42:11.123456 UTC ERROR: user <value> missing, retry 3 of 4"
    assert not re.search(r"\d{5}", _mask_values("ERROR: ref 4111-1111 9999 and 55501999 and +1 555 0199"))


def test_mask_values_leaves_a_line_without_values_alone():
    line = "2026-10-04 10:42:11 UTC ERROR: too many connections for role app, limit 100"
    assert _mask_values(line) == line


def test_secret_in_log_line_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "5" * 10
    files = [error_file("error/e.log", 1000)]
    ctx, _ = run(config_data, tmp_path, log_answers(files, f"2026-10-04 10:05:00 UTC::@:[1]:ERROR: connection failed password={secret}"))
    assert secret not in ctx.evidence.to_json()
    assert "connection failed" in ctx.evidence.to_json()


def test_metrics_use_the_instance_dimension_and_stats(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [97.5]}]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    assert by_summary(ctx, "CPUUtilization (Average): peak 97.5")
    call = aws.called("cloudwatch", "get-metric-data")[0]
    queries = json.loads(call[call.index("--metric-data-queries") + 1])
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stats["DatabaseConnections"] == "Maximum" and stats["FreeStorageSpace"] == "Minimum"
    assert stats["FreeableMemory"] == "Minimum" and stats["ReplicaLag"] == "Maximum"
    assert {"ReadLatency", "WriteLatency"} <= stats.keys()
    assert queries[0]["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "DBInstanceIdentifier", "Value": "orders-db"}]
    assert queries[0]["MetricStat"]["Metric"]["Namespace"] == "AWS/RDS"


def test_performance_insights_uses_the_resource_id(config_data, tmp_path):
    pi = {"MetricList": [
        {"Key": {"Metric": "db.load.avg"}, "DataPoints": [{"Timestamp": IN_WINDOW, "Value": 9.0}]},
        {"Key": {"Metric": "db.load.avg", "Dimensions": {"db.wait_event.type": "IO", "db.wait_event.name": "IO:DataFileRead"}},
         "DataPoints": [{"Timestamp": IN_WINDOW, "Value": 2.0}, {"Timestamp": IN_WINDOW, "Value": 4.0}]},
        {"Key": {"Metric": "db.load.avg", "Dimensions": {"db.wait_event.type": "Lock", "db.wait_event.name": "Lock:transactionid"}},
         "DataPoints": [{"Timestamp": IN_WINDOW, "Value": 5.0}]},
    ]}
    answers = healthy_answers(**{"rds describe-db-instances": instance(PerformanceInsightsEnabled=True), "pi get-resource-metrics": pi})
    ctx, aws = run(config_data, tmp_path, answers)
    call = aws.called("pi", "get-resource-metrics")[0]
    assert call[call.index("--identifier") + 1] == "db-ABCDEFG"
    assert call[call.index("--service-type") + 1] == "RDS"
    assert call[call.index("--period-in-seconds") + 1] == "300"
    assert json.loads(call[call.index("--metric-queries") + 1])[0]["GroupBy"] == {"Group": "db.wait_event", "Limit": 5}
    fact = next(f for f in ctx.evidence.facts if "wait events" in f.summary)
    assert "Lock:transactionid 5.00" in fact.summary and "IO:DataFileRead 3.00" in fact.summary
    assert fact.summary.index("Lock:transactionid") < fact.summary.index("IO:DataFileRead")
    assert_read_only(ctx, aws)


def test_cluster_fallback_describes_member_instances(config_data, tmp_path):
    cluster = {"DBClusters": [{"DBClusterIdentifier": "orders-db", "Status": "available", "Engine": "aurora-postgresql",
                               "EngineVersion": "15.4", "MultiAZ": True,
                               "DBClusterMembers": [{"DBInstanceIdentifier": "orders-db-1", "IsClusterWriter": True},
                                                    {"DBInstanceIdentifier": "orders-db-2", "IsClusterWriter": False}]}]}
    per = {"rds describe-db-instances": {"orders-db": NOT_FOUND, "orders-db-1": instance("orders-db-1"),
                                         "orders-db-2": instance("orders-db-2", DBInstanceStatus="rebooting")}}
    fake = ByArgument(healthy_answers(**{"rds describe-db-clusters": cluster}), "--db-instance-identifier", per)
    ctx, aws = run(config_data, tmp_path, healthy_answers(), fake=fake)
    assert by_summary(ctx, "Cluster orders-db is available")
    assert by_summary(ctx, "orders-db-2 is rebooting")
    assert by_summary(ctx, "orders-db-1 is available")
    call = aws.called("rds", "describe-db-clusters")[0]
    assert call[call.index("--db-cluster-identifier") + 1] == "orders-db"
    assert len(aws.called("rds", "describe-events")) == 3
    assert_read_only(ctx, aws)


def test_missing_database(config_data, tmp_path):
    answers = healthy_answers(**{
        "rds describe-db-instances": NOT_FOUND,
        "rds describe-db-clusters": (254, "An error occurred (DBClusterNotFoundFault) when calling the DescribeDBClusters operation: x"),
    })
    ctx, aws = run(config_data, tmp_path, answers)
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert ctx.evidence.facts[0].command
    assert ctx.evidence.errors == []
    assert aws.called("rds", "describe-events") == []


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"rds describe-events": access_denied("DescribeEvents")})
    ctx, aws = run(config_data, tmp_path, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert by_summary(ctx, "orders-db is available")
    assert aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws)


def test_denied_cluster_lookup_is_an_error_not_a_missing_database(config_data, tmp_path):
    answers = healthy_answers(**{"rds describe-db-instances": NOT_FOUND, "rds describe-db-clusters": access_denied("DescribeDBClusters")})
    ctx, _ = run(config_data, tmp_path, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert by_summary(ctx, "not found") == []


def test_denied_instance_lookup_does_not_fall_back_to_clusters(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"rds describe-db-instances": access_denied("DescribeDBInstances")}))
    assert aws.called("rds", "describe-db-clusters") == []
    assert by_summary(ctx, "not found") == []
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]


def test_every_events_call_is_bounded_and_cluster_events_are_requested(config_data, tmp_path):
    cluster = {"DBClusters": [{"DBClusterIdentifier": "orders-db", "Status": "available", "Engine": "aurora-postgresql",
                               "EngineVersion": "15.4", "DBClusterMembers": [{"DBInstanceIdentifier": "orders-db-1", "IsClusterWriter": True}]}]}
    per = {"rds describe-db-instances": {"orders-db": NOT_FOUND, "orders-db-1": instance("orders-db-1")}}
    fake = ByArgument(healthy_answers(**{"rds describe-db-clusters": cluster}), "--db-instance-identifier", per)
    ctx, aws = run(config_data, tmp_path, healthy_answers(), fake=fake)
    calls = aws.called("rds", "describe-events")
    assert all(c[c.index("--max-items") + 1] == "50" for c in calls)
    types = {c[c.index("--source-type") + 1]: c[c.index("--source-identifier") + 1] for c in calls}
    assert types == {"db-cluster": "orders-db", "db-instance": "orders-db-1"}


def test_cluster_members_are_capped_at_six(config_data, tmp_path):
    names = [f"orders-db-{n}" for n in range(1, 9)]
    cluster = {"DBClusters": [{"DBClusterIdentifier": "orders-db", "Status": "available", "Engine": "aurora-postgresql",
                               "EngineVersion": "15.4", "DBClusterMembers": [{"DBInstanceIdentifier": n} for n in names]}]}
    per = {"rds describe-db-instances": {"orders-db": NOT_FOUND, **{n: instance(n) for n in names}}}
    fake = ByArgument(healthy_answers(**{"rds describe-db-clusters": cluster}), "--db-instance-identifier", per)
    ctx, aws = run(config_data, tmp_path, healthy_answers(), fake=fake)
    described = [c[c.index("--db-instance-identifier") + 1] for c in aws.called("rds", "describe-db-instances")]
    assert described == ["orders-db"] + names[:6]
    assert by_summary(ctx, "8 members")[0].kind == "derived"
