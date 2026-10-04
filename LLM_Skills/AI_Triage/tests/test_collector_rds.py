import json

from fakes import FakeAws, access_denied
from helpers import WINDOW_START, assert_read_only, fact_summaries, make_context
from triage.collectors.rds import COLLECTOR
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


def test_error_log_file_is_read_and_filtered(config_data, tmp_path):
    files = [
        {"LogFileName": "error/postgresql.log.2026-10-04-11", "LastWritten": WINDOW_START_MILLIS + 3_600_000, "Size": 10},
        {"LogFileName": "error/postgresql.log.2026-10-04-10", "LastWritten": WINDOW_START_MILLIS + 60_000, "Size": 10},
        {"LogFileName": "trace/other.log", "LastWritten": WINDOW_START_MILLIS + 7_000_000, "Size": 10},
    ]
    data = "\n".join([
        "2026-10-04 10:41:00 UTC::@:[1]:LOG:  checkpoint complete",
        "2026-10-04 10:42:11 UTC:10.0.0.5(1234):app@orders:[7]:ERROR:  deadlock detected",
        "plain line with FATAL: too many connections",
        "2026-10-04 10:43:00 UTC::@:[1]:LOG:  all fine",
    ])
    ctx, aws = run(config_data, tmp_path, log_answers(files, data))
    download = aws.called("rds", "download-db-log-file-portion")
    assert len(download) == 1
    assert download[0][download[0].index("--log-file-name") + 1] == "error/postgresql.log.2026-10-04-11"
    assert download[0][download[0].index("--number-of-lines") + 1] == "200"
    listing = aws.called("rds", "describe-db-log-files")[0]
    assert listing[listing.index("--file-last-written") + 1] == str(WINDOW_START_MILLIS)
    assert "--max-items" in listing
    timed = next(f for f in ctx.evidence.facts if "deadlock detected" in f.excerpt)
    assert timed.kind == "incident_time" and timed.time == "2026-10-04T10:42:11Z"
    untimed = next(f for f in ctx.evidence.facts if "too many connections" in f.excerpt)
    assert untimed.kind == "current" and untimed.time is None
    assert not any("checkpoint complete" in f.excerpt or "all fine" in f.excerpt for f in ctx.evidence.facts)
    assert_read_only(ctx, aws)


def test_newest_file_is_read_when_none_is_an_error_log(config_data, tmp_path):
    files = [
        {"LogFileName": "audit/a.log", "LastWritten": WINDOW_START_MILLIS + 1000, "Size": 1},
        {"LogFileName": "audit/b.log", "LastWritten": WINDOW_START_MILLIS + 2000, "Size": 1},
    ]
    ctx, aws = run(config_data, tmp_path, log_answers(files, "PANIC: out of memory"))
    download = aws.called("rds", "download-db-log-file-portion")[0]
    assert download[download.index("--log-file-name") + 1] == "audit/b.log"
    assert by_summary(ctx, "audit/b.log")[0].excerpt == "PANIC: out of memory"


def test_log_lines_are_capped_at_twenty(config_data, tmp_path):
    files = [{"LogFileName": "error/e.log", "LastWritten": WINDOW_START_MILLIS + 1000, "Size": 1}]
    data = "\n".join(f"2026-10-04 10:{n:02d}:00 UTC::@:[1]:ERROR:  failure {n}" for n in range(30))
    ctx, _ = run(config_data, tmp_path, log_answers(files, data))
    lines = [f for f in ctx.evidence.facts if "failure" in f.excerpt]
    assert len(lines) == 20


def test_no_log_files_means_no_download(config_data, tmp_path):
    _, aws = run(config_data, tmp_path, healthy_answers())
    assert aws.called("rds", "download-db-log-file-portion") == []


def test_secret_in_log_line_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "5" * 10
    files = [{"LogFileName": "error/e.log", "LastWritten": WINDOW_START_MILLIS + 1000, "Size": 1}]
    ctx, _ = run(config_data, tmp_path, log_answers(files, f"ERROR: connection failed password={secret}"))
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
        {"Key": {"Metric": "db.load.avg", "Dimensions": {"db.wait_event.name": "IO:DataFileRead"}},
         "DataPoints": [{"Timestamp": IN_WINDOW, "Value": 2.0}, {"Timestamp": IN_WINDOW, "Value": 4.0}]},
        {"Key": {"Metric": "db.load.avg", "Dimensions": {"db.wait_event.name": "Lock:transactionid"}},
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
    assert len(aws.called("rds", "describe-events")) == 2
    assert_read_only(ctx, aws)


def test_missing_database(config_data, tmp_path):
    answers = healthy_answers(**{
        "rds describe-db-instances": NOT_FOUND,
        "rds describe-db-clusters": (254, "An error occurred (DBClusterNotFoundFault) when calling the DescribeDBClusters operation: x"),
    })
    ctx, aws = run(config_data, tmp_path, answers)
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("rds", "describe-events") == []


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"rds describe-events": access_denied("DescribeEvents")})
    ctx, aws = run(config_data, tmp_path, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert by_summary(ctx, "orders-db is available")
    assert aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws)
