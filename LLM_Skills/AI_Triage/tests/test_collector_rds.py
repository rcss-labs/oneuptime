import json
import re

from fakes import FakeAws, access_denied
from helpers import WINDOW_START, assert_read_only, fact_summaries, make_context
from triage.collectors.rds import COLLECTOR, _mask_values
from triage.window import Window, parse_time

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


def run(config_data, tmp_path, answers, fake=None, incident_start=None, window=None):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="rds")
    if fake is not None:
        ctx.runner, aws = fake, fake
    if window is not None:
        ctx.window = Window(parse_time(window[0]), parse_time(window[1]))
    targets = dict(TARGETS, **({"incident_start": incident_start} if incident_start else {}))
    COLLECTOR.run(ctx, targets)
    return ctx, aws


def log_lines(ctx):
    """The kept error log lines (one fact holds them all) and that fact."""
    facts = [f for f in ctx.evidence.facts if "lines" in f.data]
    assert len(facts) <= 1
    return (facts[0].data["lines"], facts[0]) if facts else ([], None)


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "rds"
    assert COLLECTOR.required == ("db",)
    assert COLLECTOR.optional == ("incident_start",)


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
    assert download[0][download[0].index("--number-of-lines") + 1] == "1000"
    assert "--no-paginate" in download[0]
    listing = aws.called("rds", "describe-db-log-files")[0]
    assert listing[listing.index("--file-last-written") + 1] == str(WINDOW_START_MILLIS)
    assert listing[listing.index("--filename-contains") + 1] == "error"
    assert "--max-items" in listing
    lines, fact = log_lines(ctx)
    assert fact.kind == "incident_time" and fact.time == "2026-10-04T10:42:11Z"
    # Both files answered with the same text; the same line is kept once.
    assert len(lines) == 1 and "deadlock detected" in lines[0]
    assert "too many connections" not in ctx.evidence.to_json()
    assert "checkpoint complete" not in ctx.evidence.to_json() and "all fine" not in ctx.evidence.to_json()
    assert_read_only(ctx, aws)


def test_no_error_log_in_the_window_is_stated_and_no_other_file_is_read(config_data, tmp_path):
    files = [{"LogFileName": "audit/b.log", "LastWritten": WINDOW_START_MILLIS + 2000, "Size": 1}]
    ctx, aws = run(config_data, tmp_path, log_answers(files, "PANIC: out of memory"))
    assert aws.called("rds", "download-db-log-file-portion") == []
    fact = by_summary(ctx, "No error log")[0]
    assert fact.kind == "derived" and "among the 1 files listed" in fact.summary and fact.command


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


class PagedListing(FakeAws):
    """Serves describe-db-log-files page by page, following --starting-token like the CLI pagination does."""

    def __init__(self, answers, pages):
        super().__init__(answers)
        self.pages = pages
        self.tokens = []

    def __call__(self, argv, timeout):
        if argv[1:3] == ["rds", "describe-db-log-files"]:
            token = argv[argv.index("--starting-token") + 1] if "--starting-token" in argv else None
            self.tokens.append(token)
            self.answers["rds describe-db-log-files"] = self.pages[len(self.tokens) - 1]
        return super().__call__(argv, timeout)


def plain_file(name, minutes_after_start):
    return {"LogFileName": name, "LastWritten": WINDOW_START_MILLIS + minutes_after_start * 60_000, "Size": 1}


def test_at_most_six_files_are_read_the_cover_file_first_then_the_newest(config_data, tmp_path):
    files = [plain_file(f"error/a{n}.log", n) for n in range(1, 9)]
    ctx, aws = run(config_data, tmp_path, log_answers(files, ""))
    # No file covers the incident start (assumed 60 minutes after the window start); the last one before it is read first.
    assert downloaded(aws) == ["error/a3.log", "error/a4.log", "error/a5.log", "error/a6.log", "error/a7.log", "error/a8.log"]
    fact = by_summary(ctx, "were not read")[0]
    assert fact.kind == "derived" and "error/a1.log" in fact.summary and "error/a2.log" in fact.summary and "a8" not in fact.summary


def test_the_cover_file_and_the_one_before_it_are_chosen_before_newer_files(config_data, tmp_path):
    before = {"LogFileName": "error/postgresql.log.2026-10-04-09", "LastWritten": WINDOW_START_MILLIS + 30 * 60_000, "Size": 1}
    files = [before, hourly(10), hourly(11)] + [plain_file(f"error/z{n}.log", 180 + n) for n in range(1, 6)]
    ctx, aws = run(config_data, tmp_path, log_answers(files, ""), incident_start="2026-10-04T10:00:00Z")
    read = downloaded(aws)
    assert len(read) == 6
    assert "error/postgresql.log.2026-10-04-10" in read and "error/postgresql.log.2026-10-04-09" in read
    assert "error/postgresql.log.2026-10-04-11" in by_summary(ctx, "were not read")[0].summary


def test_every_page_of_the_listing_is_followed(config_data, tmp_path):
    pages = [{"DescribeDBLogFiles": [hourly(10)], "NextToken": "t1"}, {"DescribeDBLogFiles": [hourly(11)]}]
    fake = PagedListing(healthy_answers(), pages)
    ctx, aws = run(config_data, tmp_path, healthy_answers(), fake=fake)
    assert fake.tokens == [None, "t1"]
    assert downloaded(aws) == ["error/postgresql.log.2026-10-04-10", "error/postgresql.log.2026-10-04-11"]
    assert by_summary(ctx, "listing was cut") == []
    assert_read_only(ctx, aws)


def test_a_listing_that_is_still_cut_after_five_pages_says_so(config_data, tmp_path):
    pages = [{"DescribeDBLogFiles": [plain_file(f"error/p{n}.log", n)], "NextToken": f"t{n}"} for n in range(1, 8)]
    fake = PagedListing(healthy_answers(), pages)
    ctx, _ = run(config_data, tmp_path, healthy_answers(), fake=fake)
    assert len(fake.tokens) == 5
    assert by_summary(ctx, "listing was cut after 5 pages")


def test_a_daily_rotated_file_written_during_the_window_is_read(config_data, tmp_path):
    daily = {"LogFileName": "error/postgresql.log.2026-10-04-00", "LastWritten": WINDOW_START_MILLIS + 6 * 3_600_000, "Size": 1}
    ctx, aws = run(config_data, tmp_path, log_answers([daily], "2026-10-04 10:30:00 UTC::@:[1]:ERROR:  onset"))
    assert downloaded(aws) == ["error/postgresql.log.2026-10-04-00"]
    assert log_lines(ctx)[0]
    assert by_summary(ctx, "No error log") == []


def test_a_date_only_name_covers_that_day_and_an_old_date_does_not(config_data, tmp_path):
    today = {"LogFileName": "error/postgresql.log.2026-10-04", "LastWritten": WINDOW_START_MILLIS + 3_600_000, "Size": 1}
    old = {"LogFileName": "error/postgresql.log.2026-10-02", "LastWritten": WINDOW_START_MILLIS - 3_600_000, "Size": 1}
    _, aws = run(config_data, tmp_path, log_answers([today, old], ""))
    assert downloaded(aws) == ["error/postgresql.log.2026-10-04"]


def test_sql_server_error_log_and_its_error_lines(config_data, tmp_path):
    files = [{"LogFileName": "log/ERROR", "LastWritten": WINDOW_START_MILLIS + 6 * 3_600_000, "Size": 1}]
    line = "2026-10-04 10:30:00.12 Logon       Error: 18456, Severity: 14, State: 8."
    message = "2026-10-04 10:30:00.12 Logon       Login failed for user <hidden>."
    ctx, aws = run(config_data, tmp_path, log_answers(files, line + "\n" + message + "\n2026-10-04 10:31:00.12 Server      Started"))
    assert downloaded(aws) == ["log/ERROR"]
    lines, _ = log_lines(ctx)
    assert len(lines) == 1 and "Error: 18456, Severity: 14, State: 8" in lines[0] and "Login failed for user" in lines[0]
    assert "Started" not in ctx.evidence.to_json()


def test_the_empty_case_names_the_listing_size_and_never_claims_more_than_it_knows(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, log_answers([hourly(9)], ""))
    assert by_summary(ctx, "No error log file overlapping the window was found among the 1 files listed")
    assert by_summary(ctx, "listing was cut") == []
    pages = [{"DescribeDBLogFiles": [plain_file(f"error/o{n}.log", -60)], "NextToken": f"t{n}"} for n in range(1, 8)]
    ctx, _ = run(config_data, tmp_path, healthy_answers(), fake=PagedListing(healthy_answers(), pages))
    fact = by_summary(ctx, "No error log file overlapping")[0]
    assert "5 files listed" in fact.summary and "listing was cut after 5 pages" in fact.summary


def test_log_line_facts_say_which_portion_was_read(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, log_answers([hourly(10)], "2026-10-04 10:30:00 UTC::@:[1]:ERROR:  onset"))
    assert "last 1,000 lines of each file" in log_lines(ctx)[1].summary


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
    assert log_lines(ctx)[0] == ["2026-10-04 10:05:00 UTC::@:[1]:ERROR:  in window failure"]


def minute_lines(first_minute, count, word="failure"):
    """Error lines one minute apart from 10:00 plus first_minute."""
    return "\n".join(
        f"2026-10-04 {10 + (first_minute + n) // 60:02d}:{(first_minute + n) % 60:02d}:00 UTC::@:[1]:ERROR:  {word}"
        for n in range(count)
    )


def test_kept_lines_are_the_five_before_the_onset_the_first_fifteen_from_it_and_the_newest_twenty(config_data, tmp_path):
    files = [error_file("error/e.log", 110 * 60_000)]
    ctx, _ = run(config_data, tmp_path, log_answers(files, minute_lines(0, 100)), incident_start="2026-10-04T10:30:00Z")
    lines, fact = log_lines(ctx)
    minutes = [line[11:16] for line in lines]
    expected = [f"10:{m:02d}" for m in range(25, 45)] + [f"{10 + m // 60:02d}:{m % 60:02d}" for m in range(80, 100)]
    assert minutes == expected and len(lines) == 40
    for part in ("100 error lines found in the lines read", "40 kept", "60 not kept"):
        assert part in fact.summary
    assert fact.time == "2026-10-04T10:30:00Z"
    assert by_summary(ctx, "Database log line") == []


def test_overlapping_choices_are_kept_once_in_time_order(config_data, tmp_path):
    files = [error_file("error/e.log", 70 * 60_000)]
    ctx, _ = run(config_data, tmp_path, log_answers(files, minute_lines(0, 60)), incident_start="2026-10-04T10:30:00Z")
    lines, fact = log_lines(ctx)
    assert [line[11:16] for line in lines] == [f"10:{m:02d}" for m in range(25, 60)]
    assert "60 error lines found in the lines read" in fact.summary and "35 kept" in fact.summary and "25 not kept" in fact.summary


def test_without_an_incident_start_the_onset_is_taken_as_sixty_minutes_after_the_window_start(config_data, tmp_path):
    files = [error_file("error/e.log", 110 * 60_000)]
    ctx, _ = run(config_data, tmp_path, log_answers(files, minute_lines(0, 110)))
    lines, fact = log_lines(ctx)
    assert lines[5][11:16] == "11:00" and lines[4][11:16] == "10:59"
    assert "11:00" in fact.summary


def test_an_invalid_incident_start_is_an_error_and_the_default_onset_is_used(config_data, tmp_path):
    files = [error_file("error/e.log", 110 * 60_000)]
    ctx, _ = run(config_data, tmp_path, log_answers(files, minute_lines(0, 110)), incident_start="yesterday")
    assert [e["code"] for e in ctx.evidence.errors] == ["InvalidTarget"]
    assert log_lines(ctx)[0][5][11:16] == "11:00"


def test_the_onset_file_is_read_first_for_a_long_window(config_data, tmp_path):
    files = [hourly(h) for h in range(9, 22)]
    window = ("2026-10-04T09:30:00Z", "2026-10-04T21:30:00Z")
    for start in ("2026-10-04T10:30:00Z", None):
        _, aws = run(config_data, tmp_path, log_answers(files, ""), incident_start=start, window=window)
        assert downloaded(aws) == [f"error/postgresql.log.2026-10-04-{h:02d}" for h in (9, 10, 18, 19, 20, 21)], start


def minute_file(hhmm, written_minutes_after_ten):
    return {"LogFileName": f"error/postgresql.log.2026-10-04-{hhmm}", "Size": 1,
            "LastWritten": WINDOW_START_MILLIS + written_minutes_after_ten * 60_000}


def test_minute_rotated_files_cover_only_their_own_minutes(config_data, tmp_path):
    files = [minute_file(hhmm, written) for hhmm, written in (
        ("0930", -1), ("1000", 29), ("1030", 59), ("1100", 89), ("1130", 119), ("1200", 149), ("1230", 179))]
    window = ("2026-10-04T09:30:00Z", "2026-10-04T11:00:00Z")
    ctx, aws = run(config_data, tmp_path, log_answers(files, ""), incident_start="2026-10-04T10:30:00Z", window=window)
    assert downloaded(aws) == ["error/postgresql.log.2026-10-04-0930", "error/postgresql.log.2026-10-04-1000",
                               "error/postgresql.log.2026-10-04-1030"]
    assert by_summary(ctx, "overlapping the window that were not read") == []


def test_a_detail_line_stays_with_its_error_line_in_one_kept_entry(config_data, tmp_path):
    data = minute_lines(0, 3) + "\n2026-10-04 10:03:00 UTC::@:[1]:DETAIL:  Key (id)=(secret) already exists."
    ctx, _ = run(config_data, tmp_path, log_answers([error_file("error/e.log", 60 * 60_000)], data))
    lines, fact = log_lines(ctx)
    assert len(lines) == 3 and "DETAIL:  Key (id)=(<value>)" in lines[2] and lines[2].startswith("2026-10-04 10:02:00")
    assert "3 error lines found in the lines read" in fact.summary


def test_a_daily_or_undated_file_says_only_its_last_thousand_lines_were_read(config_data, tmp_path):
    daily = {"LogFileName": "error/postgresql.log.2026-10-04", "LastWritten": WINDOW_START_MILLIS + 3_600_000, "Size": 1}
    ctx, aws = run(config_data, tmp_path, log_answers([daily], "2026-10-04 10:30:00 UTC::@:[1]:ERROR:  onset"))
    call = aws.called("rds", "download-db-log-file-portion")[0]
    assert call[call.index("--number-of-lines") + 1] == "1000"
    assert "last 1,000 lines of each file" in log_lines(ctx)[1].summary


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
    assert "violates unique constraint \"users_phone_key\"" not in document and "users_phone_key" in document and "Key (phone)=(<value>)" in document


BACKSLASH = "\\"
REST = "<rest masked>"
PERSON = "Ada" + " Love" + "lace"
ROLE = "ada" + "." + "love" + "lace"
EMAIL = "ada" + "@" + "example.com"


def test_any_quote_that_does_not_open_a_kept_identifier_masks_the_rest_of_the_line():
    assert _mask_values("ERROR: INSERT INTO t (a, b) VALUES ('x y', 'it''s') failed") == "ERROR: INSERT INTO t (a, b) VALUES (" + REST
    assert _mask_values('ERROR:  invalid input syntax for type integer: "' + "4111" * 4 + '"') == "ERROR:  invalid input syntax for type integer: " + REST
    assert _mask_values("ERROR: unknown thing `secret col` in table") == "ERROR: unknown thing " + REST
    assert _mask_values("ERROR: near $$Dollar Secret Value$$ and more") == "ERROR: near " + REST
    assert _mask_values("ERROR: near $tag$tagged Value$tag$ and more") == "ERROR: near " + REST
    assert _mask_values("ERROR: near $1 and $2") == "ERROR: near $1 and $2"
    assert _mask_values("ERROR: syntax error near 'secret value") == "ERROR: syntax error near " + REST
    assert _mask_values("ERROR: near \u2018secret value\u2019 x") == "ERROR: near " + REST


def test_every_family_of_non_ascii_quotes_masks_the_rest_of_the_line():
    for opener, closer in UNICODE_QUOTE_PAIRS:
        masked = _mask_values(f"FATAL:  authentication for user {opener}{PERSON}{closer} failed")
        assert masked == "FATAL:  authentication for user " + REST, (opener, masked)
    role = "ada" + "_l"
    german = f"{POSTGRES_PREFIX}{role}@shop:[1]:FATAL:  Passwort-Authentifizierung f\u00fcr Benutzer \u00bb{role}\u00ab fehlgeschlagen"
    assert role not in _mask_values(german).split("@shop")[1]
    assert _mask_values(f"{POSTGRES_PREFIX}x@shop:[1]:ERROR:  user=\u00ab{PERSON}\u00bb,db=x") .endswith("user=<value>,db=x")
    assert _mask_values("ERROR: x user=") == "ERROR: x user=<value>"


def test_engine_codes_in_the_masked_rest_are_appended_after_the_marker():
    line = "2026-10-04T10:05:00.123456Z 14 [ERROR] [MY-010584] [Repl] Replica SQL for channel '': Error 'Duplicate entry '" \
        + EMAIL + "' for key 'users.email'' on query. Error_code: MY-001062"
    assert _mask_values(line) == "2026-10-04T10:05:00.123456Z <n> [ERROR] [MY-010584] [Repl] Replica SQL for channel " + REST + " [MY-001062]"
    tail = "ERROR: near '" + PERSON + "' SQLSTATE 23505, ORA-00942 and Error: 1105, Severity: 17, State: 2. MY-" + "4111" * 4
    assert _mask_values(tail) == "ERROR: near " + REST + " [SQLSTATE 23505] [ORA-00942] [Error: 1105, Severity: 17, State: 2]"
    assert _mask_values("ERROR: relation 'x' and 'y' MY-001062") == "ERROR: relation " + REST + " [MY-001062]"


def test_numbers_are_kept_only_in_fixed_contexts():
    cases = [
        ("ERROR: Operating system error number 28 in a file operation.", "ERROR: Operating system error number 28 in a file operation."),
        ("ERROR: failed errno 28 and errno: 13", "ERROR: failed errno 28 and errno: 13"),
        ("ERROR: errno " + "41114111", "ERROR: errno <n>"),
        ('ERROR:  relation "t" does not exist at character 15', 'ERROR:  relation "t" does not exist at character 15'),
        ("ERROR: syntax error at line 12", "ERROR: syntax error at line 12"),
        ("ERROR:  value too long for type character varying(20)", "ERROR:  value too long for type character varying(20)"),
        ("ERROR:  numeric field overflow numeric(10,2) and varchar(255)", "ERROR:  numeric field overflow numeric(10,2) and varchar(255)"),
        ("ERROR: customer 28 and (20) and number 28", "ERROR: customer <n> and (<n>) and number <n>"),
    ]
    for line, expected in cases:
        assert _mask_values(line) == expected, line


def test_backslashes_and_escape_strings_mask_the_rest_of_the_line():
    mysql = "ERROR: Duplicate entry 'O" + BACKSLASH + "'Brien-" + "5550" + "199' for key 'users.name'"
    assert _mask_values(mysql) == "ERROR: Duplicate entry " + REST
    standard = "ERROR: VALUES ('C:" + BACKSLASH + "dir" + BACKSLASH + "', '" + PERSON + "', 'z')"
    assert _mask_values(standard) == "ERROR: VALUES (" + REST
    assert _mask_values("ERROR: bad literal E'123-45-" + BACKSLASH + "'67" + "89' near") == "ERROR: bad literal E" + REST


def test_literal_prefixes_glued_to_a_quote_never_pass_as_contractions():
    for prefix in ("N", "E", "X", "B", "_binary", "_utf8mb4", "U&", "n"):
        masked = _mask_values(f"ERROR: VALUES ({prefix}'{PERSON}', 1)")
        assert masked == f"ERROR: VALUES ({prefix}" + REST, prefix
    assert _mask_values(f"ERROR: VALUES (N's {PERSON}')") == "ERROR: VALUES (N" + REST


def test_the_mysql_statement_form_replica_error_shows_nothing_after_the_first_unkept_quote():
    first, last, value = "Ada", "Love" + "lace", "ada" + "_l"
    line = (
        "2026-10-04T10:05:00.123456Z 12 [ERROR] [MY-010584] [Repl] Replica SQL for channel '': Error 'Duplicate entry '"
        + value + "' for key 'users.email'' on query. Default database: 'shop'. Query: 'INSERT INTO users VALUES ('"
        + first + "', '" + last + "')', Error_code: MY-001062"
    )
    masked = _mask_values(line)
    assert masked == "2026-10-04T10:05:00.123456Z <n> [ERROR] [MY-010584] [Repl] Replica SQL for channel " + REST + " [MY-001062]"
    nested = "ERROR: Error 'Duplicate entry '" + value + "' for key 'k'' on query"
    assert _mask_values(nested) == "ERROR: Error " + REST


def test_contractions_are_words_and_do_not_start_a_quoted_span():
    assert _mask_values("ERROR: Can't drop database 'shop'; database doesn't exist") == \
        "ERROR: Can't drop database 'shop'; database doesn't exist"
    name = "ada" + "_love" + "lace"
    assert _mask_values(f"ERROR: Can't find row for user '{name}' in table") == "ERROR: Can't find row for user " + REST
    assert _mask_values("ERROR: Table 'shop/orders' doesn't exist in engine") == "ERROR: Table " + REST


def test_a_kept_identifier_needs_a_whole_keyword_a_clean_close_and_a_clean_end():
    secret = "sk" + "Q7" + "vB9" + "xZ"
    for word in ("api_key", "secret_key", "user_key", "card_type", "shop.key", "monkey"):
        assert _mask_values(f'ERROR: bad {word} "{secret}" given') == f"ERROR: bad {word} " + REST, word
    assert _mask_values("ERROR: for key 'users.email''x") == "ERROR: for key " + REST
    assert _mask_values("ERROR: for key 'users\"email' end") == "ERROR: for key " + REST
    assert _mask_values("ERROR: for key 'abc'def end") == "ERROR: for key " + REST
    assert _mask_values("ERROR: key: 'abc' end") == "ERROR: key: " + REST
    assert _mask_values("ERROR: KEY 'abc' end") == "ERROR: KEY 'abc' end"


def test_an_unkept_quote_later_in_the_line_masks_from_the_first_kept_identifier():
    assert _mask_values(f"ERROR: relation 'x' for key 'k' {PERSON}' end") == "ERROR: relation " + REST
    assert _mask_values("ERROR: Unknown column 'Ada' in 'field list'") == "ERROR: Unknown column " + REST


def test_only_english_contractions_count_as_words():
    for glued in ("select", "THEN", "user", "_binary"):
        assert _mask_values(f"ERROR: {glued}'s {PERSON}' x") == f"ERROR: {glued}" + REST, glued
    assert _mask_values("ERROR: it's here and we're done, couldn't stop") == "ERROR: it's here and we're done, couldn't stop"


def test_identifier_shaped_names_after_a_keyword_are_kept():
    assert _mask_values('ERROR:  duplicate key value violates unique constraint "users_phone_key"') == \
        'ERROR:  duplicate key value violates unique constraint "users_phone_key"'
    assert _mask_values('ERROR:  relation "public.orders" does not exist') == 'ERROR:  relation "public.orders" does not exist'
    assert _mask_values('ERROR:  column "amount" of relation "orders" does not exist') == 'ERROR:  column "amount" of relation "orders" does not exist'
    assert _mask_values("ERROR 1062 (23000): Duplicate entry for key 'users.name'") == "ERROR 1062 (23000): Duplicate entry for key 'users.name'"
    assert _mask_values("ERROR: Unknown column `amount` here") == "ERROR: Unknown column `amount` here"
    assert _mask_values('ERROR:  index "orders_2024_idx" is corrupt') == 'ERROR:  index "orders_2024_idx" is corrupt'


def test_other_quoted_spans_are_masked_even_when_identifier_shaped():
    assert _mask_values('ERROR:  role "ada" does not exist') == "ERROR:  role " + REST
    assert _mask_values("ERROR: user 'ada' denied") == "ERROR: user " + REST
    assert _mask_values('ERROR:  relation "has space" does not exist') == "ERROR:  relation " + REST
    assert _mask_values('ERROR:  value "orders" bad') == "ERROR:  value " + REST
    assert _mask_values('ERROR:  table  "' + "x" * 70 + '" gone') == "ERROR:  table  " + REST


def test_mask_values_hides_the_row_in_a_detail_line_but_keeps_the_column_list():
    phone = "+44 7700 900" + "123"
    assert _mask_values(f"DETAIL:  Key (phone)=({phone}) already exists.") == "DETAIL:  Key (phone)=(<value>) already exists."
    assert _mask_values("DETAIL:  Failing row contains (1, " + "Ada" + ", x@example.org).") == "DETAIL:  Failing row contains (<value>)."
    assert _mask_values("DETAIL:  Failing row contains (1, '" + PERSON + "', x).") == "DETAIL:  Failing row contains (<value>)."


def test_mask_values_hides_nested_parentheses_in_a_key_group():
    line = "ERROR: Key (name)=(Bob (Jr) +44 7700 900" + "123) already exists"
    assert _mask_values(line) == "ERROR: Key (name)=(<value>) already exists"


def test_runs_of_two_or_more_digits_become_n_but_the_leading_timestamp_stays():
    assert _mask_values("2026-10-04 10:42:11.123456 UTC ERROR: user " + "12345678" + " missing, retry 3 of 4, port " + "5432") == \
        "2026-10-04 10:42:11.123456 UTC ERROR: user <n> missing, retry 3 of 4, port <n>"


def test_dates_split_pins_and_digits_glued_to_letters_leave_no_digit_pair():
    assert _mask_values("ERROR: born " + "01/02/" + "99" + " pin " + "12 " + "34") == "ERROR: born <n>/<n>/<n> pin <n> <n>"
    assert _mask_values("ERROR: token AB" + "12CD" + "34 and a1b2c3") == "ERROR: token AB<n>CD<n> and a1b2c3"


def test_engine_error_codes_are_kept_and_bounded():
    for line in ("[ERROR] [MY-" + "010000] [Server] x", "ERROR: failed SQLSTATE " + "23505", "ERROR 1062 (23000): Duplicate",
                 "Error: 18456, Severity: 14, State: 8.", "ORA-" + "00942: table or view does not exist"):
        assert _mask_values(line) == line
    assert _mask_values("Error: " + "4111" * 4 + ", Severity: 14, State: 8.") == "Error: <n>, Severity: <n>, State: 8."
    assert _mask_values("ERROR: SQLSTATE " + "4111" * 4) == "ERROR: SQLSTATE <n>"
    assert _mask_values("ERROR: ORA-" + "4111" * 4) == "ERROR: ORA-<n>"


def test_phone_and_card_shapes_with_any_separator_leave_no_digit_pair():
    shapes = [
        "(" + "555" + ") " + "123" + "-" + "4567", "555" + "-" + "0199", "+44 7700 900" + "123", "+44 77 00 12 34",
        "4111" + "." + "1111" + "." + "1111" + "." + "1111", "_".join(["4111"] * 4), " ".join(["4111"] * 4),
        "-".join(["4111"] * 4), " ".join(["4111"] * 4), "123" + "-" + "45" + "-" + "6789",
    ]
    for shape in shapes:
        masked = _mask_values(f"ERROR: customer rejected {shape} today")
        assert not re.search(r"\d\d", masked), (shape, masked)


def test_the_user_role_and_usename_values_are_masked_but_db_app_client_are_kept():
    line = "2026-10-04 10:42:11 UTC:user=Ada,db=shop,app=psql,client=10.0.0.5 ERROR: x"
    assert _mask_values(line) == "2026-10-04 10:42:11 UTC:user=<value>,db=shop,app=psql,client=10.0.0.5 ERROR: x"
    assert _mask_values("ERROR: role=ada usename=bob end") == "ERROR: role=<value> usename=<value>"
    spaced = f"2026-10-04 10:42:11 UTC:user={PERSON},db=shop ERROR: x"
    assert _mask_values(spaced) == "2026-10-04 10:42:11 UTC:user=<value>,db=shop ERROR: x"
    quoted = "2026-10-04 10:42:11 UTC:user=\"Love" + "lace, Ada\",db=shop ERROR: x"
    assert _mask_values(quoted) == "2026-10-04 10:42:11 UTC:user=<value>,db=shop ERROR: x"
    unclosed = f"2026-10-04 10:42:11 UTC:user='{PERSON} ERROR: x"
    assert _mask_values(unclosed) == "2026-10-04 10:42:11 UTC:user=<value>"


def test_the_role_in_the_default_rds_postgresql_prefix_is_masked():
    head = "2026-10-04 10:05:00 UTC:10.0.0.5(53412):"
    for role in (ROLE, "ada:x", "a@b", "Ada Love" + "lace", "o'brien", '"q"'):
        line = f"{head}{role}@shop:[24816]:ERROR:  deadlock detected"
        assert _mask_values(line) == f"{head}<value>@shop:[24816]:ERROR:  deadlock detected", role
    assert _mask_values("2026-10-04 10:05:00 UTC::@:[1]:ERROR:  x") == "2026-10-04 10:05:00 UTC::@:[1]:ERROR:  x"
    ipv6 = "2026-10-04 10:05:00 UTC:2001:db8::5(53412):" + ROLE + "@shop:[24816]:ERROR:  x"
    assert _mask_values(ipv6) == "2026-10-04 10:05:00 UTC:2001:db8::5(53412):<value>@shop:[24816]:ERROR:  x"


def test_the_mysql_user_and_host_pair_are_both_masked():
    line = "2026-10-04T10:05:00.123456Z 9 [Warning] [MY-010055] [Server] Access denied for user 'bob'@'10.0.0.5' (using password: YES)"
    assert _mask_values(line) == \
        "2026-10-04T10:05:00.123456Z 9 [Warning] [MY-010055] [Server] Access denied for user <value>@<value> (using password: YES)"


def test_free_text_before_a_late_marker_is_not_kept_as_a_prefix():
    line = f"2026-10-04 10:30:00.12 spid51      Login failed for user '{PERSON}'. Reason: Error: x"
    masked = _mask_values(line)
    assert PERSON.split()[0] not in masked and PERSON.split()[1] not in masked


def test_mask_values_leaves_a_line_without_values_alone():
    line = "2026-10-04 10:42:11 UTC ERROR: too many connections for role app, limit 5"
    assert _mask_values(line) == line


POSTGRES_PREFIX = "2026-10-04 10:05:00 UTC:10.0.0.5(53412):"


def test_three_realistic_postgresql_lines():
    cases = [
        (f'{POSTGRES_PREFIX}{ROLE}@shop:[24816]:ERROR:  duplicate key value violates unique constraint "users_email_key"',
         f'{POSTGRES_PREFIX}<value>@shop:[24816]:ERROR:  duplicate key value violates unique constraint "users_email_key"'),
        (f"{POSTGRES_PREFIX}{ROLE}@shop:[24816]:DETAIL:  Key (email)=({EMAIL}) already exists.",
         f"{POSTGRES_PREFIX}<value>@shop:[24816]:DETAIL:  Key (email)=(<value>) already exists."),
        (f"{POSTGRES_PREFIX}app@shop:[24816]:DETAIL:  Process 24816 waits for ShareLock on transaction 9123456; blocked by process 24901.",
         f"{POSTGRES_PREFIX}<value>@shop:[24816]:DETAIL:  Process <n> waits for ShareLock on transaction <n>; blocked by process <n>."),
        (f'{POSTGRES_PREFIX}{ROLE}@shop:[24816]:FATAL:  password authentication failed for user "{ROLE}"',
         f"{POSTGRES_PREFIX}<value>@shop:[24816]:FATAL:  password authentication failed for user " + REST),
    ]
    for line, expected in cases:
        assert _mask_values(line) == expected


def test_three_realistic_mysql_lines():
    stamp = "2026-10-04T10:05:00.123456Z"
    cases = [
        (f"{stamp} 0 [ERROR] [MY-012592] [InnoDB] Operating system error number 28 in a file operation.",
         f"{stamp} 0 [ERROR] [MY-012592] [InnoDB] Operating system error number 28 in a file operation."),
        (f"{stamp} 14 [ERROR] [MY-010584] [Repl] Replica SQL for channel '': Worker 1 failed executing transaction 'ANONYMOUS'"
         f" at source log mysql-bin-changelog.004512, end_log_pos 98213; Could not execute Write_rows event on table shop.users;"
         f" Duplicate entry '{EMAIL}' for key 'users.email', Error_code: 1062",
         f"{stamp} <n> [ERROR] [MY-010584] [Repl] Replica SQL for channel " + REST),
        (f"{stamp} 8 [ERROR] [MY-013183] [InnoDB] Table 'shop/orders' doesn't exist in engine",
         f"{stamp} 8 [ERROR] [MY-013183] [InnoDB] Table " + REST),
    ]
    for line, expected in cases:
        assert _mask_values(line) == expected


def test_three_realistic_sql_server_lines():
    stamp = "2026-10-04 10:30:00.12"
    cases = [
        (f"{stamp} Logon       Login failed for user '{ROLE}'. Reason: Password did not match that for the login provided. [CLIENT: 10.0.0.5]",
         f"{stamp} Logon       Login failed for user " + REST),
        (f"{stamp} spid51      Could not allocate space for object 'dbo.orders'.'PK_orders' in database 'shop' because the 'PRIMARY' filegroup is full.",
         f"{stamp} spid51      Could not allocate space for object " + REST),
        (f"{stamp} spid63      The transaction log for database 'shop' is full due to 'LOG_BACKUP'.",
         f"{stamp} spid63      The transaction log for database " + REST),
    ]
    for line, expected in cases:
        assert _mask_values(line) == expected
    assert _mask_values(f"{stamp} spid51      Error: 1105, Severity: 17, State: 2.") == f"{stamp} spid51      Error: 1105, Severity: 17, State: 2."


def test_the_sql_server_message_line_after_an_error_line_is_kept_and_masked(config_data, tmp_path):
    files = [{"LogFileName": "log/ERROR", "LastWritten": WINDOW_START_MILLIS + 6 * 3_600_000, "Size": 1}]
    data = "\n".join([
        "2026-10-04 10:30:00.12 Logon       Error: 18456, Severity: 14, State: 8.",
        f"2026-10-04 10:30:00.12 Logon       Login failed for user '{ROLE}'. Reason: Password did not match.",
        "2026-10-04 10:31:00.12 Server      Started",
    ])
    ctx, _ = run(config_data, tmp_path, log_answers(files, data))
    document = ctx.evidence.to_json()
    assert "Login failed for user" in document and ROLE not in document and "Started" not in document


QUOTE_OPENERS = ("'", '"', "`", "$$", "$tag$", "N'", "E'", "X'", "_binary'", "U&'", "''", "\\'")
# One pair per family of non-ASCII quotes: Unicode initial and final quotes, low quotes, CJK corner brackets,
# full-width quotation mark and apostrophe, acute and grave accents.
UNICODE_QUOTE_PAIRS = (
    ("\u00ab", "\u00bb"), ("\u00bb", "\u00ab"), ("\u2039", "\u203a"), ("\u2018", "\u2019"), ("\u201c", "\u201d"),
    ("\u201b", "\u2019"), ("\u201f", "\u201d"), ("\u201e", "\u201c"), ("\u201a", "\u2018"), ("\u2e42", "\u201d"),
    ("\u300c", "\u300d"), ("\u300e", "\u300f"), ("\uff02", "\uff02"), ("\uff07", "\uff07"), ("\u00b4", "\u00b4"),
    ("\u02ca", "\u02ca"), ("\u02cb", "\u02cb"), ("\uff40", "\uff40"),
)
CONTEXT_WORDS = (
    "key", "relation", "table", "column", "api_key", "Can't", "doesn't", "for", "VALUES (", "=", ",", "(", "Error",
    "database", "constraint", "x", "", "''", "'a'", "\"b\"", "`c`", "\\", "key 'users.email'", "O'",
)
CONTENT_PIECES = ("", "it''s ", "a\\'b ", "\"", "'", "`", ") ", "$$", "t ", "s ", "x' for key 'k' ", "Can't ")


def planted_line(rng, marker):
    """A line with the marker inside a quote of a random kind, at a random place, among other quotes and words."""
    before = " ".join(rng.choice(CONTEXT_WORDS) for _ in range(rng.randint(0, 4)))
    if rng.random() < 0.4:
        opener, closer = rng.choice(UNICODE_QUOTE_PAIRS)
    else:
        opener = rng.choice(QUOTE_OPENERS)
        closer = opener[-1] if not opener.startswith("$") else opener
    inside = rng.choice(CONTENT_PIECES) + marker + rng.choice(CONTENT_PIECES)
    after = " ".join(rng.choice(CONTEXT_WORDS) for _ in range(rng.randint(0, 4)))
    keyword = rng.choice(("", "key ", "relation ", "column ", "table "))
    return f"2026-10-04 10:05:00 UTC:10.0.0.5(1):app@shop:[7]:ERROR:  {before} {keyword}{opener}{inside}{closer} {after}"


def test_fuzz_a_marker_inside_any_quote_never_survives():
    import random
    rng = random.Random(20261004)
    first, second = "Qz" + "vk", "Mar" + "kerx"
    marker = f"{first} {second}"
    for _ in range(2000):
        line = planted_line(rng, marker)
        masked = _mask_values(line)
        assert first not in masked and second not in masked, (line, masked)


def test_a_detail_line_directly_after_a_kept_line_is_included_after_masking(config_data, tmp_path):
    phone = "+44 7700 900" + "123"
    data = "\n".join([
        "2026-10-04 10:05:00 UTC::@:[1]:ERROR:  duplicate key value violates unique constraint \"users_phone_key\"",
        f"2026-10-04 10:05:00 UTC::@:[1]:DETAIL:  Key (phone)=({phone}) already exists.",
        "2026-10-04 10:06:00 UTC::@:[1]:LOG:  checkpoint",
        "2026-10-04 10:06:01 UTC::@:[1]:DETAIL:  not attached to a kept line (secret-ish)",
    ])
    ctx, _ = run(config_data, tmp_path, log_answers([error_file("error/e.log", 1000)], data))
    lines, _ = log_lines(ctx)
    detail = [line for line in lines if "DETAIL" in line]
    assert len(detail) == 1 and "Key (phone)=(<value>) already exists." in detail[0] and "users_phone_key" in detail[0]
    assert "not attached" not in ctx.evidence.to_json()
    assert phone not in ctx.evidence.to_json()


def test_secret_in_log_line_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "5" * 10
    files = [error_file("error/e.log", 1000)]
    ctx, _ = run(config_data, tmp_path, log_answers(files, f"2026-10-04 10:05:00 UTC::@:[1]:ERROR: connection failed password={secret}"))
    assert secret not in ctx.evidence.to_json()
    assert "connection failed" in ctx.evidence.to_json()


def test_metrics_use_the_instance_dimension_and_stats(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [97.5]}]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    assert [f.data["maximum"] for f in by_summary(ctx, "CPUUtilization (Average)")] == [97.5]
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


def endpoint_facts(ctx):
    return [f for f in ctx.evidence.facts if "endpoint" in f.summary.lower() and f.kind == "current"]


def test_an_instance_states_its_endpoint(config_data, tmp_path):
    answers = healthy_answers(**{"rds describe-db-instances": instance(
        Endpoint={"Address": "orders-db.example.com", "Port": 5432, "HostedZoneId": "Z1"})})
    ctx, aws = run(config_data, tmp_path, answers)
    facts = endpoint_facts(ctx)
    assert len(facts) == 1 and facts[0].resource == "db/orders-db" and facts[0].command
    assert "orders-db.example.com" in facts[0].summary and "5432" in facts[0].summary
    assert facts[0].data == {"address": "orders-db.example.com", "port": 5432}
    # No new call: the endpoint comes from the describe answer already read.
    assert {tuple(c[1:3]) for c in aws.calls} == {("rds", "describe-db-instances"), ("rds", "describe-events"),
                                                  ("rds", "describe-db-log-files"), ("cloudwatch", "get-metric-data")}
    assert_read_only(ctx, aws)


def test_an_aurora_cluster_states_its_writer_reader_and_custom_endpoints(config_data, tmp_path):
    custom = [f"custom-{n}.cluster-custom.example.com" for n in range(12)]
    cluster = {"DBClusters": [{"DBClusterIdentifier": "orders-db", "Status": "available", "Engine": "aurora-postgresql",
                               "EngineVersion": "15.4", "Endpoint": "orders-db.cluster.example.com",
                               "ReaderEndpoint": "orders-db.cluster-ro.example.com", "Port": 5432,
                               "CustomEndpoints": custom, "DBClusterMembers": []}]}
    answers = healthy_answers(**{"rds describe-db-instances": NOT_FOUND, "rds describe-db-clusters": cluster})
    ctx, aws = run(config_data, tmp_path, answers)
    facts = endpoint_facts(ctx)
    assert len(facts) == 1 and facts[0].resource == "db/orders-db"
    for part in ("orders-db.cluster.example.com", "orders-db.cluster-ro.example.com", "5432"):
        assert part in facts[0].summary
    assert facts[0].data["writer"] == "orders-db.cluster.example.com"
    assert facts[0].data["reader"] == "orders-db.cluster-ro.example.com" and facts[0].data["port"] == 5432
    assert facts[0].data["custom_endpoints"] == custom[:10] and facts[0].data["custom_endpoints_not_listed"] == 2
    assert_read_only(ctx, aws)


def test_an_instance_without_an_endpoint_yet_gets_no_endpoint_fact(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"rds describe-db-instances": instance(DBInstanceStatus="creating")}))
    assert endpoint_facts(ctx) == [] and ctx.evidence.errors == []
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"rds describe-db-instances": instance(Endpoint={})}))
    assert endpoint_facts(ctx) == [] and ctx.evidence.errors == []


ACCOUNT = "1" * 12


def rds_arn(kind, name):
    return f"arn:aws:rds:eu-west-1:{ACCOUNT}:{kind}:{name}"


def test_the_instance_state_fact_holds_its_arn_and_related_names(config_data, tmp_path):
    body = instance(
        DBInstanceArn=rds_arn("db", "orders-db"),
        DBSubnetGroup={"DBSubnetGroupName": "orders-subnets", "DBSubnetGroupArn": rds_arn("subgrp", "orders-subnets"), "VpcId": "vpc-1"},
        VpcSecurityGroups=[{"VpcSecurityGroupId": "sg-0a1b2c3d", "Status": "active"}, {"VpcSecurityGroupId": "sg-0e0f", "Status": "active"}],
    )
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"rds describe-db-instances": body}))
    state = ctx.evidence.facts[0]
    assert state.data["arn"] == rds_arn("db", "orders-db")
    assert state.data["parameter_group_names"] == ["orders-pg"]
    assert state.data["subnet_group_name"] == "orders-subnets" and state.data["subnet_group_arn"] == rds_arn("subgrp", "orders-subnets")
    assert state.data["security_group_ids"] == ["sg-0a1b2c3d", "sg-0e0f"]
    assert state.data["DBInstanceStatus"] == "available"
    assert_read_only(ctx, aws)


def test_an_instance_answer_without_arn_fields_writes_no_arn_key(config_data, tmp_path):
    body = instance()
    body["DBInstances"][0].pop("DBParameterGroups")
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"rds describe-db-instances": body}))
    state = ctx.evidence.facts[0]
    assert "arn" not in state.data and "subnet_group_name" not in state.data and "security_group_ids" not in state.data
    assert "parameter_group_names" not in state.data and ctx.evidence.errors == []


def test_the_cluster_state_fact_holds_its_arn_its_members_and_the_writer_arn(config_data, tmp_path):
    cluster = {"DBClusters": [{"DBClusterIdentifier": "orders-db", "DBClusterArn": rds_arn("cluster", "orders-db"),
                               "Status": "available", "Engine": "aurora-postgresql", "EngineVersion": "15.4",
                               "DBClusterParameterGroup": "orders-cluster-pg", "DBSubnetGroup": "orders-subnets",
                               "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-0a1b2c3d", "Status": "active"}],
                               "DBClusterMembers": [{"DBInstanceIdentifier": "orders-db-1", "IsClusterWriter": True},
                                                    {"DBInstanceIdentifier": "orders-db-2", "IsClusterWriter": False}]}]}
    per = {"rds describe-db-instances": {
        "orders-db": NOT_FOUND,
        "orders-db-1": instance("orders-db-1", DBInstanceArn=rds_arn("db", "orders-db-1")),
        "orders-db-2": instance("orders-db-2", DBInstanceArn=rds_arn("db", "orders-db-2"))}}
    fake = ByArgument(healthy_answers(**{"rds describe-db-clusters": cluster}), "--db-instance-identifier", per)
    ctx, aws = run(config_data, tmp_path, healthy_answers(), fake=fake)
    state = by_summary(ctx, "Cluster orders-db is available")[0]
    assert state.data["arn"] == rds_arn("cluster", "orders-db")
    assert state.data["writer_instance_arn"] == rds_arn("db", "orders-db-1")
    assert state.data["member_instances"] == [
        {"id": "orders-db-1", "writer": True, "arn": rds_arn("db", "orders-db-1")},
        {"id": "orders-db-2", "writer": False, "arn": rds_arn("db", "orders-db-2")},
    ]
    assert state.data["cluster_parameter_group_name"] == "orders-cluster-pg"
    assert state.data["subnet_group_name"] == "orders-subnets" and state.data["security_group_ids"] == ["sg-0a1b2c3d"]
    member = by_summary(ctx, "Instance orders-db-2 is")[0]
    assert member.data["arn"] == rds_arn("db", "orders-db-2") and "describe-db-instances" in member.command
    assert "orders-db-2" in member.command
    assert_read_only(ctx, aws)
