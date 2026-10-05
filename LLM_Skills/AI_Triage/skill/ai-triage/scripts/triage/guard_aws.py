"""Decide whether one AWS CLI invocation is a triage read."""
from __future__ import annotations

import os
from typing import Sequence

from triage.verdict import ALLOW, ASK, DENY, Verdict

VALUE_OPTIONS = frozenset(
    {
        "--profile",
        "--region",
        "--output",
        "--query",
        "--endpoint-url",
        "--color",
        "--ca-bundle",
        "--cli-read-timeout",
        "--cli-connect-timeout",
        "--cli-binary-format",
    }
)
READ_PREFIXES = ("describe-", "list-", "get-", "batch-get-")
READ_EXACT = frozenset(
    {
        ("cloudtrail", "lookup-events"),
        ("logs", "filter-log-events"),
        ("logs", "start-query"),
        ("logs", "stop-query"),
        ("rds", "download-db-log-file-portion"),
        ("iam", "simulate-principal-policy"),
        ("route53", "test-dns-answer"),
        ("s3", "ls"),
    }
)
# Operations that look like reads but return secrets, credentials, or stored data.
DENY_EXACT = frozenset(
    {
        ("secretsmanager", "get-secret-value"),
        ("secretsmanager", "batch-get-secret-value"),
        ("ec2", "get-password-data"),
        ("ecr", "get-login-password"),
        ("ecr", "get-authorization-token"),
        ("ecr", "get-download-url-for-layer"),
        ("ecr", "batch-get-image"),
        ("eks", "get-token"),
        ("lambda", "get-function"),
        ("s3api", "get-object"),
        ("sts", "get-session-token"),
        ("sts", "get-federation-token"),
        ("dynamodb", "get-item"),
        ("dynamodb", "batch-get-item"),
        ("kinesis", "get-records"),
        ("kinesis", "get-shard-iterator"),
        ("codecommit", "get-file"),
        ("codecommit", "get-blob"),
        ("glue", "get-connection"),
        ("glue", "get-connections"),
        ("athena", "get-query-results"),
        ("appconfig", "get-configuration"),
        ("appconfigdata", "get-latest-configuration"),
        ("s3control", "get-data-access"),
        ("lightsail", "get-instance-access-details"),
        ("lambda", "get-layer-version"),
        ("lambda", "get-layer-version-by-arn"),
        ("codecommit", "get-folder"),
        ("ec2", "get-console-screenshot"),
    }
)
# An operation whose name contains one of these returns a secret, whatever its service.
DENY_NAME_PARTS = ("secret-value", "password", "credentials", "token", "login")
# Flags that make an otherwise ordinary read return secret values.
REVEALING_FLAGS = frozenset({"--with-decryption", "--include-value", "--include-values"})
# The AWS CLI accepts any unique prefix of a long option, so these could hide behind a shortened spelling.
CHECKED_OPTIONS = frozenset(
    {"--profile", "--region", "--endpoint-url", "--debug", "--with-decryption", "--include-value", "--include-values", "--no-verify-ssl", "--ca-bundle"}
) | {option for option in VALUE_OPTIONS if option.startswith("--")}
# Options that change how the triage credentials' requests are routed or protected.
ASK_OPTIONS = {"--endpoint-url": "redirects the request", "--no-verify-ssl": "turns off TLS verification", "--ca-bundle": "changes which certificates are trusted"}
# Operations whose response body the AWS CLI writes to a required <outfile> positional.
# Generated from the CLI's bundled models by tools/list_streaming_operations.py; a test checks it is complete.
STREAMING_OUTPUT_OPERATIONS = frozenset(
    {
        "apigateway get-export",
        "apigateway get-sdk",
        "apigatewayv2 export-api",
        "appconfig create-hosted-configuration-version",
        "appconfig get-configuration",
        "appconfig get-hosted-configuration-version",
        "appconfigdata get-latest-configuration",
        "appsync get-introspection-schema",
        "bedrock-agentcore invoke-agent-runtime",
        "bedrock-runtime invoke-model",
        "cloudfront get-connection-function",
        "cloudfront get-function",
        "codeartifact get-package-version-asset",
        "codeguruprofiler get-profile",
        "datazone get-lineage-event",
        "ebs get-snapshot-block",
        "geo-maps get-glyphs",
        "geo-maps get-sprites",
        "geo-maps get-static-map",
        "geo-maps get-style-descriptor",
        "geo-maps get-tile",
        "glacier get-job-output",
        "iot-data delete-thing-shadow",
        "iot-data get-thing-shadow",
        "iot-data update-thing-shadow",
        "iotwireless get-position-estimate",
        "iotwireless get-resource-position",
        "kinesis-video-archived-media get-clip",
        "kinesis-video-archived-media get-media-for-fragment-list",
        "kinesis-video-media get-media",
        "lakeformation get-work-unit-results",
        "lambda invoke",
        "lex-runtime post-content",
        "lex-runtime put-session",
        "lexv2-runtime put-session",
        "lexv2-runtime recognize-utterance",
        "location get-map-glyphs",
        "location get-map-sprites",
        "location get-map-style-descriptor",
        "location get-map-tile",
        "medialive describe-input-device-thumbnail",
        "mediastore-data get-object",
        "medical-imaging get-image-frame",
        "medical-imaging get-image-set-metadata",
        "neptune-graph execute-query",
        "neptunedata execute-gremlin-explain-query",
        "neptunedata execute-gremlin-profile-query",
        "neptunedata execute-open-cypher-explain-query",
        "omics get-read-set",
        "omics get-reference",
        "polly synthesize-speech",
        "s3api get-object",
        "s3api get-object-torrent",
        "sagemaker-geospatial get-tile",
        "sagemaker-runtime invoke-endpoint",
        "schemas get-code-binding-source",
        "tnb get-sol-function-package-content",
        "tnb get-sol-function-package-descriptor",
        "tnb get-sol-network-package-content",
        "tnb get-sol-network-package-descriptor",
        "workmailmessageflow get-raw-message-content",
    }
)
# No aws argument may name a local file: it could be read (file://) or written (an outfile).
# The CloudWatch agent names log groups after file paths (/var/log/messages), so these option values may look like
# paths. The list options take every value up to the next option. Never a home, relative, or file:// value.
LOG_NAME_OPTIONS = frozenset({"--log-group-name", "--log-group-name-prefix", "--log-group-name-pattern",
                              "--log-group-identifier", "--log-stream-name", "--log-stream-name-prefix"})
LOG_NAME_LIST_OPTIONS = frozenset({"--log-group-names", "--log-group-identifiers", "--log-stream-names"})
NEVER_EXEMPT_PREFIXES = ("~", "./", "../", "file://", "fileb://")
LOCAL_PATH_PREFIXES = ("/users/", "/home/", "/tmp", "/private/", "/var/", "/etc/", "/opt/", "/volumes/", "./", "../",
                       "~", "file://", "fileb://")
LOCAL_READS = frozenset({("configure", "list"), ("configure", "list-profiles")})


def _option_values(argv: tuple[str, ...], name: str) -> list[str]:
    """Every value given for an option. The AWS CLI lets an option repeat and uses the last."""
    values: list[str] = []
    for index, token in enumerate(argv):
        if token == name and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith(name + "="):
            values.append(token.split("=", 1)[1])
    return values


def _service_and_operation(argv: tuple[str, ...]) -> tuple[str | None, str | None]:
    positionals: list[str] = []
    index = 1
    while index < len(argv) and len(positionals) < 2:
        token = argv[index]
        if token.startswith("-"):
            index += 2 if token in VALUE_OPTIONS else 1
            continue
        positionals.append(token)
        index += 1
    positionals += [None, None]
    return positionals[0], positionals[1]


def _abbreviated_option(argv: tuple[str, ...]) -> str | None:
    for word in argv:
        if word.startswith("--"):
            name = word.split("=", 1)[0]
            if name not in CHECKED_OPTIONS and any(option.startswith(name) for option in CHECKED_OPTIONS):
                return name
    return None


GLOBAL_OPTIONS = ("--profile", "--region", "--endpoint-url", "--debug", "--no-verify-ssl", "--ca-bundle")


def global_option_in(args: Sequence[str]) -> str | None:
    """The first word that is, or could abbreviate, an option that run_aws must set itself."""
    for word in args:
        if word.startswith("--"):
            name = word.split("=", 1)[0]
            if any(option.startswith(name) for option in GLOBAL_OPTIONS):
                return name
    return None


def _is_local_path(value: str) -> bool:
    # Compared without letter case: macOS file systems usually ignore it, and so does the CLI's file:// prefix.
    lowered = value.casefold()
    home = os.environ.get("HOME", "").rstrip("/").casefold()
    if home and (lowered == home or lowered.startswith(home + "/")):
        return True
    return lowered.startswith(LOCAL_PATH_PREFIXES)


def _exempt_log_name(value: str) -> bool:
    lowered = value.casefold()
    home = os.environ.get("HOME", "").rstrip("/").casefold()
    if home and (lowered == home or lowered.startswith(home + "/")):
        return False
    return not lowered.startswith(NEVER_EXEMPT_PREFIXES)


def local_path_argument(args: Sequence[str]) -> str | None:
    """The first argument, or value after =, that names a local path (log group and stream names excepted)."""
    exempt_next, exempt_list = False, False
    for word in args:
        is_option = word.startswith("-")
        is_log_value = not is_option and (exempt_next or exempt_list)
        exempt_next = False
        if is_option:
            name, has_value, value = word.partition("=")
            exempt_list = name in LOG_NAME_LIST_OPTIONS and not has_value
            exempt_next = name in LOG_NAME_OPTIONS and not has_value
            if has_value and name in LOG_NAME_OPTIONS | LOG_NAME_LIST_OPTIONS:
                if _is_local_path(value) and not _exempt_log_name(value):
                    return word
                continue
        if is_log_value:
            if _is_local_path(word) and not _exempt_log_name(word):
                return word
            continue
        values = [word] + ([word.split("=", 1)[1]] if "=" in word else [])
        if any(_is_local_path(value) for value in values):
            return word
    return None


def check_aws(argv: tuple[str, ...], env: tuple[str, ...], profiles: frozenset[str]) -> Verdict:
    if any(assignment.startswith("AWS_") for assignment in env):
        return Verdict(ASK, "AWS_* environment variables are set on the command line")
    abbreviated = _abbreviated_option(argv)
    if abbreviated:
        return Verdict(ASK, f"option {abbreviated} could be an abbreviation the guard cannot check")
    if "--debug" in argv:
        return Verdict(DENY, "--debug prints request signing details")
    local_path = local_path_argument(argv[1:])
    if local_path:
        return Verdict(DENY, f"aws arguments may not name a local path ({local_path})")
    for option, effect in ASK_OPTIONS.items():
        if any(word == option or word.startswith(option + "=") for word in argv):
            return Verdict(ASK, f"{option} {effect}")

    service, operation = _service_and_operation(argv)
    if service is None:
        return Verdict(ALLOW, "version check") if "--version" in argv else Verdict(ASK, "no AWS service given")
    if (service, operation) in LOCAL_READS:
        return Verdict(ALLOW, "reads local AWS CLI settings")
    if service == "configure":
        return Verdict(DENY, "changes local AWS CLI settings")
    if service == "sso":
        return Verdict(DENY, "sign in yourself with: aws sso login --profile <triage profile>")

    given_profiles = _option_values(argv, "--profile")
    if not given_profiles:
        return Verdict(DENY, "every AWS command must set --profile to a triage profile")
    for profile in given_profiles:
        if profile not in profiles:
            return Verdict(DENY, f"profile '{profile}' is not a triage profile")
    if not _option_values(argv, "--region"):
        return Verdict(DENY, "every AWS command must set --region")
    if operation is None:
        return Verdict(ASK, f"no operation given for aws {service}")
    if operation == "help":
        return Verdict(ALLOW, "help text")
    return classify(service, operation, argv[1:])


def classify(service: str, operation: str, args: Sequence[str]) -> Verdict:
    """The rules that depend only on the service, the operation, and the argument words."""
    if (service, operation) in DENY_EXACT or any(part in operation for part in DENY_NAME_PARTS):
        return Verdict(DENY, f"aws {service} {operation} returns secrets, credentials, or stored data")
    if f"{service} {operation}" in STREAMING_OUTPUT_OPERATIONS:
        return Verdict(DENY, f"aws {service} {operation} writes its response to a local output file")
    for word in args:
        flag = word.split("=", 1)[0]
        if flag in REVEALING_FLAGS:
            return Verdict(DENY, f"{flag} reads encrypted or secret values")
    if service == "s3" and operation != "ls":
        return Verdict(DENY, f"aws s3 {operation} is not a read-only listing")
    if (service, operation) in READ_EXACT or operation.startswith(READ_PREFIXES):
        return Verdict(ALLOW, f"aws {service} {operation} is a read")
    return Verdict(DENY, f"aws {service} {operation} is not a known read operation")
