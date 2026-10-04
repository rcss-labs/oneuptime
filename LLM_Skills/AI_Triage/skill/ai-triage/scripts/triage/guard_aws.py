"""Decide whether one AWS CLI invocation is a triage read."""
from __future__ import annotations

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


def check_aws(argv: tuple[str, ...], env: tuple[str, ...], profiles: frozenset[str]) -> Verdict:
    if any(assignment.startswith("AWS_") for assignment in env):
        return Verdict(ASK, "AWS_* environment variables are set on the command line")
    abbreviated = _abbreviated_option(argv)
    if abbreviated:
        return Verdict(ASK, f"option {abbreviated} could be an abbreviation the guard cannot check")
    if "--debug" in argv:
        return Verdict(DENY, "--debug prints request signing details")
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
    for word in args:
        flag = word.split("=", 1)[0]
        if flag in REVEALING_FLAGS:
            return Verdict(DENY, f"{flag} reads encrypted or secret values")
    if service == "s3" and operation != "ls":
        return Verdict(DENY, f"aws s3 {operation} is not a read-only listing")
    if (service, operation) in READ_EXACT or operation.startswith(READ_PREFIXES):
        return Verdict(ALLOW, f"aws {service} {operation} is a read")
    return Verdict(DENY, f"aws {service} {operation} is not a known read operation")
