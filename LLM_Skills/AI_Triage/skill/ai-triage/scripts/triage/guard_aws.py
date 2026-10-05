"""Decide whether one AWS CLI invocation is a triage read."""
from __future__ import annotations

import os
from typing import Sequence

from triage.verdict import ALLOW, ASK, DENY, Verdict, strictest

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
        ("dynamodbstreams", "get-records"),
        ("dynamodbstreams", "get-shard-iterator"),
    }
)
# Reads whose output often holds secrets; no triage step needs them, so the engineer decides.
ASK_READS = {
    ("ec2", "describe-launch-template-versions"): "the output can hold launch template user data, which often holds secrets",
    ("autoscaling", "describe-launch-configurations"): "the output can hold launch configuration user data, which often holds secrets",
    ("cloudformation", "get-template"): "the output is the whole template, which can hold secrets in defaults or parameters",
    ("codebuild", "batch-get-projects"): "the output can hold the build environment, whose variables often hold secrets",
}
# Reads that return secrets outright, with what they return.
DENY_READS = {("ec2", "describe-vpn-connections"): "returns the VPN tunnels' pre-shared keys"}
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
# Every word the installed AWS CLI accepts after "aws". Generated by tools/list_aws_services.py; a test checks it
# is complete. Any other word could be an alias from ~/.aws/cli/alias, which runs whatever it holds.
AWS_SERVICE_NAMES = frozenset(
    {
        "accessanalyzer", "account", "acm", "acm-pca", "aiops", "amp", "amplify", "amplifybackend",
        "amplifyuibuilder", "apigateway", "apigatewaymanagementapi", "apigatewayv2", "appconfig", "appconfigdata",
        "appfabric", "appflow", "appintegrations", "application-autoscaling", "application-insights",
        "application-signals", "applicationcostprofiler", "appmesh", "apprunner", "appstream", "appsync",
        "arc-region-switch", "arc-zonal-shift", "artifact", "athena", "auditmanager", "autoscaling",
        "autoscaling-plans", "b2bi", "backup", "backup-gateway", "backupsearch", "batch", "bcm-dashboards",
        "bcm-data-exports", "bcm-pricing-calculator", "bcm-recommended-actions", "bedrock", "bedrock-agent",
        "bedrock-agent-runtime", "bedrock-agentcore", "bedrock-agentcore-control", "bedrock-data-automation",
        "bedrock-data-automation-runtime", "bedrock-runtime", "billing", "billingconductor", "braket", "budgets",
        "ce", "chatbot", "chime", "chime-sdk-identity", "chime-sdk-media-pipelines", "chime-sdk-meetings",
        "chime-sdk-messaging", "chime-sdk-voice", "cleanrooms", "cleanroomsml", "cli-dev", "cloud9", "cloudcontrol",
        "clouddirectory", "cloudformation", "cloudfront", "cloudfront-keyvaluestore", "cloudhsm", "cloudhsmv2",
        "cloudsearch", "cloudsearchdomain", "cloudtrail", "cloudtrail-data", "cloudwatch", "codeartifact",
        "codebuild", "codecatalyst", "codecommit", "codeconnections", "codeguru-reviewer", "codeguru-security",
        "codeguruprofiler", "codepipeline", "codestar-connections", "codestar-notifications", "cognito-identity",
        "cognito-idp", "cognito-sync", "comprehend", "comprehendmedical", "compute-optimizer",
        "compute-optimizer-automation", "configservice", "configure", "connect", "connect-contact-lens",
        "connectcampaigns", "connectcampaignsv2", "connectcases", "connecthealth", "connectparticipant",
        "controlcatalog", "controltower", "cost-optimization-hub", "cur", "customer-profiles", "databrew",
        "dataexchange", "datapipeline", "datasync", "datazone", "dax", "ddb", "deadline", "deploy", "detective",
        "devicefarm", "devops-guru", "directconnect", "discovery", "dlm", "dms", "docdb", "docdb-elastic", "drs",
        "ds", "ds-data", "dsql", "dynamodb", "dynamodbstreams", "ebs", "ec2", "ec2-instance-connect", "ecr",
        "ecr-public", "ecs", "efs", "eks", "eks-auth", "elasticache", "elasticbeanstalk", "elb", "elbv2",
        "elementalinference", "emr", "emr-containers", "emr-serverless", "entityresolution", "es", "events", "evs",
        "finspace", "finspace-data", "firehose", "fis", "fms", "forecast", "forecastquery", "frauddetector",
        "freetier", "fsx", "gamelift", "gameliftstreams", "geo-maps", "geo-places", "geo-routes", "glacier",
        "globalaccelerator", "glue", "grafana", "greengrass", "greengrassv2", "groundstation", "guardduty", "health",
        "healthlake", "help", "history", "iam", "identitystore", "imagebuilder", "importexport", "inspector",
        "inspector-scan", "inspector2", "internetmonitor", "invoicing", "iot", "iot-data", "iot-jobs-data",
        "iot-managed-integrations", "iotdeviceadvisor", "iotevents", "iotevents-data", "iotfleetwise",
        "iotsecuretunneling", "iotsitewise", "iotthingsgraph", "iottwinmaker", "iotwireless", "ivs", "ivs-realtime",
        "ivschat", "kafka", "kafkaconnect", "kendra", "kendra-ranking", "keyspaces", "keyspacesstreams", "kinesis",
        "kinesis-video-archived-media", "kinesis-video-media", "kinesis-video-signaling",
        "kinesis-video-webrtc-storage", "kinesisanalytics", "kinesisanalyticsv2", "kinesisvideo", "kms",
        "lakeformation", "lambda", "launch-wizard", "lex-models", "lex-runtime", "lexv2-models", "lexv2-runtime",
        "license-manager", "license-manager-linux-subscriptions", "license-manager-user-subscriptions", "lightsail",
        "location", "login", "logout", "logs", "lookoutequipment", "m2", "machinelearning", "macie2", "mailmanager",
        "managedblockchain", "managedblockchain-query", "marketplace-agreement", "marketplace-catalog",
        "marketplace-deployment", "marketplace-entitlement", "marketplace-reporting", "marketplacecommerceanalytics",
        "mediaconnect", "mediaconvert", "medialive", "mediapackage", "mediapackage-vod", "mediapackagev2",
        "mediastore", "mediastore-data", "mediatailor", "medical-imaging", "memorydb", "meteringmarketplace", "mgh",
        "mgn", "migration-hub-refactor-spaces", "migrationhub-config", "migrationhuborchestrator",
        "migrationhubstrategy", "mpa", "mq", "mturk", "mwaa", "mwaa-serverless", "neptune", "neptune-graph",
        "neptunedata", "network-firewall", "networkflowmonitor", "networkmanager", "networkmonitor", "notifications",
        "notificationscontacts", "nova-act", "oam", "observabilityadmin", "odb", "omics", "opensearch",
        "opensearchserverless", "organizations", "osis", "outposts", "panorama", "partnercentral-account",
        "partnercentral-benefits", "partnercentral-channel", "partnercentral-selling", "payment-cryptography",
        "payment-cryptography-data", "pca-connector-ad", "pca-connector-scep", "pcs", "personalize",
        "personalize-events", "personalize-runtime", "pi", "pinpoint", "pinpoint-email", "pinpoint-sms-voice",
        "pinpoint-sms-voice-v2", "pipes", "polly", "pricing", "proton", "qapps", "qbusiness", "qconnect",
        "quicksight", "ram", "rbin", "rds", "rds-data", "redshift", "redshift-data", "redshift-serverless",
        "rekognition", "repostspace", "resiliencehub", "resource-explorer-2", "resource-groups",
        "resourcegroupstaggingapi", "rolesanywhere", "route53", "route53-recovery-cluster",
        "route53-recovery-control-config", "route53-recovery-readiness", "route53domains", "route53globalresolver",
        "route53profiles", "route53resolver", "rtbfabric", "rum", "s3", "s3api", "s3control", "s3outposts",
        "s3tables", "s3vectors", "sagemaker", "sagemaker-a2i-runtime", "sagemaker-edge",
        "sagemaker-featurestore-runtime", "sagemaker-geospatial", "sagemaker-metrics", "sagemaker-runtime",
        "savingsplans", "scheduler", "schemas", "sdb", "secretsmanager", "security-ir", "securityhub",
        "securitylake", "serverlessrepo", "service-quotas", "servicecatalog", "servicecatalog-appregistry",
        "servicediscovery", "ses", "sesv2", "shield", "signer", "signer-data", "signin", "simspaceweaver",
        "snow-device-management", "snowball", "sns", "socialmessaging", "sqs", "ssm", "ssm-contacts",
        "ssm-guiconnect", "ssm-incidents", "ssm-quicksetup", "ssm-sap", "sso", "sso-admin", "sso-oidc",
        "stepfunctions", "storagegateway", "sts", "supplychain", "support", "support-app", "swf", "synthetics",
        "taxsettings", "textract", "timestream-influxdb", "timestream-query", "timestream-write", "tnb",
        "transcribe", "transfer", "translate", "trustedadvisor", "verifiedpermissions", "voice-id", "vpc-lattice",
        "waf", "waf-regional", "wafv2", "wellarchitected", "wickr", "wisdom", "workdocs", "workmail",
        "workmailmessageflow", "workspaces", "workspaces-instances", "workspaces-thin-client", "workspaces-web",
        "xray",
    }
)
# Parameters given as a document are not checked by the flag rules (for example WithDecryption inside the JSON).
CLI_INPUT_OPTIONS = ("--cli-input-json", "--cli-input-yaml")
CLI_INPUT_SHORTEST = "--cli-i"
# No aws argument may name a local file: it could be read (file://) or written (an outfile).
# The CloudWatch agent names log groups after file paths (/var/log/messages), so these option values may look like
# paths. The list options take every value up to the next option. Never a home, relative, or file:// value.
LOG_NAME_OPTIONS = frozenset({"--log-group-name", "--log-group-name-prefix", "--log-group-name-pattern",
                              "--log-group-identifier", "--log-stream-name", "--log-stream-name-prefix"})
LOG_NAME_LIST_OPTIONS = frozenset({"--log-group-names", "--log-group-identifiers", "--log-stream-names"})
NEVER_EXEMPT_PREFIXES = ("~", "./", "../", "file://", "fileb://")
LOCAL_PATH_PREFIXES = ("/users/", "/home/", "/tmp", "/private/", "/var/", "/etc/", "/opt/", "/volumes/", "./", "../",
                       "~", "file://", "fileb://")
# Auto-prompt lets the person at a terminal edit the command before it runs. "--cli-a" is its shortest unique prefix.
AUTO_PROMPT_OPTION = "--cli-auto-prompt"
AUTO_PROMPT_SHORTEST = "--cli-a"
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


def _always_local(value: str) -> bool:
    """A value that can only be a local file: under home, relative, ~, or file://."""
    lowered = value.casefold()
    home = os.environ.get("HOME", "").rstrip("/").casefold()
    if home and (lowered == home or lowered.startswith(home + "/")):
        return True
    return lowered.startswith(NEVER_EXEMPT_PREFIXES)


def local_path_argument(args: Sequence[str]) -> tuple[str, str] | None:
    """The argument that names a local path, with deny or ask (any deny wins over the first ask).

    Deny: a positional, or a value that can only be local (home, ~, ./, ../, file://).
    Ask: another path-like option value, which may be an AWS name such as an SSM parameter.
    Allowed: path-like values of the log group and stream options.
    """
    option_value_next = log_value_next = log_list = False
    first_ask: tuple[str, str] | None = None
    for word in args:
        if word.startswith("-"):
            name, has_value, value = word.partition("=")
            log_list = name in LOG_NAME_LIST_OPTIONS and not has_value
            log_value_next = name in LOG_NAME_OPTIONS and not has_value
            option_value_next = not has_value
            if has_value and _is_local_path(value):
                if _always_local(value):
                    return word, DENY
                if name not in LOG_NAME_OPTIONS | LOG_NAME_LIST_OPTIONS:
                    first_ask = first_ask or (word, ASK)
            continue
        is_option_value, is_log_value = option_value_next or log_list, log_value_next or log_list
        option_value_next = log_value_next = False
        for value in [word] + ([word.split("=", 1)[1]] if "=" in word else []):
            if not _is_local_path(value):
                continue
            if _always_local(value):
                return word, DENY
            if is_log_value and value == word:
                continue
            if not is_option_value:
                return word, DENY
            first_ask = first_ask or (word, ASK)
    return first_ask


def _is_cli_input(word: str) -> bool:
    name = word.split("=", 1)[0]
    return len(name) >= len(CLI_INPUT_SHORTEST) and any(option.startswith(name) for option in CLI_INPUT_OPTIONS)


def _is_auto_prompt(word: str) -> bool:
    name = word.split("=", 1)[0]
    return len(name) >= len(AUTO_PROMPT_SHORTEST) and AUTO_PROMPT_OPTION.startswith(name)


def check_aws(argv: tuple[str, ...], env: tuple[str, ...], profiles: frozenset[str]) -> Verdict:
    if any(assignment.startswith("AWS_") for assignment in env):
        return Verdict(ASK, "AWS_* environment variables are set on the command line")
    if any(_is_auto_prompt(word) for word in argv[1:]):
        return Verdict(DENY, "--cli-auto-prompt lets the command be edited after the guard checked it")
    if any(_is_cli_input(word) for word in argv[1:]):
        return Verdict(DENY, "--cli-input-json and --cli-input-yaml hide parameters the guard cannot check")
    abbreviated = _abbreviated_option(argv)
    if abbreviated:
        return Verdict(ASK, f"option {abbreviated} could be an abbreviation the guard cannot check")
    if "--debug" in argv:
        return Verdict(DENY, "--debug prints request signing details")
    local_path = local_path_argument(argv[1:])
    if local_path and local_path[1] == DENY:
        return Verdict(DENY, f"aws arguments may not name a local path ({local_path[0]})")
    verdict = _check_options_and_operation(argv, profiles)
    if local_path:
        ask = Verdict(ASK, f"{local_path[0]} looks like a local path; approve it only if it is an AWS name "
                           "(an SSM parameter name, an IAM path, an S3 prefix)")
        return strictest([verdict, ask])
    return verdict


def _check_options_and_operation(argv: tuple[str, ...], profiles: frozenset[str]) -> Verdict:
    for option, effect in ASK_OPTIONS.items():
        if any(word == option or word.startswith(option + "=") for word in argv):
            return Verdict(ASK, f"{option} {effect}")

    service, operation = _service_and_operation(argv)
    if service is None:
        return Verdict(ALLOW, "version check") if "--version" in argv else Verdict(ASK, "no AWS service given")
    if service not in AWS_SERVICE_NAMES:
        return Verdict(DENY, f"aws {service} is not a service of the AWS CLI; a CLI alias could run anything")
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
    if (service, operation) in DENY_READS:
        return Verdict(DENY, f"aws {service} {operation} {DENY_READS[(service, operation)]}")
    if (service, operation) in DENY_EXACT or any(part in operation for part in DENY_NAME_PARTS):
        return Verdict(DENY, f"aws {service} {operation} returns secrets, credentials, or stored data")
    if (service, operation) == ("ec2", "describe-instance-attribute") and any(
            "userdata" in word.casefold() for word in args):
        return Verdict(DENY, "EC2 user data often holds secrets")
    if f"{service} {operation}" in STREAMING_OUTPUT_OPERATIONS:
        return Verdict(DENY, f"aws {service} {operation} writes its response to a local output file")
    for word in args:
        flag = word.split("=", 1)[0]
        if flag in REVEALING_FLAGS:
            return Verdict(DENY, f"{flag} reads encrypted or secret values")
    if service == "s3" and operation != "ls":
        return Verdict(DENY, f"aws s3 {operation} is not a read-only listing")
    if (service, operation) in ASK_READS:
        return Verdict(ASK, f"aws {service} {operation}: {ASK_READS[(service, operation)]}")
    if (service, operation) in READ_EXACT or operation.startswith(READ_PREFIXES):
        return Verdict(ALLOW, f"aws {service} {operation} is a read")
    return Verdict(DENY, f"aws {service} {operation} is not a known read operation")
