"""Regression corpus for redaction: realistic leaking lines and realistic harmless lines.

Every secret-looking value is assembled at runtime from pieces, so nothing here matches a
secret scanner. Each leaking line is paired with the piece that must not survive text();
each harmless line must come back unchanged.
"""
import base64
import json
import random
import string

import pytest

from triage.redact import Redactor

ESC = "\x1b"
PW = "Wint3r" + "Sun2026q"                       # a realistic password, too short for the token rule
PW2 = "Blue" + "Fox77" + "rain"
PW_SPECIAL = "ab" + "&c;d" + "Ef9"               # holds query and statement delimiters
PW_SPACES = "correct horse " + "battery st4ple"
SHORT = "s3" + "cret" + "!"
PWP = "Qa" + "!z9#" + "Lk"                          # short and punctuated: no token rule can see it


def _hex(seed: int, length: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def _random(seed: int, length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    """A random value holding every character class (lower, upper, digit) its alphabet offers."""
    rng = random.Random(seed)
    checks = [check for check in (str.islower, str.isupper, str.isdigit) if any(check(c) for c in alphabet)]
    while True:
        value = "".join(rng.choice(alphabet) for _ in range(length))
        if all(any(check(c) for c in value) for check in checks):
            return value


KEY40 = _random(11, 40)
KEY32 = _random(12, 32)
B64KEY = _random(13, 42, string.ascii_letters + string.digits + "+/") + "=="
HEX40 = _hex(14, 40)
AWS_ID = "AK" + "IA" + _random(15, 16, string.ascii_uppercase + string.digits)
AWS_SECRET = _random(16, 40, string.ascii_letters + string.digits + "/+")
STS = "IQoJb3JpZ2lu" + "X2VjE" + _random(17, 80, string.ascii_letters + string.digits + "/+")
GITHUB = "gh" + "p_" + _random(18, 36)
GITHUB_USER = "gh" + "u_" + _random(19, 36)
GITLAB = "gl" + "pat-" + _random(20, 20)
SLACK_BOT = "xo" + "xb-" + "1234567890-" + _random(21, 24)
SLACK_APP = "xa" + "pp-1-" + "A01B2C3D4E5-" + "1234567890123-" + _hex(22, 32)
STRIPE = "sk" + "_live_" + _random(23, 24)
STRIPE_RK = "rk" + "_test_" + _random(24, 24)
GOOGLE_KEY = "AI" + "za" + _random(25, 35, string.ascii_letters + string.digits + "-_")
GOOGLE_OAUTH = "ya" + "29." + _random(26, 60, string.ascii_letters + string.digits + "-_")
GOOGLE_CLIENT = "GOC" + "SPX-" + _random(27, 28)
NPM = "np" + "m_" + _random(28, 36)
SENDGRID = "SG" + "." + _random(29, 22) + "." + _random(30, 43)
VAULT = "hv" + "s." + _random(31, 24)
OPENAI = "sk" + "-proj-" + _random(32, 40)
WHSEC = "wh" + "sec_" + _random(33, 32)
JWT_HEADER = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
JWT_BODY = base64.urlsafe_b64encode(json.dumps({"sub": "u-1", "email": "bob@example.com"}).encode()).decode().rstrip("=")
JWT = JWT_HEADER + "." + JWT_BODY + "." + _random(34, 43, string.ascii_letters + string.digits + "-_")
JWT_UNSIGNED = JWT_HEADER + "." + JWT_BODY + "."
BASIC = base64.b64encode(("admin:" + PW).encode()).decode()
SLACK_HOOK = "https://hooks.slack.com/services/" + "T0" + "1ABCDEF/B0" + "2GHIJKL/" + _random(35, 24)
SLACK_WORKFLOW = "https://hooks.slack.com/workflows/" + "T0" + "1ABCDEF/A0" + "2GHIJKL/" + "123456789/" + _random(36, 24)
PEM_KIND = "PRIVATE " + "KEY"
PEM_BODY = _random(37, 64, string.ascii_letters + string.digits + "+/")
PEM_BODY_2 = _random(38, 64, string.ascii_letters + string.digits + "+/")
PEM_LAST = _random(39, 22, string.ascii_letters + string.digits + "+/") + "=="
EMAIL = "jane.doe" + "@" + "corp.example.com"
EMAIL_ENCODED = "jane.doe" + "%40" + "corp.example.com"
PHONE = "+1 (555) " + "010-4477"
SHADOW_HASH = "$" + "6$" + "rounds=5000$" + "Xy7salt" + "$" + _random(40, 86, string.ascii_letters + string.digits + "./")
BCRYPT = "$" + "2b$" + "12$" + _random(41, 53, string.ascii_letters + string.digits + "./")
CARD = "4111" + " 1111 " + "1111 1111"
SSN = "078" + "-05-" + "1120"
SAML = base64.b64encode(("<samlp:Response ID='_" + KEY32 + "'>" + "x" * 60 + "</samlp:Response>").encode()).decode()


def ansi(code: str, text: str) -> str:
    return f"{ESC}[{code}m{text}{ESC}[0m"


def json_line(**fields) -> str:
    return json.dumps({"ts": "2026-10-04T10:00:00Z", "level": "info", **fields})


TASK_DEF = {
    "family": "checkout-api",
    "containerDefinitions": [{
        "name": "api",
        "image": "111111111111.dkr.ecr.eu-west-1.amazonaws.com/checkout-api:1.4.2",
        "environment": [{"name": "LOG_LEVEL", "value": "info"}, {"name": "DB_PASSWORD", "value": PW}],
        "healthCheck": {"command": ["CMD", "mysqladmin", "ping", "-uroot", "-p" + PW2]},
    }],
}

# (id, leaking text, piece that must not survive)
LEAKS = [
    # --- application logs, several formats
    ("java-kv", f"2026-10-04 10:00:00,123 INFO [main] c.e.DbConfig - connecting with password={PW}", PW),
    ("logfmt", f'ts=2026-10-04T10:00:00Z level=info msg="db connect" db_password={PW} host=db.example.com', PW),
    ("json-log-field", json_line(msg="config loaded", DB_PASSWORD=PW), PW),
    ("json-log-nested-string", json_line(msg=json.dumps({"api_key": PW})), PW),
    ("json-log-token", json_line(msg="auth ok", access_token=KEY40), KEY40),
    ("structlog-ansi", f"{ansi('2', '2026-10-04 10:00:00')} [{ansi('32', 'info')}] {ansi('36', 'password')}={ansi('35', PW)}", PW),
    ("loguru-ansi", f"{ansi('1;33', 'DB_PASSWORD:')} {PW}", PW),
    ("ansi-authorization", f"{ESC}[33mAuthorization: {ESC}[0mBearer {SHORT}", SHORT),
    ("python-repr-env", "[INFO] event: " + repr({"name": "DB_PASSWORD", "value": PW}), PW),
    ("python-repr-taskdef", "[INFO] registering " + repr(TASK_DEF), PW),
    ("python-repr-datetime", "{'name': 'db_password', 'created': datetime.datetime(2026, 10, 4, 10, 0), 'value': '" + PW + "'}", PW),
    ("python-logging-dict", f"2026-10-04 10:00:00 DEBUG settings: {{'DATABASE': {{'PASSWORD': '{PW}', 'HOST': 'db'}}}}", PW),
    ("go-struct", f"config: {{Host:db.example.com Password:{PW} Port:5432}}", PW),
    ("go-assignment", f'main.go:42: password := "{PW}"', PW),
    ("node-inspect", f"{{ db: {{ creds: {{ password: '{PW}' }} }} }}", PW),
    ("ruby-hash-rocket", f'params: {{:password => "{PW}", :user => "bob"}}', PW),
    ("ruby-new-hash", f'params: {{password: "{PW}", user: "bob"}}', PW),
    ("php-print-r", f"Array\n(\n    [user] => bob\n    [password] => {PW}\n)", PW),
    ("php-var-dump", f'array(2) {{\n  ["user"]=>\n  string(3) "bob"\n  ["password"]=>\n  string(14) "{PW}"\n}}', PW),
    ("tab-separated", f"password\t{PW}", PW),
    ("sentence-is", f"temporary password is {PW} for user bob", PW),
    ("sentence-setting", f"setting password to '{PW}' for user bob", PW),
    ("toml-multiline", f"password = '''\n{PW}\n'''", PW),
    ("toml-basic", f'db_password = "{PW}"', PW),
    ("ini", f"[database]\npassword = {PW}\nhost = db.example.com", PW),
    ("properties", f"spring.datasource.password={PW}", PW),
    ("dotenv-export", f"export STRIPE_SECRET_KEY={STRIPE}", STRIPE),
    ("dotenv-spaces", f"DB_PASSWORD={PW_SPACES}", "battery"),
    ("special-chars", f"password={PW_SPECIAL} user=bob", "c;d"),
    ("special-chars-amp", f"GET /login?password={PW_SPECIAL}", "Ef9"),
    ("digit-suffix-name", f"DB_PASS1={PW}", PW),
    ("camel-digit-name", f'{{"DbPassword2": "{PW}"}}', PW),
    ("mixed-case-name", f"PaSsWoRd={PW}", PW),
    ("apikey-spelling", f"APIkey: {PW}", PW),
    ("dbpwd", f"DBPWD={PW}", PW),
    ("refresh-tok", f"refresh_tok={PW}", PW),
    ("sessionid", f"sessionid={PW}", PW),
    ("pin-name", f"user_pin: {SHORT}", SHORT),
    ("dsn-name", f"SENTRY_DSN={PW}", PW),
    ("cert-key-name", f"tls_key: {PW}", PW),
    ("full-width-name", "ｐａｓｓｗｏｒｄ=" + PW, PW),
    ("zero-width-name", f"pass​word={PW}", PW),
    ("soft-hyphen-name", f"pass­word={PW}", PW),
    ("escaped-unicode-key", '{"pass\\u0077ord": "' + PW + '"', PW),
    ("unicode-escaped-json-fragment", '{"msg":"x","d":{"api\\u005fkey":"' + PW + '"', PW),
    # --- exceptions and stack traces
    ("python-traceback", f'  File "app.py", line 12, in connect\n    conn = psycopg2.connect(password="{PW}")\npsycopg2.OperationalError: x', PW),
    ("java-exception", f"java.sql.SQLException: Access denied; url=jdbc:mysql://app:{PW}@db.example.com:3306/app", PW),
    ("node-error", f"Error: connect ECONNREFUSED at redis://:{PW}@cache.example.com:6379", PW),
    ("go-panic", f"panic: dial failed: postgres://app:{PW}@db.example.com/app?sslmode=require", PW),
    ("traceback-locals", f"    self = <Client>, token = '{KEY40}'", KEY40),
    # --- HTTP access logs and header dumps
    ("access-log-query-token", f'10.0.1.5 - - [04/Oct/2026:10:00:00 +0000] "GET /api/v1/items?access_token={KEY40} HTTP/1.1" 200 512', KEY40),
    ("access-log-email-encoded", f'10.0.1.5 - - [04/Oct/2026:10:00:00 +0000] "GET /signup?email={EMAIL_ENCODED}&step=2 HTTP/1.1" 200 12', EMAIL_ENCODED),
    ("alb-log", f'https 2026-10-04T10:00:00Z app/lb/1 10.0.1.5:443 10.0.2.7:8080 0.001 0.002 0.000 200 200 34 366 "GET https://api.example.com:443/v1/reset?token={KEY32} HTTP/1.1"', KEY32),
    ("cloudfront-log", f"2026-10-04\t10:00:00\tIAD89-C1\t512\t10.0.1.5\tGET\td1.cloudfront.net\t/cb\t200\t-\tMozilla\tcode={KEY32}&state=x", KEY32),
    ("nginx-encoded-secret", "GET /cb?next=%2Fhome%3Ftoken%3D" + PW + " 200", PW),
    ("header-authorization-bearer", f"Authorization: Bearer {KEY40}", KEY40),
    ("header-authorization-basic", f"authorization: Basic {BASIC}", BASIC),
    ("bare-basic", f"retrying with Basic {BASIC}", BASIC),
    ("header-cookie", f"Cookie: sid={KEY32}; theme=dark", KEY32),
    ("header-set-cookie", f"Set-Cookie: session={KEY32}; Path=/; HttpOnly", KEY32),
    ("header-x-api-key", f"X-Api-Key: {PW}", PW),
    ("header-private-token", f"curl -H 'Private-Token: {PW}' https://gitlab.example.com/api/v4/projects", PW),
    ("header-dict-requests", f"send: b'GET / HTTP/1.1\\r\\nHost: api.example.com\\r\\nAuthorization: Bearer {KEY40}\\r\\n'", KEY40),
    ("asgi-header-pairs", "scope: {'type': 'http', 'headers': [(b'host', b'api.example.com'), (b'cookie', b'sid=" + PW + "')]}", PW),
    ("json-header-pairs", json.dumps({"headers": [["Host", "api.example.com"], ["Cookie", "sid=" + PW]]}), PW),
    ("header-dict-json", json.dumps({"headers": {"Authorization": "Basic " + BASIC, "Accept": "*/*"}}), BASIC),
    ("proxy-authorization", f"Proxy-Authorization: Basic {BASIC}", BASIC),
    ("authorization-sentence", f"Received Authorization header: Basic {BASIC}", BASIC),
    ("x-amz-signature", "GET /bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=" + HEX40 + "a1b2c3d4", HEX40),
    ("azure-sas", f"https://acct.blob.core.windows.net/c/b?sv=2022-11-02&se=2026-10-05&sig={PW}%3D", PW),
    # --- CI output and command lines
    ("ci-docker-login", f"+ docker login -u AWS -p {KEY40} 111111111111.dkr.ecr.eu-west-1.amazonaws.com", KEY40),
    ("ci-docker-password-stdin", f"+ echo {PW} | docker login --username ci --password-stdin registry.example.com", PW),
    ("ci-curl-user", f"+ curl -sS -u deploy:{PW} https://ci.example.com/api/json", PW),
    ("ci-curl-header", f'+ curl -H "Authorization: token {GITHUB}" https://api.github.com/repos/o/r', GITHUB),
    ("ci-mysql", f"+ mysql -h db.example.com -u root -p{PW} -e 'select 1'", PW),
    ("ci-mariadb", f"+ mariadb -u root -p{PW} app", PW),
    ("ci-mysqladmin", f"mysqladmin ping -uroot -p{PW}", PW),
    ("ci-redis-a", f"redis-cli -h cache.example.com -a {PW} ping", PW),
    ("ci-redis-auth", f"redis-cli -h cache.example.com AUTH {PW}", PW),
    ("redis-monitor", f'1696413600.123456 [0 10.0.1.5:53120] "AUTH" "{PW}"', PW),
    ("ci-sshpass", f"sshpass -p {PW} ssh deploy@host.example.com", PW),
    ("ci-htpasswd", f"htpasswd -b -c /etc/nginx/.htpasswd admin {PW}", PW),
    ("ci-keytool", f"keytool -importcert -keystore ks.jks -storepass {PW} -noprompt", PW),
    ("ci-ldapsearch", f'ldapsearch -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w {PW} -b dc=example,dc=com', PW),
    ("ci-smbclient", f"smbclient //files.example.com/share -U deploy%{PW}", PW),
    ("ci-sqlplus", f"sqlplus scott/{PW}@db.example.com:1521/ORCL", PW),
    ("ci-kubectl-literal", f"kubectl create secret generic db --from-literal=password={PW}", PW),
    ("ci-helm-set", f"helm upgrade api ./chart --set db.password={PW}", PW),
    ("ci-terraform-var", f"terraform apply -var db_password={PW}", PW),
    ("ci-docker-build-arg", f"docker build --build-arg NPM_TOKEN={NPM} .", NPM),
    ("ci-docker-env", f"docker run -e DB_PASSWORD={PW} api:1.4.2", PW),
    ("ci-gradle", f"./gradlew publish -PsigningPassword={PW}", PW),
    ("ci-maven", f"mvn deploy -Drepo.password={PW}", PW),
    ("ci-git-url", f"git clone https://x-access-token:{GITHUB}@github.com/org/repo", GITHUB),
    ("ci-npmrc", f"//registry.npmjs.org/:_authToken={NPM}", NPM),
    ("ci-pip-index", f"pip install --index-url https://ci:{PW}@pypi.example.com/simple app", PW),
    ("ci-set-x-export", f"+ export AWS_SECRET_ACCESS_KEY={AWS_SECRET}", AWS_SECRET),
    ("ci-aws-configure", f"aws configure set aws_secret_access_key {AWS_SECRET}", AWS_SECRET),
    ("ci-cfn-parameters", f"aws cloudformation deploy --parameters ParameterKey=DBPassword,ParameterValue={PW} ParameterKey=Env,ParameterValue=prod", PW),
    ("ci-tags-shorthand", f"aws ec2 create-tags --resources i-0123456789abcdef0 --tags Key=api_token,Value={PW}", PW),
    ("ci-ecs-overrides", f"aws ecs run-task --overrides containerOverrides=[{{name=api,environment=[{{name=DB_PASSWORD,value={PW}}}]}}]", PW),
    ("ci-ssm-put", f"aws ssm put-parameter --name /prod/db/password --type SecureString --value {PW}", PW),
    ("ci-secret-string", f"aws secretsmanager create-secret --name db --secret-string '{{\"password\":\"{PW}\"}}'", PW),
    ("ci-master-password", f"aws rds create-db-instance --db-instance-identifier db1 --master-user-password {PW}", PW),
    ("ci-exec-form-healthcheck-json", json.dumps({"healthCheck": {"command": ["CMD", "mysqladmin", "ping", "-uroot", "-p" + PW]}}), PW),
    ("ci-github-actions-mask-miss", f"Run actions/checkout@v4 with token: {GITHUB}", GITHUB),
    # --- SQL logs
    ("pg-alter-user", f"2026-10-04 10:00:00 UTC [123]: LOG:  statement: ALTER USER app WITH PASSWORD '{PW}';", PW),
    ("pg-create-role", f"LOG:  statement: CREATE ROLE reporter WITH LOGIN ENCRYPTED PASSWORD '{PW}'", PW),
    ("mysql-create-user", f"2026-10-04T10:00:00.000000Z 12 Query\tCREATE USER 'app'@'%' IDENTIFIED BY '{PW}'", PW),
    ("mysql-identified-with", f"ALTER USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY '{PW}'", PW),
    ("mysql-set-password", f"SET PASSWORD FOR 'app'@'%' = '{PW}'", PW),
    ("sql-connection-string", f"Server=db.example.com;Database=app;User Id=app;Password={PW};", PW),
    ("jdbc-url-param", f"jdbc:postgresql://db.example.com:5432/app?user=app&password={PW}&ssl=true", PW),
    # --- task definitions and AWS API output
    ("taskdef-pretty", "[INFO] registering task definition: " + json.dumps(TASK_DEF, indent=4), PW),
    ("taskdef-healthcheck", json.dumps(TASK_DEF), PW2),
    ("ssm-parameter", json.dumps({"Parameter": {"Name": "/prod/db/password", "Type": "SecureString", "Value": PW}}), PW),
    ("secrets-manager", json.dumps({"ARN": "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-AbCdEf", "SecretString": json.dumps({"password": PW})}), PW),
    ("lambda-env", json.dumps({"Environment": {"Variables": {"SLACK_WEBHOOK": SLACK_HOOK, "STAGE": "prod"}}}), SLACK_HOOK[-24:]),
    ("codebuild-env", json.dumps({"environmentVariables": [{"name": "GITHUB_TOKEN", "value": GITHUB, "type": "PLAINTEXT"}]}), GITHUB),
    ("name-nested-object-between", '{"name":"db_password","meta":{"owner":"team"},"value":"' + PW + '"', PW),
    ("name-many-pairs-between", '{"name":"db_password",' + ",".join(f'"k{i}":"v{i}"' for i in range(12)) + ',"value":"' + PW + '"', PW),
    ("value-before-name", '{"value":"' + PW + '","name":"DB_PASSWORD"', PW),
    ("cfn-parameters-json", json.dumps({"Parameters": [{"ParameterKey": "DBPassword", "ParameterValue": PW}]}), PW),
    ("iam-access-key", json.dumps({"AccessKey": {"AccessKeyId": AWS_ID, "SecretAccessKey": AWS_SECRET}}), AWS_SECRET),
    ("sts-credentials", json.dumps({"Credentials": {"AccessKeyId": AWS_ID, "SessionToken": STS}}), STS),
    ("bare-sts-token", f"using session {STS} for the call", STS),
    ("bare-aws-access-key", f"key id {AWS_ID} was used", AWS_ID),
    ("ec2-password-data", json.dumps({"InstanceId": "i-0123456789abcdef0", "PasswordData": B64KEY}), B64KEY),
    ("ecr-auth", json.dumps({"authorizationData": [{"authorizationToken": B64KEY}]}), B64KEY),
    # --- Kubernetes manifests and output
    ("k8s-env-plain", f"env:\n- name: DB_PASSWORD\n  value: {PW}\n- name: LOG_LEVEL\n  value: info", PW),
    ("k8s-env-block", f"    - name: DB_PASSWORD\n      value: >-\n        {PW}\n    - name: A\n      value: b", PW),
    ("k8s-env-extra-key", f"- name: DB_PASSWORD\n  type: plain\n  value: {PW}", PW),
    ("k8s-env-value-first", f"- value: {PW}\n  name: DB_PASSWORD", PW),
    ("k8s-flow", f"env: [{{name: DB_PASSWORD, value: {PW}}}]", PW),
    ("k8s-configmap-block", f"data:\n  password: |\n    {PW}\n  host: db.example.com", PW),
    ("k8s-secret-stringdata", f"stringData:\n  api-token: {PW}\n", PW),
    ("k8s-command-args", f"  command:\n  - mysql\n  args:\n  - -h\n  - db\n  - -p{PW}\n", PW),
    ("k8s-command-flow", f'  command: ["mysql"]\n  args: ["-h", "db", "-p{PW}"]\n', PW),
    ("k8s-last-applied", json.dumps({"metadata": {"annotations": {"kubectl.kubernetes.io/last-applied-configuration": json.dumps({"spec": {"env": [{"name": "API_TOKEN", "value": PW}]}})}}}), PW),
    ("k8s-describe", f"    Environment:\n      DB_PASSWORD:  {PW}\n      LOG_LEVEL:    info", PW),
    ("k8s-secret-data-base64", "data:\n  password: " + base64.b64encode(PW.encode()).decode(), base64.b64encode(PW.encode()).decode()),
    ("helm-values", f"database:\n  auth:\n    rootPassword: {PW}\n    username: app", PW),
    # --- XML
    ("xml-element", f"<password>{PW}</password>", PW),
    ("xml-namespaced", f"<ns:password>{PW}</ns:password>", PW),
    ("xml-multiline", f"<password>\n  {PW}\n</password>", PW),
    ("xml-cdata", f"<password><![CDATA[{PW}]]></password>", PW),
    ("xml-add-key", f'<add key="DbPassword" value="{PW}" />', PW),
    ("xml-param", f'<param name="password" value="{PW}"/>', PW),
    ("xml-name-value", f"<Name>DbPassword</Name><Value>{PW}</Value>", PW),
    # --- tokens with vendor prefixes, webhooks and keys
    ("github-token", f"pushing with {GITHUB}", GITHUB),
    ("github-user-token", f"oauth {GITHUB_USER}", GITHUB_USER),
    ("gitlab-token", f"token {GITLAB} rejected", GITLAB),
    ("slack-bot", f"slack client {SLACK_BOT}", SLACK_BOT),
    ("slack-app", f"socket mode {SLACK_APP}", SLACK_APP),
    ("stripe-live", f"charge via {STRIPE}", STRIPE),
    ("stripe-restricted", f"refund via {STRIPE_RK}", STRIPE_RK),
    ("google-api-key", f"maps key {GOOGLE_KEY}", GOOGLE_KEY),
    ("google-oauth", f"access {GOOGLE_OAUTH}", GOOGLE_OAUTH),
    ("google-client-secret", f"client {GOOGLE_CLIENT}", GOOGLE_CLIENT),
    ("npm-token", f"npm {NPM}", NPM),
    ("sendgrid", f"mail via {SENDGRID}", SENDGRID),
    ("vault-token", f"vault {VAULT}", VAULT),
    ("openai", f"llm {OPENAI}", OPENAI),
    ("stripe-webhook-secret", f"verify with {WHSEC}", WHSEC),
    ("slack-webhook", f"posting to {SLACK_HOOK}", SLACK_HOOK[-24:]),
    ("slack-workflow", f"posting to {SLACK_WORKFLOW}", SLACK_WORKFLOW[-24:]),
    ("jwt", f"session {JWT} expired", JWT_BODY),
    ("jwt-unsigned", f"id_token={JWT_UNSIGNED} accepted", JWT_BODY),
    ("jwt-unsigned-bare", f"accepted {JWT_UNSIGNED} as identity", JWT_BODY),
    ("pem-block", f"-----BEGIN {PEM_KIND}-----\n{PEM_BODY}\n{PEM_BODY_2}\n-----END {PEM_KIND}-----", PEM_BODY),
    ("pem-body-line-alone", PEM_BODY, PEM_BODY),
    ("pem-end-without-begin", f"{PEM_LAST}\n-----END {PEM_KIND}-----", PEM_LAST),
    ("putty-private-lines", f"Private-Lines: 2\n{PEM_BODY}\n{PEM_LAST}\nPrivate-MAC: {HEX40}", PEM_BODY),
    ("unlabelled-key-material", f"retrying request with {KEY40}", KEY40),
    ("unlabelled-hex", f"signature mismatch {HEX40}", HEX40),
    ("saml-response", f"SAMLResponse={SAML}", SAML[:40]),
    ("key-on-next-line-token", f"api key follows:\n{KEY40}", KEY40),
    ("json-split-second-half", f'{KEY40}","expires_in":3600}}', KEY40),
    # --- hashes
    ("shadow-line", f"root:{SHADOW_HASH}:19000:0:99999:7:::", SHADOW_HASH[12:40]),
    ("bcrypt", f"user bob hash {BCRYPT}", BCRYPT[8:]),
    # --- personal data
    ("email-plain", f"password reset sent to {EMAIL}", EMAIL),
    ("email-quoted-local", 'from "jane doe"@corp.example.com', "jane doe"),
    ("email-unicode", "contact jörg@bücher.example", "jörg"),
    ("phone", f"sms sent to {PHONE}", "010-4477"),
    ("phone-e164", "callback +4915112345678 queued", "4915112345678"),
    ("card-number", f"card_number={CARD}", "1111 1111"),
    ("cvv", "cvv: 123", "123"),
    ("ssn", f"ssn={SSN}", SSN),
    ("iban-name", "iban: DE89" + "3704 0044 0532 0130 00", "0532"),
    # round 5: regressed, still-open and positional shapes, with a short punctuated password
    ("odbc-braces", "Driver={ODBC Driver 18};Server=db;Uid=app;Pwd={" + PWP + "};", PWP),
    ("oracle-user-slash", "sqlplus scott/" + PWP + "@db.example.com:1521/ORCL", PWP),
    ("htpasswd-b-path", "htpasswd -b /etc/nginx/htpasswd admin " + PWP, PWP),
    ("k8s-secret-data", "kind: Secret\ndata:\n  DATABASE_URL: " + PWP + "\n", PWP),
    ("netrc", "machine api.example.com login deploy password " + PWP, PWP),
    ("pgpass", "db.example.com:5432:app:app_user:" + PWP, PWP),
    ("sqlcmd-P", "sqlcmd -S db -U sa -P " + PWP, PWP),
    ("mongosh-p", "mongosh -u admin -p " + PWP, PWP),
    ("ldapsearch-w-short", "ldapsearch -x -w " + PWP + " -b dc=example", PWP),
    ("chpasswd", "echo 'deploy:" + PWP + "' | chpasswd", PWP),
    ("terraform-plan", '  ~ db_password = "a" -> "' + PWP + '"', PWP),
    ("csv-password-column", "user,password\nbob," + PWP, PWP),
    ("markdown-password-column", "| user | password |\n|---|---|\n| bob | " + PWP + " |", PWP),
    ("html-escaped-json", "&quot;password&quot;:&quot;" + PWP + "&quot;", PWP),
    ("multipart-password", 'Content-Disposition: form-data; name="password"\r\n\r\n' + PWP + "\r\n--b", PWP),
    ("add-mask", "::add-mask::" + PWP, PWP),
]

assert len(LEAKS) >= 150, len(LEAKS)

# (id, harmless text) that must come back unchanged
HARMLESS = [
    ("plain-info", "2026-10-04T10:00:00Z INFO request handled in 12 ms path=/health host=api.example.com"),
    ("uuid", "request 123e4567-e89b-12d3-a456-4266141740ab finished"),
    ("lambda-report", "REPORT RequestId: 123e4567-e89b-12d3-a456-4266141740ab Duration: 12.34 ms Billed Duration: 13 ms Memory Size: 512 MB"),
    ("arn-role", "assumed arn:aws:iam::111111111111:role/service-role/AmazonEC2ContainerServiceforEC2Role"),
    ("arn-secret", "secret arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-credentials-AbCdEf rotated"),
    ("arn-lambda", "invoked arn:aws:lambda:eu-west-1:111111111111:function:checkout-api-ProcessOrderFunction-1A2B3C4D5E6F"),
    ("digest", "pulled image sha256:" + "0123456789abcdef" * 4),
    ("ecs-task-id", "task 0123456789abcdef0123456789abcdef stopped: Essential container in task exited"),
    ("aws-ids", "i-0123456789abcdef0 in subnet-0123456789abcdef0 with sg-0123456789abcdef0 in vpc-0123456789abcdef0"),
    ("aws-more-ids", "eni-0123456789abcdef0 vol-0123456789abcdef0 ami-0123456789abcdef0 snap-0123456789abcdef0"),
    ("url-words", "GET https://checkout-api.internal.example.com/api/v1/orders/create-order-request?page=2 200"),
    ("python-path", 'File "/usr/local/lib/python3.11/site-packages/botocore/endpoint.py", line 102, in _send'),
    ("container-log-path", "/var/log/containers/checkout-api-7d9f8b6c5-x2x4z_default_api-0123456789abcdef.log"),
    ("timestamps", "2026-10-04T10:00:00.123456789Z epoch=1759572000123"),
    ("placeholders", "<SECRET-1> <TOKEN-2> <EMAIL-3> <PHONE-4> <IP-5>"),
    ("pod-name", "pod checkout-api-7d9f8b6c5-x2x4z restarted 3 times"),
    ("java-class", "at com.example.checkout.PaymentServiceImplementation.charge(PaymentServiceImplementation.java:42)"),
    ("camel-identifiers", "AmazonEC2ContainerServiceforEC2Role ProcessOrderFunctionHandler2024"),
    ("env-name", "CHECKOUT_SERVICE_DATABASE_PRIMARY_HOST=db.example.com"),
    ("log-stream", "2026/10/04/[$LATEST]0123456789abcdef0123456789abcdef"),
    ("xray", "trace 1-5759e988-bd862e3fe1be46a994272793 sampled"),
    ("cfn-physical-ids", "stack checkout-api-TargetGroup-1A2B3C4D5E6F7 and checkout-prod-WebServerSecurityGroup-ABCD1234EFGH"),
    ("pg-auth-failed", 'FATAL:  password authentication failed for user "app"'),
    ("mysql-denied", "Access denied for user 'root'@'10.0.1.5' (using password: YES)"),
    ("pg-valid-until", "ALTER USER app VALID UNTIL 'infinity'"),
    ("token-metrics", "token_bucket_remaining=42 auth_latency_ms=12 AuthTokenRequests=5 max_tokens_count=4096"),
    ("password-file-flags", "run --password-file /run/secrets/db --token-file=/var/run/secrets/token"),
    ("ssl-key-path", "ssl_key: /etc/ssl/private/server.key"),
    ("ssl-key-flag", "nginx --ssl-key /etc/nginx/certs/site.key --port 443"),
    ("literal-values", "token=true api_key=None secret=ok"),
    ("literal-colon", "password: null"),
    ("lookup-attributes", "aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false"),
    ("docker-run-user", "docker run --user app:app -p 8080:80 --name web api:1.4.2"),
    ("docker-login-no-pw", "docker login -u AWS registry.example.com"),
    ("mysql-no-pw", "mysql -h db.example.com -P 3306 -u root"),
    ("kubectl-get", "kubectl get pods -n checkout -o wide"),
    ("aws-describe", "aws ecs describe-services --cluster checkout --services api --region eu-west-1"),
    ("k8s-manifest", "spec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n      - name: api\n        image: api:1.4.2\n        resources:\n          limits:\n            memory: 512Mi"),
    ("k8s-env-ok", "env:\n- name: LOG_LEVEL\n  value: info\n- name: DB_HOST\n  value: db.example.com"),
    ("k8s-secret-ref", "- name: DB_PASSWORD\n  valueFrom:\n    secretKeyRef:\n      name: db\n      key: password"),
    ("stack-trace", "Traceback (most recent call last):\n  File \"app.py\", line 3, in <module>\n    main()\nKeyError: 'region'"),
    ("node-stack", "    at Object.<anonymous> (/srv/app/index.js:10:15)\n    at Module._compile (node:internal/modules/cjs/loader:1256:14)"),
    ("http-status", '{"statusCode": 502, "body": "Bad Gateway"}'),
    ("exit-code", "Essential container in task exited with exit_code=137 reason=OutOfMemoryError"),
    ("elb-status", "elb_status_code=502 target_status_code=- request_processing_time=0.001"),
    ("private-ip", '{"PrivateIpAddress": "10.0.1.5", "PrivateDnsName": "ip-10-0-1-5.eu-west-1.compute.internal"}'),
    ("percent-cpu", "CPU at 95% for 5 minutes, memory 80%"),
    ("percent-path", "GET /files/annual%20report.pdf 200"),
    ("timezone", "2026-10-04 10:00:00 +0000 12345 handled"),
    ("apache-log", '10.0.1.5 - - [04/Oct/2026:10:00:00 +0000] "GET /health HTTP/1.1" 200 2'),
    ("version-numbers", "upgraded from 1.2.3 to 1.4.2 build 20261004.1"),
    ("private-addresses", "10.0.4.7:8080 172.16.0.1 192.168.1.1 127.0.0.1"),
    ("git-ssh", "git clone git@github.com:example/repo.git"),
    ("npm-version", "npm install left-pad@1.3.0"),
    ("auth-hostname", "redirect to https://auth.example.com:443/oauth/callback"),
    ("gates-line", "- Gates passed: evidence, no_contradiction, rank"),
    ("tests-passed", "tests passed: 120, failed: 0"),
    ("prose-authorization", "Authorization failed for user bob after 3 attempts"),
    ("keyboard", 'layout {"name": "web", "keyboard": "us"} key=abc'),
    ("ellipsis", "summary " + "x" * 20 + "… [summary cut]"),
    ("unicode-text", "café résumé 日本語"),
    ("s3-key", "s3://logs-bucket/AWSLogs/111111111111/elasticloadbalancing/eu-west-1/2026/10/04/file.log.gz"),
    ("dynamodb-key", "Key={'pk': {'S': 'order#123'}} ConsistentRead=True"),
    ("long-word-url", "https://wiki.example.com/" + "a" * 120),
    ("number-run", "id " + "1234567890" * 5),
    ("tokens-count", "usage: tokens: 512 max_tokens = 4096"),
    ("iam-action", "User is not authorized to perform: secretsmanager:GetSecretValue on resource db"),
    ("iam-policy", '{"Effect": "Allow", "Action": ["kms:Decrypt", "secretsmanager:GetSecretValue"]}'),
    ("secret-key-ref", "valueFrom:\n  secretKeyRef: db-password"),
    ("secret-ref", "envFrom:\n- secretRef: app-secrets\n  secretName: tls-secret"),
    # round 5: the re-review's wrongly changed lines
    ("aws-error-code-json", '{"Error":{"Code":"AccessDenied","Message":"Access Denied"}}'),
    ("s3-error-text", "Code: NoSuchKey Message: The specified key does not exist. Key: logs/app.log"),
    ("s3-error-xml", "<Error><Code>SignatureDoesNotMatch</Code></Error>"),
    ("grpc-code", "rpc error: code = Unknown desc = context deadline exceeded"),
    ("node-code", "Error: connect ECONNREFUSED 10.0.1.5:6379 code=ECONNREFUSED"),
    ("code-500", "Code: 500"),
    ("lambda-code", '{"code": "ResourceNotFoundException", "message": "Function not found"}'),
    ("reset-code-paren", "password reset requested for user 42 (code=PR-1)"),
    ("unauthorized", "401 Unauthorized: invalid_token"),
    ("authorize-chain", "failed to authorize: failed to fetch anonymous token"),
    ("ecs-secrets-error", "unable to pull secrets or registry auth: execution resource retrieval failed: unable to retrieve secret"),
    ("auth-ok", "auth: OK user=bob mfa=true"),
    ("author", "author: pavel committed 3 files"),
    ("set-secret-prose", "ResourceInitializationError: setSecret: password does not meet complexity requirements"),
    ("mount-volume", 'MountVolume.SetUp failed for volume "db-creds" : secret "db-creds" not found'),
    ("cpu-credit", "CPUCreditBalance: 0.0"),
    ("private-subnets", "private_subnets: subnet-0123456789abcdef0"),
    ("license-model", "LicenseModel: license-included"),
    ("key-manager", "KeyManager: CUSTOMER"),
    # round 5 ruling 6: labelled commits and AWS request ids
    ("git-commit", "deployed commit " + _hex(60, 40) + " to prod"),
    ("image-tag-sha", "image tag " + _hex(61, 40)),
    ("amz-id-2", "x-amz-id-2: " + _random(62, 76, string.ascii_letters + string.digits + "+/")),
    ("amz-cf-id", "x-amz-cf-id: " + _random(63, 56, string.ascii_letters + string.digits + "_-")),
]

assert len(HARMLESS) >= 60, len(HARMLESS)


@pytest.mark.parametrize("name, source, secret", LEAKS, ids=[case[0] for case in LEAKS])
def test_leaking_line_loses_its_secret(name, source, secret):
    out = Redactor().text(source)
    assert secret not in out
    assert Redactor().text(out) == out  # stable on already-redacted text


@pytest.mark.parametrize("name, source", HARMLESS, ids=[case[0] for case in HARMLESS])
def test_harmless_line_is_unchanged(name, source):
    assert Redactor().text(source) == source
