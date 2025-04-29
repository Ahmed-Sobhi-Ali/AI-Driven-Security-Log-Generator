import time
import random
from faker import Faker
from datetime import datetime, timedelta
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

# Load or download the model
def load_model():
    print("[+] Loading AI Model...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    print("[+] Model loaded successfully.")
    return model

# Predefined Event Descriptions
EVENTS_DB = [
    {
        "event_id": 1,
        "description": "Successful SSH login attempt",
        "log_types": ["auth"],
        "system": "linux",
        "service": "sshd",
        "message_patterns": [
            "Accepted password for {user} from {ip_address} port {port} ssh2",
            "session opened for user {user} by uid 0"
        ],
        "keywords": {"success": 2, "login": 3, "ssh": 3, "linux": 1}
    },
    {
        "event_id": 2,
        "description": "Failed SSH login attempt",
        "log_types": ["auth"],
        "system": "linux",
        "service": "sshd",
        "message_patterns": [
            "Failed password for invalid user {user} from {ip_address} port {port} ssh2",
            "Failed password for {user} from {ip_address} port {port} ssh2",
            "Connection closed by authenticating user {user} {ip_address} port {port} [preauth]"
        ],
        "keywords": {"fail": 2, "attempt": 2, "login": 3, "ssh": 3, "linux": 1}
    },
    {
        "event_id": 3,
        "description": "Apache web server access log",
        "log_types": ["access"],
        "system": "apache",
        "log_type": "access",
        "message_patterns": [
            '{ip_address} - - [{timestamp}] "{http_method} {url} HTTP/1.1" {status_code} {bytes} "{referrer}" "{user_agent}"'
        ],
        "keywords": {"apache": 2, "web": 1, "access": 3, "request": 2}
    },
    {
        "event_id": 4,
        "description": "Apache web server error log",
        "log_types": ["error"],
        "system": "apache",
        "log_type": "error",
        "message_patterns": [
            "[{timestamp}] [error] [client {ip_address}] {error_message}, referer: {referrer}",
            "[{timestamp}] [error] [client {ip_address}:80] PHP Warning: {php_warning} in {script_path} on line {line_number}",
            "[{timestamp}] [notice] child pid {pid} exit signal Segmentation fault (11)"
        ],
        "keywords": {"apache": 2, "web": 1, "error": 3, "problem": 2}
    },
    {
        "event_id": 5,
        "description": "Windows security successful login (Event ID 4624)",
        "log_types": ["security"],
        "system": "windows",
        "event_id": "4624",
        "message_patterns": [
            "An account was successfully logged on. Subject: Security ID: S-1-5-18 Account Name: SYSTEM Account Domain: NT AUTHORITY Logon ID: 0x{hex_logon_id} Logon Type: {logon_type} Account Whose Account Name: {user} Account Domain: {domain} Logon GUID: {{{guid}}} Caller Process ID: 0x{hex_pid} Caller Process Name: C:\\\\Windows\\\\System32\\\\services.exe Network Information: Workstation Name: {hostname} Source Network Address: {ip_address} Source Port: {port} Detailed Authentication Information: Logon Process: Advapi SubAuthentication Package: Negotiate Authenticated Name: - Package Name (NTLM): - Key Length: 0 Logon GUID: {{{guid}}} This event is generated when a logon session is created. It is generated on the computer that was accessed."
        ],
        "keywords": {"windows": 2, "success": 3, "login": 3, "security": 2, "4624": 2}
    },
    {
        "event_id": 6,
        "description": "Windows security failed login (Event ID 4625)",
        "log_types": ["security"],
        "system": "windows",
        "event_id": "4625",
        "message_patterns": [
            "An account failed to log on. Subject: Security ID: S-1-0-0 Account Name: - Account Domain: - Logon ID: 0x{hex_logon_id} Caller Process ID: 0x{hex_pid} Caller Process Name: C:\\\\Windows\\\\system32\\\\lsass.exe Network Information: Workstation Name: {hostname} Source Network Address: {ip_address} Source Port: {port} Detailed Authentication Information: Logon Process: NtLmSsp Authentication Package: NTLM Authentication Package GUID: {{{guid}}} Key Length: 0 Failure Information: Failure Reason: %%{failure_code} Status: 0x{hex_status} Sub Status: 0x{hex_sub_status}"
        ],
        "keywords": {"windows": 2, "fail": 3, "attempt": 2, "login": 3, "security": 2, "4625": 2}
    },
    {
        "event_id": 7,
        "description": "Firewall denied connection",
        "log_types": ["firewall"],
        "system": "firewall",
        "message_patterns": [
            "Apr 29 11:{minute}:{second} MY-FIREWALL %ASA-4-106023: Deny {protocol} src {interface}:{src_ip}/{src_port} dst {dest_interface}:{dest_ip}/{dest_port} by access-group {acl_name}",
            "Apr 29 11:{minute}:{second} MY-FIREWALL %ASA-3-202014: Teardown {protocol} connection {conn_id} for {interface}:{src_ip}/{src_port} to {dest_interface}:{dest_ip}/{dest_port} duration {duration} bytes {bytes} reason {reason}"
        ],
        "keywords": {"firewall": 3, "deny": 3, "block": 2, "connection": 2}
    },
    {
        "event_id": 8,
        "description": "DNS query log",
        "log_types": ["dns"],
        "system": "dns",
        "server_name": "bind",
        "message_patterns": [
            "Apr 29 11:{minute}:{second}.{millisecond} client {ip_address}#{port}: query: {hostname} IN {record_type} +({flags}) {server_ip}({server_port})",
            "Apr 29 11:{minute}:{second}.{millisecond} client {ip_address}#{port}: query: {hostname} AAAA +({flags}) {server_ip}({server_port})"
        ],
        "keywords": {"dns": 3, "query": 3, "request": 2, "name": 1}
    },
    {
        "event_id": 9,
        "description": "Application error log",
        "log_types": ["app"],
        "system": "app",
        "app_name": "my_web_app",
        "message_patterns": [
            "[{timestamp}] ERROR [{thread}] {module}.{function} - {error_message}",
            "[{timestamp}] CRITICAL [{thread}] {module} - Unhandled exception: {exception_type}: {exception_value}"
        ],
        "keywords": {"application": 2, "error": 3, "app": 2, "problem": 2}
    },
    {
        "event_id": 10,
        "description": "VPN client connection log",
        "log_types": ["vpn"],
        "system": "vpn",
        "vpn_gateway": "openvpn",
        "message_patterns": [
            "{timestamp} MANAGEMENT: Client connected from {ip_address}:{port}"
        ],
        "keywords": {"vpn": 3, "connect": 3, "login": 2, "client": 2}
    },
    {
        "event_id": 11,
        "description": "VPN client disconnection log",
        "log_types": ["vpn"],
        "system": "vpn",
        "vpn_gateway": "openvpn",
        "message_patterns": [
            "{timestamp} MANAGEMENT: Client disconnected, {bytes_in}/{bytes_out}"
        ],
        "keywords": {"vpn": 3, "disconnect": 3, "logout": 2, "client": 2}
    },
    {
        "event_id": 12,
        "description": "Database slow query log",
        "log_types": ["db"],
        "system": "db",
        "db_name": "mysql",
        "message_patterns": [
            "[{timestamp}] [slow_query] User@{host} Query: {query} Time: {duration}s"
        ],
        "keywords": {"database": 2, "slow": 3, "query": 3, "sql": 2}
    },
    {
        "event_id": 13,
        "description": "Proxy server access log",
        "log_types": ["proxy"],
        "system": "proxy",
        "proxy_name": "squid",
        "message_patterns": [
            "{timestamp}.{millisecond} {duration} {ip_address} TCP_MISS/{status_code} {bytes} {http_method} {url} - NONE/- {mime_type}"
        ],
        "keywords": {"proxy": 3, "access": 2, "squid": 2, "http": 1}
    }
]

fake = Faker()

def generate_realistic_data(pattern, system, log_type=None, event_id=None, app_name=None, db_name=None, server_name=None, proxy_name=None, vpn_gateway=None):
    data = {}
    now = datetime.now()
    data["timestamp"] = now.strftime("%b %d %H:%M:%S") if system == "linux" or system == "dns" else now.strftime("%Y-%m-%d %H:%M:%S") if system == "windows" or system == "app" else now.strftime("%d/%b/%Y:%H:%M:%S +0200") if system == "apache" else now.strftime("%Y-%m-%d %H:%M:%S") if system == "vpn" else now.strftime("%Y-%m-%d_%H:%M:%S") if system == "proxy" else now.strftime("%Y-%m-%d %H:%M:%S")
    data["ip_address"] = fake.ipv4()
    data["port"] = random.randint(1024, 65535)
    data["user"] = fake.user_name()
    data["http_method"] = random.choice(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
    data["url"] = fake.uri_path()
    data["status_code"] = random.choice([200, 302, 400, 401, 403, 404, 500, 503])
    data["bytes"] = random.randint(100, 50000)
    data["referrer"] = random.choice([fake.uri(), "-"] )
    data["user_agent"] = fake.user_agent()
    data["error_message"] = random.choice(["File not found", "Internal server error", "PHP Warning: Division by zero", "Database connection error", "Authentication failed"])
    data["php_warning"] = random.choice(["Division by zero", "Undefined variable", "Array index out of bounds"])
    data["script_path"] = fake.file_path(depth=3, extension="php")
    data["line_number"] = random.randint(1, 200)
    data["pid"] = random.randint(100, 5000)
    data["hex_pid"] = hex(data["pid"])[2:].upper()
    data["hostname"] = fake.hostname()
    data["logon_type"] = random.choice([2, 3, 8, 10])
    data["domain"] = fake.domain_name()
    data["guid"] = fake.uuid4()
    data["hex_logon_id"] = hex(random.randint(100, 1000))[2:].upper()
    data["failure_code"] = random.choice(["50331648", "3221225506", "3221225477"])
    data["hex_status"] = hex(random.randint(0xC0000000, 0xC00000FF))[2:].upper()
    data["hex_sub_status"] = hex(random.randint(0, 0xFF))[2:].upper()
    data["protocol"] = random.choice(["tcp", "udp"])
    data["interface"] = random.choice(["outside", "inside", "dmz", "eth0", "wlan0"])
    data["src_ip"] = fake.ipv4()
    data["src_port"] = random.randint(1, 65535)
    data["dest_ip"] = fake.ipv4()
    data["dest_port"] = random.randint(1, 65535)
    if system == "firewall":
        data["dest_interface"] = random.choice(["outside", "inside", "dmz", "eth0", "wlan0"])
    data["acl_name"] = random.choice(["inbound_acl", "outbound_acl", "web_acl", "dmz_policy"])
    data["minute"] = str(random.randint(0, 59)).zfill(2)
    data["second"] = str(random.randint(0, 59)).zfill(2)
    data["millisecond"] = str(random.randint(0, 999)).zfill(3)
    data["thread"] = random.randint(1, 20)
    data["module"] = random.choice(["auth", "database", "api", "main", "security", "network"])
    data["function"] = random.choice(["login", "query", "process_request", "init", "check_credentials", "send_packet"])
    data["app_name"] = app_name if app_name else "unknown_app"
    data["exception_type"] = random.choice(["ValueError", "TypeError", "IOError", "ZeroDivisionError"])
    data["exception_value"] = fake.sentence(nb_words=5)
    data["conn_id"] = random.randint(100000, 999999)
    data["duration"] = f"{random.randint(0, 59)}:{random.randint(0, 59)}:{random.randint(0, 59)}"
    data["reason"] = random.choice(["idle timeout", "tcp reset", "policy"])
    data["hostname"] = fake.hostname()
    data["record_type"] = random.choice(["A", "AAAA", "CNAME", "MX", "TXT"])
    data["flags"] = ''.join(random.choice('+-adqrst') for _ in range(random.randint(0, 5)))
    data["server_ip"] = fake.ipv4()
    data["server_port"] = random.choice([53, 5353])
    data["db_name"] = db_name if db_name else "mysql"
    data["query"] = random.choice(["SELECT * FROM users", "INSERT INTO logs VALUES (...)", "UPDATE products SET price = ..."])
    data["proxy_name"] = proxy_name if proxy_name else "squid"
    data["vpn_gateway"] = vpn_gateway if vpn_gateway else "openvpn"
    data["bytes_in"] = random.randint(1000, 100000)
    data["bytes_out"] = random.randint(1000, 100000)
    return pattern.format(**data)

def find_best_event(user_prompt, model, events_db, match_sensitivity="loose"):
    best_event = None
    best_score = -1
    user_embedding = model.encode([user_prompt])

    for event in events_db:
        description_embedding = model.encode([event["description"]])
        description_similarity = cosine_similarity(user_embedding, description_embedding)[0][0]

        keyword_score = 0
        user_keywords = user_prompt.lower().split()

        for keyword, weight in event.get("keywords", {}).items():
            if keyword in user_keywords:
                keyword_score += weight

        total_keyword_weight = sum(event.get("keywords", {}).values()) + 1e-9
        normalized_keyword_score = keyword_score / total_keyword_weight

        if match_sensitivity == "strict":
            # More emphasis on description similarity
            combined_score = (0.9 * description_similarity) + (0.1 * normalized_keyword_score)
        elif match_sensitivity == "loose":
            # More emphasis on keyword matching
            combined_score = (0.7 * description_similarity) + (0.3 * normalized_keyword_score)
        else:
            # Default weighting
            combined_score = (0.8 * description_similarity) + (0.2 * normalized_keyword_score)

        if combined_score > best_score:
            best_score = combined_score
            best_event = event

    return best_event, best_score

def generate_logs_for_scenario(event, num_logs=1):
    logs = []
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    for _ in range(num_logs):
        log_type = random.choice(event["log_types"])
        message_pattern = random.choice(event["message_patterns"])
        log_message = generate_realistic_data(message_pattern, event["system"], event.get("log_type"), event.get("event_id"), event.get("app_name"), event.get("db_name"), event.get("server_name"), event.get("proxy_name"), event.get("vpn_gateway"))
        if event["system"] == "linux":
            log_entry = f"{timestamp.strftime('%b %d %H:%M:%S')} my-server {event['service']}: {log_message}"
        elif event["system"] == "apache":
            log_entry = f"[{timestamp.strftime('%a %b %d %H:%M:%S.%fZ %Y')}] [error] [client {fake.ipv4()}:80] {log_message}"
        elif event["system"] == "apache" and event.get("log_type") == "access":
            log_entry = f"{fake.ipv4()} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S +0200')}] \"{random.choice(['GET', 'POST'])} {fake.uri_path()} HTTP/1.1\" {random.choice([200, 404])} {random.randint(100, 5000)} \"-\" \"{fake.user_agent()}\""
        elif event["system"] == "windows" and event.get("event_id") == "4624":
            log_entry = f"<{event['event_id']}> {timestamp.strftime('%Y-%m-%d %H:%M:%S')} Security {generate_realistic_data(message_pattern, event['system'], event_id=event['event_id'])}"
        elif event["system"] == "windows" and event.get("event_id") == "4625":
            log_entry = f"<{event['event_id']}> {timestamp.strftime('%Y-%m-%d %H:%M:%S')} Security {generate_realistic_data(message_pattern, event['system'], event_id=event['event_id'])}"
        elif event["system"] == "firewall":
            log_entry = generate_realistic_data(message_pattern, event["system"])
        elif event["system"] == "dns":
            log_entry = f"{timestamp.strftime('%b %d %H:%M:%S.%f')} my-dns-server named[{random.randint(1000, 9999)}]: {generate_realistic_data(message_pattern, event['system'])}"
        elif event["system"] == "app":
            log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S,%f')}] {event.get('app_name')} [{random.choice(['INFO', 'WARNING', 'ERROR'])}] {generate_realistic_data(message_pattern, event['system'], app_name=event.get('app_name'))}"
        elif event["system"] == "vpn":
            log_entry = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} {event.get('vpn_gateway')}: {generate_realistic_data(message_pattern, event['system'], vpn_gateway=event.get('vpn_gateway'))}"
        elif event["system"] == "db":
            log_entry = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} {event.get('db_name')} - {generate_realistic_data(message_pattern, event['system'], db_name=event.get('db_name'))}"
        elif event["system"] == "proxy":
            log_entry = f"{timestamp.strftime('%Y-%m-%d_%H:%M:%S')}{generate_realistic_data(message_pattern, event['system'], proxy_name=event.get('proxy_name'))}"
        else:
            log_entry = log_message
        logs.append(log_entry)
        time.sleep(random.uniform(0.01, 0.5))
    return logs

def save_logs_to_file(logs, filename="ai_generated_logs.log"):
    with open(filename, "w") as f:
        for log in logs:
            f.write(log + "\n")
    print(f"Logs saved to {filename}")

if __name__ == "__main__":
    model = load_model()
    user_description = input("Describe the log scenario you want to generate: ")
    match_sensitivity = input("Enter match sensitivity ('strict', 'loose', or leave empty for default): ").lower()
    best_event, similarity_score = find_best_event(user_description, model, EVENTS_DB, match_sensitivity)

    print(f"\nBest matching scenario: {best_event['description']}")
    print(f"Similarity score: {similarity_score:.4f}")

    num_logs_to_generate = int(input("Enter the number of logs to generate for this scenario: "))
    generated_logs = generate_logs_for_scenario(best_event, num_logs_to_generate)

    if generated_logs:
        save_logs_to_file(generated_logs)
    else:
        print("No logs were generated.")
