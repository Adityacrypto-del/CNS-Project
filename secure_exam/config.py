"""Central configuration: file locations, network settings and security parameters."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Override with SECURE_EXAM_DATA (used by the test-suite to run in a temp dir).
DATA_DIR = Path(os.environ.get("SECURE_EXAM_DATA", ROOT / "data"))

# --- PKI / key material ---------------------------------------------------
PKI_DIR = DATA_DIR / "pki"
CA_CERT = PKI_DIR / "ca_cert.pem"
CA_KEY = PKI_DIR / "ca_key.pem"
SERVER_TLS_CERT = PKI_DIR / "server_tls_cert.pem"
SERVER_TLS_KEY = PKI_DIR / "server_tls_key.pem"
SERVER_SIGN_KEY = PKI_DIR / "server_sign_key.pem"      # RSA key for signatures + key wrapping
SERVER_SIGN_PUB = PKI_DIR / "server_sign_pub.pem"       # distributed to clients

# --- Server-side storage (all encrypted at rest) --------------------------
SERVER_DIR = DATA_DIR / "server"
STORAGE_KEY_WRAPPED = SERVER_DIR / "storage_key.bin"    # AES key, RSA-OAEP wrapped
AUDIT_KEY_WRAPPED = SERVER_DIR / "audit_key.bin"        # HMAC key for the audit log, RSA wrapped
STUDENTS_DB = SERVER_DIR / "students.enc"
ADMINS_DB = SERVER_DIR / "admins.enc"
EXAMS_DB = SERVER_DIR / "exams.enc"
ANSWER_KEYS_DB = SERVER_DIR / "answer_keys.enc"
SUBMISSIONS_DB = SERVER_DIR / "submissions.enc"
AUDIT_LOG = SERVER_DIR / "audit.log"

# --- Client-side key store --------------------------------------------------
CLIENT_DIR = DATA_DIR / "clients"

# --- Network ---------------------------------------------------------------
HOST = os.environ.get("SECURE_EXAM_HOST", "127.0.0.1")
PORT = int(os.environ.get("SECURE_EXAM_PORT", 8443))           # TLS socket protocol
API_PORT = int(os.environ.get("SECURE_EXAM_API_PORT", 8444))   # HTTPS JSON API (for web frontends)
WEB_PORT = int(os.environ.get("SECURE_EXAM_WEB_PORT", 5173))   # HTTPS web frontend (static files)
SERVER_HOSTNAME = "localhost"      # must match the TLS certificate SAN
# Origin allowed to call the HTTPS API from a browser (CORS). Empty = same-origin only.
API_ALLOWED_ORIGIN = os.environ.get("SECURE_EXAM_ALLOWED_ORIGIN", f"https://{SERVER_HOSTNAME}:{WEB_PORT}")

# --- Security parameters ---------------------------------------------------
PBKDF2_ITERATIONS = 600_000        # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
RSA_KEY_BITS = 3072
STUDENT_RSA_KEY_BITS = 2048
MAX_CLOCK_SKEW = 60                # seconds a message timestamp may differ from server time
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
SESSION_TTL = 3 * 60 * 60          # absolute lifetime of an authenticated session (seconds)
API_SESSION_IDLE = 30 * 60         # HTTPS API sessions expire after this much inactivity
API_MAX_SESSIONS = 10_000
MAX_FRAME_BYTES = 1_000_000
ENROLLMENT_CODE_TTL = 72 * 60 * 60
SUBMISSION_GRACE_SECONDS = 30      # network latency allowance after the deadline
PASSWORD_MIN_LENGTH = 10
