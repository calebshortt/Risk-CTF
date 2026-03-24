"""Protocol-level constants used by both monitor and mothership."""

REGISTER_PATH = "/api/v1/monitors/register"
EVENTS_PATH = "/api/v1/events"
DASHBOARD_PATH = "/dashboard"

HEADER_MONITOR_ID = "X-Risk-Monitor-Id"
HEADER_TS = "X-Risk-Timestamp"
HEADER_NONCE = "X-Risk-Nonce"
HEADER_SIGNATURE = "X-Risk-Signature"

MAX_CLOCK_SKEW_SECONDS = 120
NONCE_TTL_SECONDS = 300

