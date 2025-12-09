"""
RAXE API Server
Main FastAPI application providing API endpoints for RAXE threat detection.
"""

import os
import json
import subprocess
from typing import Optional
from contextlib import asynccontextmanager
from datetime import datetime
from threading import Lock

from fastapi import FastAPI, HTTPException, Request, Header, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from raxe import Raxe

# Load environment variables
load_dotenv()

# Configuration
API_KEY = os.getenv("API_KEY", "")
# Rate limiting: Default 100 req/min aligned with RAXE Free tier (100 req/min, 1K events/day)
RATE_LIMIT_REQUESTS = os.getenv("RATE_LIMIT_REQUESTS", "100")
RATE_LIMIT_PERIOD = os.getenv("RATE_LIMIT_PERIOD", "60")
# Threat detection: Minimum severity threshold (low, medium, high, critical)
MIN_THREAT_SEVERITY = os.getenv("MIN_THREAT_SEVERITY", "medium").lower()
APP_NAME = os.getenv("APP_NAME", "RAXE API Server")
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# Severity hierarchy for filtering
SEVERITY_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize RAXE
raxe_client: Optional[Raxe] = None

# Statistics tracking
stats_lock = Lock()
STATS_FILE = "/app/data/stats.json"  # Persistent storage location

server_stats = {
    "startup_time": None,
    "total_scans": 0,
    "threats_detected": 0,
    "safe_scans": 0,
    "last_scan_time": None,
    "last_threat_time": None
}


# Stats persistence helpers
def load_stats_from_file() -> dict:
    """Load statistics from persistent storage."""
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                data = json.load(f)

            # Convert ISO timestamps back to datetime objects
            if data.get("startup_time"):
                data["startup_time"] = datetime.fromisoformat(data["startup_time"])
            if data.get("last_scan_time"):
                data["last_scan_time"] = datetime.fromisoformat(data["last_scan_time"])
            if data.get("last_threat_time"):
                data["last_threat_time"] = datetime.fromisoformat(data["last_threat_time"])

            print(f"✅ Loaded statistics from {STATS_FILE}")
            print(f"   Previous session: {data['total_scans']} scans, {data['threats_detected']} threats")
            return data
    except Exception as e:
        print(f"⚠️  Could not load stats from file: {e}")

    return None


def save_stats_to_file(stats: dict) -> None:
    """Save statistics to persistent storage."""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)

        # Convert datetime objects to ISO format strings for JSON serialization
        stats_copy = stats.copy()
        if stats_copy.get("startup_time"):
            stats_copy["startup_time"] = stats_copy["startup_time"].isoformat()
        if stats_copy.get("last_scan_time"):
            stats_copy["last_scan_time"] = stats_copy["last_scan_time"].isoformat()
        if stats_copy.get("last_threat_time"):
            stats_copy["last_threat_time"] = stats_copy["last_threat_time"].isoformat()

        # Write to file atomically (write to temp file, then rename)
        temp_file = f"{STATS_FILE}.tmp"
        with open(temp_file, 'w') as f:
            json.dump(stats_copy, f, indent=2)

        os.replace(temp_file, STATS_FILE)

    except Exception as e:
        print(f"⚠️  Could not save stats to file: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    """
    # Startup
    global raxe_client

    print("🚀 Starting RAXE API Server...")
    print(f"📋 Initializing RAXE client...")

    # Load persistent statistics
    print("💾 Loading persistent statistics...")
    loaded_stats = load_stats_from_file()

    if loaded_stats:
        # Restore previous statistics
        with stats_lock:
            server_stats["total_scans"] = loaded_stats.get("total_scans", 0)
            server_stats["threats_detected"] = loaded_stats.get("threats_detected", 0)
            server_stats["safe_scans"] = loaded_stats.get("safe_scans", 0)
            server_stats["last_scan_time"] = loaded_stats.get("last_scan_time")
            server_stats["last_threat_time"] = loaded_stats.get("last_threat_time")
            # Note: startup_time is always current deployment time
            server_stats["startup_time"] = datetime.now()
        print(f"✅ Restored statistics: {server_stats['total_scans']} total scans")
    else:
        # Fresh start
        server_stats["startup_time"] = datetime.now()
        print("📊 Starting with fresh statistics")

    # Check for RAXE API key
    raxe_api_key = os.getenv("RAXE_API_KEY")
    if not raxe_api_key:
        print("⚠️  Warning: RAXE_API_KEY environment variable not set")
    else:
        print("✅ RAXE_API_KEY is configured")

    # Initialize RAXE client
    try:
        raxe_client = Raxe()
        print("✅ RAXE client initialized successfully")
        print(f"   Ready to scan prompts for threats")
    except Exception as e:
        print(f"❌ Failed to initialize RAXE client: {e}")
        print(f"   Make sure RAXE_API_KEY is set correctly")
        raise

    print(f"🎉 {APP_NAME} v{APP_VERSION} is ready!")
    print(f"📊 Statistics tracking enabled (persistent)")

    yield

    # Shutdown - save statistics
    print("💾 Saving statistics before shutdown...")
    with stats_lock:
        save_stats_to_file(server_stats)
    print("👋 Shutting down RAXE API Server...")


# Initialize FastAPI app
app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="API server for RAXE AI threat detection and safety research",
    lifespan=lifespan,
    debug=DEBUG
)

# Add rate limiter to app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Pydantic models
class ScanRequest(BaseModel):
    """Request model for prompt scanning."""
    prompt: str = Field(..., description="The user prompt to scan for threats", min_length=1)


class ThreatInfo(BaseModel):
    """Information about a detected threat."""
    severity: Optional[str] = None
    family: Optional[str] = None
    rule_id: Optional[str] = None
    confidence: Optional[float] = None
    description: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for prompt scanning."""
    has_threats: bool = Field(..., description="Whether threats were detected above minimum severity threshold")
    threat_info: Optional[ThreatInfo] = Field(None, description="Details about detected threats")
    message: str = Field(..., description="Human-readable message")
    scanned_prompt: str = Field(..., description="The prompt that was scanned")
    filtered_threat: Optional[ThreatInfo] = Field(None, description="Low-severity threat that was filtered out (if any)")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    app_name: str
    version: str
    raxe_initialized: bool


class ServerStatusData(BaseModel):
    """Server status data model."""
    status: str = Field(..., description="Server running status")
    raxe_client_initialized: bool = Field(..., description="RAXE client initialization status")
    app_version: str = Field(..., description="Application version")
    uptime: str = Field(..., description="Server uptime")
    started_at: str = Field(..., description="Server start timestamp")


class ScanStatisticsData(BaseModel):
    """Scan statistics data model."""
    total_scans: int = Field(..., description="Total number of scans")
    safe_scans: int = Field(..., description="Number of safe scans")
    threats_detected: int = Field(..., description="Number of threats detected")
    threat_detection_rate: float = Field(..., description="Threat detection rate percentage")
    last_scan: Optional[str] = Field(None, description="Last scan timestamp")
    last_threat: Optional[str] = Field(None, description="Last threat timestamp")


class RateLimitData(BaseModel):
    """Rate limiting data model."""
    requests_per_period: int = Field(..., description="Requests allowed per period")
    period_seconds: int = Field(..., description="Time period in seconds")


class TierLimitsData(BaseModel):
    """RAXE tier limits data model."""
    max_requests_per_minute: int = Field(..., description="Max requests per minute")
    max_events_per_day: int = Field(..., description="Max events per day")
    analytics: str = Field(..., description="Analytics tier level")


class ThreatCapabilitiesData(BaseModel):
    """Threat detection capabilities data model."""
    detection_rules: str = Field(..., description="Number of detection rules")
    threat_families: int = Field(..., description="Number of threat families")
    p95_latency: str = Field(..., description="P95 latency")
    families: list[str] = Field(..., description="List of threat family names")


class StructuredStatsData(BaseModel):
    """Structured statistics data model."""
    server_status: ServerStatusData
    scan_statistics: ScanStatisticsData
    rate_limiting: RateLimitData
    tier_limits: TierLimitsData
    threat_capabilities: ThreatCapabilitiesData


class StatsResponse(BaseModel):
    """Response model for RAXE stats."""
    stats: str = Field(..., description="Raw formatted statistics text")
    structured_data: Optional[StructuredStatsData] = Field(None, description="Parsed structured data (may be null if parsing fails)")
    message: str = Field(..., description="Response message")
    parsing_error: Optional[str] = Field(None, description="Error message if parsing failed")


# Stats parsing helper
def parse_stats_to_structured_data(
    stats_text: str,
    server_stats_dict: dict,
    app_version: str,
    rate_limit_requests: str,
    rate_limit_period: str
) -> Optional[StructuredStatsData]:
    """
    Parse raw statistics text into structured data.
    Returns None if parsing fails (graceful degradation).
    """
    try:
        # Extract uptime
        uptime_str = "N/A"
        if server_stats_dict["startup_time"]:
            uptime_delta = datetime.now() - server_stats_dict["startup_time"]
            days = uptime_delta.days
            hours, remainder = divmod(uptime_delta.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            if days > 0:
                uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
            elif hours > 0:
                uptime_str = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                uptime_str = f"{minutes}m {seconds}s"
            else:
                uptime_str = f"{seconds}s"

        # Format timestamps
        started_at = server_stats_dict["startup_time"].strftime("%Y-%m-%d %H:%M:%S") if server_stats_dict["startup_time"] else "N/A"
        last_scan = server_stats_dict["last_scan_time"].strftime("%Y-%m-%d %H:%M:%S") if server_stats_dict["last_scan_time"] else None
        last_threat = server_stats_dict["last_threat_time"].strftime("%Y-%m-%d %H:%M:%S") if server_stats_dict["last_threat_time"] else None

        # Calculate threat rate
        threat_rate = 0.0
        if server_stats_dict["total_scans"] > 0:
            threat_rate = round((server_stats_dict["threats_detected"] / server_stats_dict["total_scans"]) * 100, 1)

        # Build structured data
        structured_data = StructuredStatsData(
            server_status=ServerStatusData(
                status="running",
                raxe_client_initialized=True,
                app_version=app_version,
                uptime=uptime_str,
                started_at=started_at
            ),
            scan_statistics=ScanStatisticsData(
                total_scans=server_stats_dict["total_scans"],
                safe_scans=server_stats_dict["safe_scans"],
                threats_detected=server_stats_dict["threats_detected"],
                threat_detection_rate=threat_rate,
                last_scan=last_scan,
                last_threat=last_threat
            ),
            rate_limiting=RateLimitData(
                requests_per_period=int(rate_limit_requests),
                period_seconds=int(rate_limit_period)
            ),
            tier_limits=TierLimitsData(
                max_requests_per_minute=100,
                max_events_per_day=1000,
                analytics="Basic"
            ),
            threat_capabilities=ThreatCapabilitiesData(
                detection_rules="460+",
                threat_families=7,
                p95_latency="<10ms",
                families=[
                    "Prompt Injection",
                    "Jailbreaks",
                    "PII",
                    "Encoding Tricks",
                    "Command Injection",
                    "Toxic Content",
                    "RAG Attacks"
                ]
            )
        )

        return structured_data

    except Exception as e:
        # Parsing failed - return None for graceful degradation
        print(f"⚠️  Warning: Failed to parse stats to structured data: {e}")
        return None


# Authentication middleware
async def verify_api_key(authorization: str = Header(None)):
    """
    Verify API key from Authorization header.
    Expected format: Bearer <api_key>
    """
    if not API_KEY:
        # If no API key is configured, skip authentication
        return

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError("Invalid authentication scheme")
        if token != API_KEY:
            raise ValueError("Invalid API key")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected: Bearer <api_key>",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Routes
@app.get("/", response_model=HealthResponse)
async def root():
    """
    Root endpoint - health check.
    """
    return HealthResponse(
        status="healthy",
        app_name=APP_NAME,
        version=APP_VERSION,
        raxe_initialized=raxe_client is not None
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    """
    return HealthResponse(
        status="healthy",
        app_name=APP_NAME,
        version=APP_VERSION,
        raxe_initialized=raxe_client is not None
    )


@app.post("/scan", response_model=ScanResponse, dependencies=[])
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_PERIOD}seconds")
async def scan_prompt(
    request: Request,
    scan_request: ScanRequest,
    authorization: str = Header(None)
):
    """
    Scan a user prompt for AI threats using RAXE.

    Requires API key authentication via Authorization header:
    - Authorization: Bearer <your_api_key>

    Rate limited to configured requests per period.
    """
    # Verify API key
    await verify_api_key(authorization)

    if not raxe_client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RAXE client not initialized"
        )

    try:
        # Scan the prompt with RAXE
        result = raxe_client.scan(scan_request.prompt)

        # Extract threat information
        detected_severity = getattr(result, 'severity', 'unknown')
        if detected_severity:
            detected_severity = str(detected_severity).lower()

        # Check if threat meets minimum severity threshold
        threat_above_threshold = False
        if result.has_threats and detected_severity in SEVERITY_LEVELS:
            min_level = SEVERITY_LEVELS.get(MIN_THREAT_SEVERITY, 2)  # Default to medium
            detected_level = SEVERITY_LEVELS.get(detected_severity, 0)
            threat_above_threshold = detected_level >= min_level

        # Build threat info object
        threat_info_obj = None
        if result.has_threats:
            threat_info_obj = ThreatInfo(
                severity=getattr(result, 'severity', None),
                family=getattr(result, 'family', None),
                rule_id=getattr(result, 'rule_id', None),
                confidence=getattr(result, 'confidence', None),
                description=getattr(result, 'description', None)
            )

        # Update statistics (count threats above threshold)
        with stats_lock:
            server_stats["total_scans"] += 1
            server_stats["last_scan_time"] = datetime.now()

            if threat_above_threshold:
                server_stats["threats_detected"] += 1
                server_stats["last_threat_time"] = datetime.now()
            else:
                server_stats["safe_scans"] += 1

            # Save statistics to persistent storage
            save_stats_to_file(server_stats)

        # Build response based on threshold filtering
        if result.has_threats and threat_above_threshold:
            # Threat detected and above threshold
            return ScanResponse(
                has_threats=True,
                threat_info=threat_info_obj,
                message=f"Threat detected: {detected_severity}",
                scanned_prompt=scan_request.prompt,
                filtered_threat=None
            )
        elif result.has_threats and not threat_above_threshold:
            # Threat detected but below threshold (filtered out)
            return ScanResponse(
                has_threats=False,
                threat_info=None,
                message=f"No threats detected. Prompt is safe. (Low-severity alert filtered: {detected_severity})",
                scanned_prompt=scan_request.prompt,
                filtered_threat=threat_info_obj  # Include filtered threat info
            )
        else:
            # No threats detected
            return ScanResponse(
                has_threats=False,
                threat_info=None,
                message="No threats detected. Prompt is safe.",
                scanned_prompt=scan_request.prompt,
                filtered_threat=None
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error scanning prompt: {str(e)}"
        )


@app.get("/stats", response_model=StatsResponse)
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_PERIOD}seconds")
async def get_stats(
    request: Request,
    authorization: str = Header(None)
):
    """
    Get RAXE statistics.

    Requires API key authentication via Authorization header:
    - Authorization: Bearer <your_api_key>

    Rate limited to configured requests per period.
    """
    # Verify API key
    await verify_api_key(authorization)

    if not raxe_client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RAXE client not initialized"
        )

    # Calculate uptime
    uptime_str = "N/A"
    if server_stats["startup_time"]:
        uptime_delta = datetime.now() - server_stats["startup_time"]
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if days > 0:
            uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            uptime_str = f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            uptime_str = f"{minutes}m {seconds}s"
        else:
            uptime_str = f"{seconds}s"

    # Format last scan times
    last_scan = "Never"
    if server_stats["last_scan_time"]:
        last_scan = server_stats["last_scan_time"].strftime("%Y-%m-%d %H:%M:%S")

    last_threat = "Never"
    if server_stats["last_threat_time"]:
        last_threat = server_stats["last_threat_time"].strftime("%Y-%m-%d %H:%M:%S")

    # Calculate threat detection rate
    threat_rate = 0.0
    if server_stats["total_scans"] > 0:
        threat_rate = (server_stats["threats_detected"] / server_stats["total_scans"]) * 100

    # Build stats information (raw text format)
    stats_info = f"""
RAXE API Server Statistics
{'=' * 70}

SERVER STATUS
  Status: ✅ Running
  RAXE Client: ✅ Initialized
  App Version: {APP_VERSION}
  Uptime: {uptime_str}
  Started: {server_stats["startup_time"].strftime("%Y-%m-%d %H:%M:%S") if server_stats["startup_time"] else "N/A"}

SCAN STATISTICS (Since Startup)
  Total Scans: {server_stats["total_scans"]}
  Safe Scans: {server_stats["safe_scans"]}
  Threats Detected: {server_stats["threats_detected"]}
  Threat Detection Rate: {threat_rate:.1f}%
  Last Scan: {last_scan}
  Last Threat: {last_threat}

RATE LIMITING
  Current Limit: {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_PERIOD} seconds

RAXE FREE TIER LIMITS
  Max requests/minute: 100
  Max events/day: 1,000
  Analytics: Basic

  Note: For detailed usage statistics and daily limits,
  check your RAXE dashboard at https://raxe.ai

THREAT DETECTION CAPABILITIES
  Detection Rules: 460+
  Threat Families: 7
  P95 Latency: <10ms
  Families: Prompt Injection, Jailbreaks, PII, Encoding Tricks,
            Command Injection, Toxic Content, RAG Attacks
    """.strip()

    # Parse stats into structured data
    structured_data = None
    parsing_error = None

    try:
        structured_data = parse_stats_to_structured_data(
            stats_text=stats_info,
            server_stats_dict=server_stats,
            app_version=APP_VERSION,
            rate_limit_requests=RATE_LIMIT_REQUESTS,
            rate_limit_period=RATE_LIMIT_PERIOD
        )
    except Exception as e:
        parsing_error = f"Failed to parse structured data: {str(e)}"
        print(f"⚠️  Stats parsing error: {parsing_error}")

    return StatsResponse(
        stats=stats_info,
        structured_data=structured_data,
        message="Server statistics retrieved successfully",
        parsing_error=parsing_error
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Custom HTTP exception handler.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=DEBUG
    )

