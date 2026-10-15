import os

REQUIRE_AGENT_AUTH: bool = os.getenv("REQUIRE_AGENT_AUTH", "false").lower() in (
    "1",
    "true",
    "yes",
)
