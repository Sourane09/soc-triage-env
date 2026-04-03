from openenv.core.env_server.http_server import create_app
from openenv.core.env_server.mcp_types import CallToolAction, CallToolObservation
from .soc_environment import SOCTriageEnvironment

app = create_app(
    SOCTriageEnvironment,
    CallToolAction,
    CallToolObservation,
    env_name="soc_triage_env",
)

def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    main()
