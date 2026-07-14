import uvicorn
import os

if __name__ == "__main__":
    port = int(os.environ.get("EZPEEK_API_PORT", "8787"))
    uvicorn.run(
        "ezpeek_cloud.app:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
    )
