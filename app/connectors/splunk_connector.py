def fetch_splunk_logs():
    # Simulated Splunk data (mock for now)
    return [
        {
            "event": "Failed login",
            "ip": "10.0.0.5",
            "source": "splunk",
            "timestamp": "2026-04-23T10:00:00Z"
        },
        {
            "event": "Failed login",
            "ip": "10.0.0.5",
            "source": "splunk",
            "timestamp": "2026-04-23T10:01:00Z"
        },
        {
            "event": "Suspicious access to /admin",
            "ip": "10.0.0.8",
            "source": "splunk",
            "timestamp": "2026-04-23T10:03:00Z"
        },
        {
            "event": "Successful login",
            "ip": "10.0.0.9",
            "source": "splunk",
            "timestamp": "2026-04-23T10:04:00Z"
        }
    ]
