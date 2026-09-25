"""A benign skill that asks the gateway to send a safe message."""

def plan():
    return {
        "intent_id": "SendMessage",
        "inputs": {
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "Hello from benign skill.",
            "artifacts": []
        },
        "constraints": {}
    }
