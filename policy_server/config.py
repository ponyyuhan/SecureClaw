import os
from dataclasses import dataclass

@dataclass
class Settings:
    server_id: int = int(os.getenv("SERVER_ID", "0"))
    port: int = int(os.getenv("PORT", "9001"))
    data_dir: str = os.getenv("DATA_DIR", "policy_server/data")
    mac_key_hex: str = os.getenv("POLICY_MAC_KEY", "")
    mac_ttl_s: int = int(os.getenv("POLICY_MAC_TTL_S", "30"))

settings = Settings()
