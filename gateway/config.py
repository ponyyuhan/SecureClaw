import os
from dataclasses import dataclass
from typing import List

@dataclass
class Settings:
    gateway_port: int = int(os.getenv("PORT", "8000"))
    policy_servers: List[str] = None
    fss_domain_size: int = int(os.getenv("FSS_DOMAIN_SIZE", "4096"))
    max_tokens_per_message: int = int(os.getenv("MAX_TOKENS_PER_MESSAGE", "32"))

    def __post_init__(self):
        if self.fss_domain_size <= 0 or (self.fss_domain_size & (self.fss_domain_size - 1)) != 0:
            raise ValueError("FSS_DOMAIN_SIZE must be a power of two (e.g. 4096, 65536).")
        if self.policy_servers is None:
            # two non-colluding policy servers
            self.policy_servers = [
                os.getenv("POLICY0_URL", "http://localhost:9001"),
                os.getenv("POLICY1_URL", "http://localhost:9002"),
            ]

settings = Settings()
