from pydantic import BaseSettings


class BaseAPISettings(BaseSettings):
    class Config:
        env_prefix = ""
        arbitrary_types_allowed = True
        validate_assignment = True
