from pydantic import BaseModel, IPvAnyAddress

class Flow(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    sport: int
    dport: int
    proto: str
    dur: float
    sbytes: int
    dbytes: int
    pkts: int
    state: str
    ct_flw_http_mthd: int
    ct_state_ttl: float
    ct_srv_src: int
