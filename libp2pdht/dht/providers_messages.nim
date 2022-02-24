import
  ../discv5/[node],
  libp2p/routing_record

type
  AddProviderMessage* = object
    cId*: NodeId
    prov*: PeerRecord

  GetProvidersMessage* = object
    cId*: NodeId

  ProvidersMessage* = object
    total*: uint32
    provs*: seq[PeerRecord]
