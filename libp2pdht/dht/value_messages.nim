import
  ../discv5/[node]

type
  AddValueMessage* = object
    cId*: NodeId
    value*: seq[byte]

  GetValueMessage* = object
    cId*: NodeId

  ValueMessage* = object
    #total*: uint32
    value*: seq[byte]

  FindValueMessage* = object
    cId*: NodeId
