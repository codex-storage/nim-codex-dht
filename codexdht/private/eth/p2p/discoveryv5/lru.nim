import std/[tables, lists, options]

{.push raises: [Defect].}

export tables, lists, options

type
  LRUCache*[K, V] = object of RootObj
    list: DoublyLinkedList[(K, V)] # Head is MRU k:v and tail is LRU k:v
    table: Table[K, DoublyLinkedNode[(K, V)]] # DoublyLinkedNode is already ref
    capacity: int

func init*[K, V](T: type LRUCache[K, V], capacity: int): LRUCache[K, V] =
  doAssert capacity > 0, "Capacity should be greater than 0!"
  LRUCache[K, V](capacity: capacity) # Table and list init is done default

func get*[K, V](lru: var LRUCache[K, V], key: K): Option[V] =
  let node = lru.table.getOrDefault(key, nil)
  if node.isNil:
    return none(V)

  lru.list.remove(node)
  lru.list.prepend(node)
  return some(node.value[1])

func put*[K, V](lru: var LRUCache[K, V], key: K, value: V) =
  let node = lru.table.getOrDefault(key, nil)
  if not node.isNil:
    lru.list.remove(node)
  else:
    if lru.len > 0 and lru.table.len >= lru.capacity:
      lru.table.del(lru.list.tail.value[0])
      lru.list.remove(lru.list.tail)

  lru.list.prepend((key, value))
  lru.table[key] = lru.list.head

func del*[K, V](lru: var LRUCache[K, V], key: K) =
  var node: DoublyLinkedNode[(K, V)]
  if lru.table.pop(key, node):
    lru.list.remove(node)

func len*[K, V](lru: LRUCache[K, V]): int =
  lru.table.len

proc contains*[K, V](lru: LRUCache[K, V], k: K): bool =
  ## Check for cached item - this doesn't touch the cache
  ##

  k in lru.table

iterator items*[K, V](lru: LRUCache[K, V]): V =
  ## Get cached items - this doesn't touch the cache
  ##

  for item in lru.list:
    yield item[1]

iterator keys*[K, V](lru: LRUCache[K, V]): K =
  ## Get cached keys - this doesn't touch the cache
  ##

  for item in lru.table.keys:
    yield item
