# DAS emulator

Emulate DAS DHT behavior, with a few simple assumption
- the block is populated in the DHT by the builder (node 0)
- all nodes start sampling at the same time
- 1-way latency is 50ms (configurable)
- no losses in transmission (configurable)
- scaled down numbers (nodes, blocksize, etc., all configrable)

## Compilation

```
# install Nim 1.6

# install Nimble 0.14+
nimble install nimble

# make sure the newly installed nimble is used
export PATH=~/.nimble/bin:$PATH

# install dependencies
nimble install 

# compile and run passing on various flags
nimble run "-d:chronicles_sinks=textlines[stdout,nocolors]" -d:chronicles_log_level=INFO -d:release -d:asyncTimer=virtual das
```