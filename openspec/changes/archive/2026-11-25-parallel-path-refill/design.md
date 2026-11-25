# Concurrent Path refill

Establish the first Path and Session before attaching additional Paths. The
Ingress serializes refill batches with Session creation and runs the batch's
carrier handshakes concurrently for the same Session. Each accepted completion
can attach while other handshakes are still running. Size a batch from the
current deficit plus one speculative attempt, bounded by remaining physical
Path slots. Existing backoff governs failed batches. The existing hysteretic
drain handles surplus.
