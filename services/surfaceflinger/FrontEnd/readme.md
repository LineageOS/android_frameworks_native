# SurfaceFlinger FrontEnd

SurfaceFlinger FrontEnd implements the client APIs that describe how buffers should be
composited on the screen. Layers are used to capture how the buffer should be composited
and each buffer is associated with a Layer. Transactions contain an atomic set of changes
to one or more of these layers. The FrontEnd consumes these transactions, maintains the
layer lifecycle, and provides a snapshot to the composition engine every frame that
describes how a set of buffers should be composited.



## Layers
Layers are used to describe how a buffer should be placed on the display relative to other
buffers. They are represented as a hierarchy, similar to a scene graph. Child layers can
inherit some properties from their parents, which allows higher-level system components to
maintain policies at different levels without needing to understand the entire hierarchy.
This allows control to be delegated to different parts of the system - such as SystemServer,
SysUI and Apps.

### Layer Lifecycle
Layer is created by a client. The client receives a strong binder reference to the layer
handle, which will keep the layer alive as long as the client holds the reference. The
layer can also be kept alive if the layer has a parent, since the parent will hold a
strong reference to the children. If the layer is not reachable but its handle is alive,
the layer will be offscreen and its resources will not be freed. Clients must explicitly
release all references to the handle as soon as it's done with the layer. It's strongly
recommended to explicitly release the layer in Java and not rely on the GC.



## Transactions
Transactions contain a group of changes to one or more layers that are applied together.
Transactions can be merged to apply a set of changes atomically. Merges are associative,
meaning how you group the merges does not matter, but they are not commutative, meaning
that the order in which you merge them does.
For example:

`Transaction a; a.setAlpha(sc, 2);`

`Transaction b; b.setAlpha(sc, 4);`

`a.merge(b)` is not the same as `b.merge(a)`

<p>

`Transaction c; c.setAlpha(sc, 6);`

`a.merge(b).merge(c)` is the same as `b.merge(c); a.merge(b);`

Transactions are queued in SurfaceFlinger per ApplyToken so order is only guaranteed for
Transactions with the same applyToken. By default each process and each buffer producer
provides a unique ApplyToken. This prevents clients from affecting one another, and possibly
slowing each other down.



## Architecture
SurfaceFlinger FrontEnd intends to optimize for predictability and performance because state
generation is on the hotpath. Simple buffer updates should be as fast as possible, and they
should be consistently fast. This means avoiding contention (e.g., locks) and context
switching. We also want to avoid doing anything that does not contribute to putting a pixel
on the display.

The pipeline can be broken down into five stages:
- Queue and filter transactions that are ready to be committed.
- Handle layer lifecycles and update server-side state per layer.
- Generate and/or update the traversal trees.
- Generate a z-ordered list of snapshots.
- Emit callbacks back to clients


### TransactionHandler
TransactionHandler is responsible for queuing and filtering transactions that are ready to
be applied. On commit, we filter the transactions that are ready. We provide an interface
for other components to apply their own filter to determine if a transaction is ready to be
applied.


### LayerLifecycleManager
RequestedLayerState is a simple data class that stores the server side layer state.
Transactions are merged into this state, similar to how transactions can be merged on the
client side. The states can always be reconstructed from LayerCreationArgs and a list of
transactions. LayerLifecycleManager keeps track of Layer handle lifecycle and the layer
lifecycle itself. It consumes a list of transactions and generates a list of server side
states and change flags. Other components can register to listen to layer lifecycles.


### LayerHierarchyBuilder
LayerHierarchyBuilder consumes a list of RequestedLayerStates to generate a LayerHierarchy.
The hierarchy provides functions for breadth-first traversal and z-order traversal of the
entire tree or a subtree. Internally, the hierarchy is represented by a graph. Mirrored
layers are represented by the same node in the graph with multiple parents. This allows us
to implement mirroring without cloning Layers and maintaining complex hierarchies.


### LayerSnapshotBuilder
LayerSnapshotBuilder consumes a LayerHierarchy along with a list of RequestedLayerStates to
generate a flattened z-ordered list of LayerSnapshots. LayerSnapshots contain all the data
required for CompositionEngine and RenderEngine. It has no dependencies to FrontEnd, or the
LayerHierarchy used to create them. They can be cloned and consumed freely. Other consumers
like WindowInfo listeners (input and accessibility) also updated from these snapshots.

Change flags are used to efficiently traverse this hierarchy where possible. This allows us
to support short circuiting parts of the hierarchy, partial hierarchy updates and fast paths
for buffer updates.


While they can be cloned, the current implementation moves the snapshot from FrontEnd to
CompositionEngine to avoid needless work in the hotpath. For snapshot consumers not critical
to composition, the goal is to clone the snapshots and consume them on a background thread.
