# Persistent conferences

This document describes the "minpgc" simple persistent conferences
implementation of PR #1069.

Many of the ideas derive from isotoxin's persistent conferences implementation,
PR #826.

## Specification of changes from pre-existing conference specification

We add one new packet type:

Rejoin Conference packet

| Length | Contents              |
| :----- | :-------------------- |
| `1`    | `uint8_t` (0x64)      |
| `33`   | Group chat identifier |

A peer times out from a group if it has been inactive for 60s. When a peer times
out, we flag it as _frozen_. Frozen peers are disregarded for all purposes
except those discussed below - in particular no packets are sent to them except
as described below, they are omitted from the peer lists sent to the client or
in a Peer Response packet, and they are not considered when determining closest
peers for establishing direct connections.

A peer is considered to be active if we receive a group message or Rejoin packet
from it, or a New Peer message for it.

If a frozen peer is seen to be active, we remove its 'frozen' flag and send a
Name group message. (We can hold off on sending this message until the next
`tox_iterate`, and only send one message if many frozen peers become active at
once).

If we receive a New Peer message for a peer, we update its DHT pubkey.

If we receive a group message originating from an unknown peer, we drop the
message but send a Peer Query packet back to the peer who directly sent us the
message. (This is current behaviour; it's mentioned here because it's important
and not currently mentioned in the spec.)

If we receive a Rejoin packet from a peer we update its DHT pubkey, add a
temporary groupchat connection for the peer, and, once the connection is online,
send out a New Peer message announcing the peer, and a Name message.

Whenever we make a new friend connection, we check if the public key is that of
any frozen peer. If so, we send it a Rejoin packet, add a temporary groupchat
connection for it, and, once the connection is online, send the peer a Peer
Query packet.

We do the same with a peer when we are setting it as frozen if we have a friend
connection to it.

The temporary groupchat connections established in sending and handling Rejoin
packets are not immediately operational (because group numbers are not known);
rather, an Online packet is sent when we handle a Rejoin packet.

When a connection is set as online as a result of an Online packet, we ping the
group.

When processing the reply to a Peer Query, we update the DHT pubkey of an
existing peer if and only if it is frozen or has not had its DHT pubkey updated
since it last stopped being frozen.

When we receive a Title Response packet, we set the title if it has never been
set or if at some point since it was last set, there were no unfrozen peers
(except us).

## Discussion

### Overview

The intention is to recover seamlessly from splits in the group, the most common
form of which is a single peer temporarily losing all connectivity.

To see how this works, first note that groups (even before the changes discussed
here) have the property that for a group to be connected in the sense that any
peer will receive the messages of any other peer and have them in their
peerlist, it is necessary and sufficient that there is a path of direct group
connections between any two peers.

Now suppose the group is split into two connected components, with each member
of one component frozen according to the members of the other. Suppose there are
two peers, one in each component, which are using the above protocol, and
suppose they establish a friend connection. Then each will rejoin the other,
forming a direct group connection. Hence the whole group will become connected
(even if all other peers are using the unmodified protocol).

The Peer Query packet sent on rejoining hastens this process.

Peers who leave the group during a split will not be deleted by all peers after
the merge - but they will be set as frozen due to ping timeouts, which is
sufficient.

### Titles

If we have a split into components each containing multiple peers, and the title
is changed in one component, then peers will continue to disagree on the title
after the split. Short of a complicated voting system, this seems the only
reasonable behaviour.

### Implementation notes

Although I've described the logic in terms of an 'frozen' flag, it might
actually make more sense in the implementation to have a separate list for
frozen peers.

## Saving

Saving is implemented by simply saving all live groups with their group numbers
and full peer info for all peers. On reload, all peers are set as frozen.

Clients needs to support this by understanding that groups may exist on
start-up. Clients should call `tox_conference_get_chatlist` to obtain them. A
group which is deleted (with `tox_conference_delete`) is removed permanently and
will not be saved.

## Limitations

If a peer disconnects from the group for a period short enough that group
timeouts do not occur, and a name change occurs during this period, then the
name change will never be propagated.

One way to deal with this would be a general mechanism for storing and
requesting missed group messages. But this is considered out of scope of this
PR.

If a peer changes its DHT pubkey, the change might not be properly propagated
under various circumstances - in particular, if connections do not go down long
enough for the peer to become frozen.

One way to deal with this would be to add a group message announcing the sending
peer's current DHT pubkey, and treat it analogously to the Name message.
