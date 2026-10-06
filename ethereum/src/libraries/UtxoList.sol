// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice One owner's UTXOs of one app, in order: change at the front and receipts at the back.
/// Insert at either end and removal of any member are O(1), so a UTXO leaves the list in the same
/// call that spends it and a walk from `first` meets only live UTXOs.
/// @dev Members are `utxoKey`s, which are never zero. Zero marks both ends. A removed entry keeps
/// its `next` and has `prev` set to `REMOVED`, so a paging cursor that names a UTXO spent between
/// two calls still leads to the rest of the list.
library UtxoList {
    bytes32 internal constant REMOVED = bytes32(type(uint256).max);

    struct List {
        bytes32 first;
        bytes32 last;
        mapping(bytes32 key => Link) links;
    }

    struct Link {
        bytes32 prev;
        bytes32 next;
    }

    function pushFront(List storage list, bytes32 key) internal {
        bytes32 first = list.first;
        list.links[key].next = first;
        if (first == 0) list.last = key;
        else list.links[first].prev = key;
        list.first = key;
    }

    function pushBack(List storage list, bytes32 key) internal {
        bytes32 last = list.last;
        list.links[key].prev = last;
        if (last == 0) list.first = key;
        else list.links[last].next = key;
        list.last = key;
    }

    /// @dev `key` must be a member. Every caller removes a key it knows the list holds.
    function remove(List storage list, bytes32 key) internal {
        Link storage link = list.links[key];
        (bytes32 prevKey, bytes32 nextKey) = (link.prev, link.next);
        if (prevKey == 0) list.first = nextKey;
        else list.links[prevKey].next = nextKey;
        if (nextKey == 0) list.last = prevKey;
        else list.links[nextKey].prev = prevKey;
        link.prev = REMOVED;
    }

    function isEntry(List storage list, bytes32 key) internal view returns (bool) {
        return key != 0 && (key == list.first || list.links[key].prev != 0);
    }

    function isRemoved(List storage list, bytes32 key) internal view returns (bool) {
        return list.links[key].prev == REMOVED;
    }
}
