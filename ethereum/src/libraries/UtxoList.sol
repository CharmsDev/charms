// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice One owner's UTXOs of one app, in order: change at the front and receipts at the back.
/// Insert at either end and removal of any member are O(1), so a UTXO leaves the list in the same
/// call that spends it and no walk ever meets a spent key.
/// @dev Members are `utxoKey`s, which are never zero. Zero marks both ends.
library UtxoList {
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
        delete list.links[key];
    }

    function isMember(List storage list, bytes32 key) internal view returns (bool) {
        return key != 0 && (key == list.first || list.links[key].prev != 0);
    }
}
