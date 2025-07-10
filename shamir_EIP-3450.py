#!/usr/bin/env python

import argparse
import itertools
from dataclasses import dataclass
from eth_account.hdaccount import Mnemonic
from bitarray import bitarray
from bitarray.util import int2ba
from hashlib import sha256
from pyssss.PGF256Interpolator import PGF256Interpolator
from pyssss.GF256elt import GF256elt
from pyssss.PySSSS import pickRandomPolynomial
from pyssss import GF256


@dataclass
class ShamirShare:
    id: int
    secret: bytes


def mnemonic_entropy(mnemonic: str) -> bytes:
    """
    Retrieve mnemonic's random data while checking if it has a valid checksum

    :param str mnemonic: Mnemonic string
    """
    VALID_WORD_COUNTS = [12, 24]
    words = mnemonic.split(" ")
    num_words = len(words)

    if num_words not in VALID_WORD_COUNTS:
        return False

    try:
        indices = tuple(wordlist.index(w) for w in words)
    except ValueError:
        return False

    encoded_seed = bitarray()
    for idx in indices:
        # Build bitarray from tightly packing indices (which are 11-bits integers)
        encoded_seed.extend(int2ba(idx, length=11))

    entropy_size = 4 * num_words // 3

    # Checksum the raw entropy bits
    checksum = bitarray()
    stored_entropy = encoded_seed[: entropy_size * 8].tobytes()
    checksum.frombytes(sha256(stored_entropy).digest())
    computed_checksum = checksum[: len(encoded_seed) - entropy_size * 8].tobytes()

    # Extract the stored checksum bits
    stored_checksum = encoded_seed[entropy_size * 8 :].tobytes()

    # Check that the stored matches the relevant slice of the actual checksum
    if stored_checksum != computed_checksum:
        raise ValueError("Not a valid BIP-39 mnemonic (checksum validation failed).")

    return stored_entropy


def eip3450_reconstruct(GF: GF256.GF256, shares: list[ShamirShare]) -> bytes:
    """
    Recover original secret from the list of Shamir Shares.

    :param GF256 GF: Instance of GF(256) based on some irreducible polynomial (Rijndael or QR)
    :param list[ShamirShare] shares: List of Shamir's Shares (id+data as ShamirShare(id, data)).
    """
    interpolator = PGF256Interpolator()
    zero = GF256elt(GF, 0)

    share_ids = [s.id for s in shares]
    share_secrets = [s.secret for s in shares]
    result = []

    # combine secrets byte-by-byte
    for y_vec in zip(*share_secrets):
        points = [(GF256elt(GF, x), GF256elt(GF, y)) for x, y in zip(share_ids, y_vec)]
        f = interpolator.interpolate(points).f(zero)
        result.append(int(f))

    recovered_secret = bytes(result)
    return recovered_secret


def eip3450_split(GF: GF256.GF256, data: bytes, n: int, t: int) -> list[ShamirShare]:
    """
    Split data to n Shamir Shares with threshold t as described in EIP-3450.

    :param GF256 GF: Instance of GF(256) based on some irreducible polynomial (Rijndael or QR)
    :param bytes data: Original secret data
    :param int n: Number of shares to generate
    :param int t: Threshold number of shares required to reconstruct the secret
    """
    keys = [list() for i in range(n)]
    for byte in data:
        P = pickRandomPolynomial(t - 1, GF256elt(GF, byte))
        for i in range(n):
            share_id = i + 1
            X = GF256elt(GF, share_id)
            Y = P.f(X)
            keys[i].append(int(Y))

    return [ShamirShare(i + 1, bytes(keys[i])) for i in range(n)]


def check_combinations(
    original_secret: bytes,
    all_shares: list[ShamirShare],
    threshold: int,
    verbose: bool = True,
):
    if verbose:
        print("Checking reconstructibility...")

    for shares_subset in itertools.permutations(all_shares, threshold):
        ids = tuple(s.id for s in shares_subset)
        is_valid = bool(eip3450_reconstruct(GF, shares_subset) == original_secret)
        if verbose:
            status = "OK" if is_valid else "Error"
            print(f"{ids}: {status}, ", end="", flush=True)
        if not is_valid:
            raise ValueError(f"Reconstruction failed for shares {ids}")

    if verbose:
        print("\nDone.")


def action_split(args):
    secret_data = mnemonic_entropy(args.secret)
    shares = eip3450_split(GF, secret_data, args.n, args.t)

    if args.check:
        check_combinations(secret_data, shares, args.t)

    for s in shares:
        print(f"Share {s.id}/{args.n}")
        print(f"{s.id} {en_mnemonic.to_mnemonic(s.secret)}\n")


def action_combine(args):
    shares: list[ShamirShare] = []
    for s_arg in args.shares:
        words = s_arg.split(" ")
        share_id = int(words[0])
        share_mnemonic = " ".join(words[1:])
        share_data = mnemonic_entropy(share_mnemonic)
        shares.append(ShamirShare(share_id, share_data))

    recovered_secret = eip3450_reconstruct(GF, shares)
    recovered_mnemonic = en_mnemonic.to_mnemonic(recovered_secret)

    print(f"Recovered mnemonic: {recovered_mnemonic}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Split/Reconstruct BIP-39 mnemonic to/from Shamir's Shares as described in EIP-3450"
    )
    parser.add_argument(
        "-q",
        "--qr",
        action="store_true",
        help="Use QR irreducible polynomial (compatible with asonnino/shamir-bip39 tool) instead of Rijndael",
    )
    subparsers = parser.add_subparsers(
        title="subcommands", dest="subcommand", required=True
    )
    parser_split = subparsers.add_parser("split", help="split mnemonic")
    parser_split.add_argument("-s", "--secret", required=True, help="BIP-39 mnemonic")
    parser_split.add_argument(
        "-c", "--check", action="store_true", help="check reconstructibility"
    )
    parser_split.add_argument(
        "-n", "--n", type=int, required=True, help="number of shares"
    )
    parser_split.add_argument("-t", "--t", type=int, required=True, help="threshold")
    parser_split.set_defaults(func=action_split)

    parser_combine = subparsers.add_parser("reconstruct", help="combine shares")
    parser_combine.add_argument(
        "-s",
        "--shares",
        nargs="*",
        required=True,
        help='Shares are provided in the following format: "INDEX_I WORD_1 .. WORD_24"',
    )
    parser_combine.set_defaults(func=action_combine)
    args = parser.parse_args()

    en_mnemonic = Mnemonic()
    wordlist = en_mnemonic.wordlist
    # QR polynomial is compatible with github.com/asonnino/shamir-bip39 implementation but contradicts ERC-3450
    GF = GF256.QR if args.qr else GF256.RIJNDAEL

    args.func(args)
