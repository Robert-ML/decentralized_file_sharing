"""
Using ETH's bn128 curve, maybe bls12_381 will be better as is more secure and now supported on ETH contracts

bn128 has:
- the field_modulus (the prime number in 'mod p'):
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
where 2 ^ 253 < p < 2 ^ 254; security parameter k is 253 according to the paper

- the curve order (how many points are on the curve which is obtained by using Schoof's algorithm):
q = 21888242871839275222246405745257275088548364400416034343698204186575808495617

- the curve formula is:
y**2 = x**3 + 3


Note: The paper requires a Hash function H G -> {0,1}^k, but a hash function of 253 bits output is not really common (not a
multiple of 8 which is the size of a byte in bits) even taking into account the RSA-3 new hash variable length
functions. The k used for the hash function will be 256 (bits of output).

"""


# from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dataclasses import dataclass
from hashlib import sha3_256
import secrets
from typing import Any, List, Union, Callable, Self

from py_ecc.bn128 import bn128_curve, bn128_pairing
from py_ecc.fields import (
    bn128_FQ as FQ,
    bn128_FQ2 as FQ2,
    bn128_FQ12 as FQ12,
    bn128_FQP as FQP,
)
from py_ecc.typing import Point2D

from .utils import get_secure_pseudo_rand_in_range
from .field_elements_utils import get_list_of_items_from_G1, get_list_of_items_from_G2, get_list_of_items_from_G12
from .field_elements_utils import build_bn128_G1, build_bn128_G2, build_bn128_G12


def to_int_array(point: tuple[FQ, FQ] | tuple[FQ2, FQ2]) -> list[int]:
    if isinstance(point[0], FQ) and isinstance(point[1], FQ):
        return [
            int(str(point[0].n)),
            int(str(point[1].n)),
        ]
    elif isinstance(point[0], FQ2) and isinstance(point[1], FQ2):
        return [
            int(str(point[0].coeffs[0])),
            int(str(point[0].coeffs[1])),
            int(str(point[1].coeffs[0])),
            int(str(point[1].coeffs[1])),
        ]
    else:
        raise RuntimeError("Unknown point type passed")


@dataclass
class Isshiki_PrivateKey:
    sk1: int
    sk2: int

    def to_dict(self) -> dict[str, int]:
        return {
            "sk1": self.sk1,
            "sk2": self.sk2,
        }

    @classmethod
    def from_dict(cls, container: dict[str, int]) -> Self:
        return cls(
            sk1=container["sk1"],
            sk2=container["sk2"],
        )


@dataclass
class Isshiki_PublicKey:
    pk1: tuple[FQ2, FQ2]
    pk2: tuple[FQ , FQ ]
    pk3: tuple[FQ2, FQ2]

    def to_dict(self) -> dict[str, int]:
        return {
            "pk1_00": int(str(self.pk1[0].coeffs[0])),
            "pk1_01": int(str(self.pk1[0].coeffs[1])),
            "pk1_10": int(str(self.pk1[1].coeffs[0])),
            "pk1_11": int(str(self.pk1[1].coeffs[1])),

            "pk2_0": int(str(self.pk2[0].n)),
            "pk2_1": int(str(self.pk2[1].n)),

            "pk3_00": int(str(self.pk3[0].coeffs[0])),
            "pk3_01": int(str(self.pk3[0].coeffs[1])),
            "pk3_10": int(str(self.pk3[1].coeffs[0])),
            "pk3_11": int(str(self.pk3[1].coeffs[1])),
        }

    @classmethod
    def from_dict(cls, container: dict[str, int]) -> Self:
        return cls(
            pk1=(
                FQ2([
                    container["pk1_00"],
                    container["pk1_01"],
                ]),
                FQ2([
                    container["pk1_10"],
                    container["pk1_11"],
                ]),
            ),
            pk2=(FQ(container["pk2_0"]), FQ(container["pk2_1"])),
            pk3=(
                FQ2([
                    container["pk3_00"],
                    container["pk3_01"],
                ]),
                FQ2([
                    container["pk3_10"],
                    container["pk3_11"],
                ]),
            ),
        )

    def to_list(self) -> list[int]:
        return [
            int(str(self.pk1[0].coeffs[0])),
            int(str(self.pk1[0].coeffs[1])),
            int(str(self.pk1[1].coeffs[0])),
            int(str(self.pk1[1].coeffs[1])),

            int(str(self.pk2[0].n)),
            int(str(self.pk2[1].n)),

            int(str(self.pk3[0].coeffs[0])),
            int(str(self.pk3[0].coeffs[1])),
            int(str(self.pk3[1].coeffs[0])),
            int(str(self.pk3[1].coeffs[1])),
        ]

    @classmethod
    def from_list(cls, container: list[int]) -> Self:
        return cls(
            pk1=(
                FQ2([
                    container[0],
                    container[1],
                ]),
                FQ2([
                    container[2],
                    container[3],
                ]),
            ),
            pk2=(FQ(container[4]), FQ(container[5])),
            pk3=(
                FQ2([
                    container[6],
                    container[7],
                ]),
                FQ2([
                    container[8],
                    container[9],
                ]),
            ),
        )


@dataclass
class Isshiki_ReEncKey:
    rekey: tuple[FQ, FQ]

    def to_list(self) -> list[int]:
        return [
            int(str(self.rekey[0])),
            int(str(self.rekey[1])),
        ]

    @classmethod
    def from_list(cls, container: list[int]) -> Self:
        return cls(
            rekey=(FQ(container[0]), FQ(container[1])),
        )


@dataclass
class Isshiki_PublicParameters:
    g: tuple[FQ2, FQ2] # generator in G2
    g1: tuple[FQ, FQ] # generator in G1
    h: tuple[FQ2, FQ2] # generator in G2
    u: tuple[FQ, FQ] # generator in G1
    v: tuple[FQ, FQ] # generator in G1
    d: tuple[FQ, FQ] # generator in G1

    def to_dict(self) -> dict[str, int]:
        return {
            "g_00": int(str(self.g[0].coeffs[0])),
            "g_01": int(str(self.g[0].coeffs[1])),
            "g_10": int(str(self.g[1].coeffs[0])),
            "g_11": int(str(self.g[1].coeffs[1])),

            "g1_0": int(str(self.g1[0].n)),
            "g1_1": int(str(self.g1[1].n)),

            "h_00": int(str(self.h[0].coeffs[0])),
            "h_01": int(str(self.h[0].coeffs[1])),
            "h_10": int(str(self.h[1].coeffs[0])),
            "h_11": int(str(self.h[1].coeffs[1])),

            "u_0": int(str(self.u[0].n)),
            "u_1": int(str(self.u[1].n)),

            "v_0": int(str(self.v[0].n)),
            "v_1": int(str(self.v[1].n)),

            "d_0": int(str(self.d[0].n)),
            "d_1": int(str(self.d[1].n)),
        }

    @classmethod
    def from_dict(cls, container: dict[str, int]) -> Self:
        return cls(
            g=(
                FQ2([
                    container["g_00"],
                    container["g_01"],
                ]),
                FQ2([
                    container["g_10"],
                    container["g_11"],
                ]),
            ),
            g1=(FQ(container["g1_0"]), FQ(container["g1_1"])),
            h=(
                FQ2([
                    container["h_00"],
                    container["h_01"],
                ]),
                FQ2([
                    container["h_10"],
                    container["h_11"],
                ]),
            ),
            u=(FQ(container["u_0"]), FQ(container["u_1"])),
            v=(FQ(container["v_0"]), FQ(container["v_1"])),
            d=(FQ(container["d_0"]), FQ(container["d_1"])),
        )

    @classmethod
    def from_list(cls, parameters: list[int]) -> Self:
        return cls(
            g=(
                FQ2([
                    parameters[0],
                    parameters[1],
                ]),
                FQ2([
                    parameters[2],
                    parameters[3],
                ]),
            ),
            g1=(FQ(parameters[4]), FQ(parameters[5])),
            h=(
                FQ2([
                    parameters[6],
                    parameters[7],
                ]),
                FQ2([
                    parameters[8],
                    parameters[9],
                ]),
            ),
            u=(FQ(parameters[10]), FQ(parameters[11])),
            v=(FQ(parameters[12]), FQ(parameters[13])),
            d=(FQ(parameters[14]), FQ(parameters[15])),
        )


class Isshiki_Cyphertext_LV1:
    def __init__(self, A, B, C: bytes, C_iv: bytes, original: bool) -> None:
        """
        A - point on the curve
        B - point on the curve
        C - output of SYM enc

        original - if the first level cyphertext was generated by enc 1 it is original True, else False if was created
                by re-encryption
        """
        self.A: tuple[FQ2, FQ2] = A
        self.B: tuple[FQ2, FQ2] = B
        self.C: bytes = C
        self.C_iv: bytes = C_iv

        self.original = original

    def to_evm_args(self) -> tuple[list[int], bytes, bytes]:
        return (
            [
                # A
                int(str(self.A[0].coeffs[0])),
                int(str(self.A[0].coeffs[1])),
                int(str(self.A[1].coeffs[0])),
                int(str(self.A[1].coeffs[1])),

                # B
                int(str(self.B[0].coeffs[0])),
                int(str(self.B[0].coeffs[1])),
                int(str(self.B[1].coeffs[0])),
                int(str(self.B[1].coeffs[1])),
            ],
            self.C,
            self.C_iv,
        )


class Isshiki_Cyphertext_LV2:
    def __init__(self, C1, C2, C3, C4, C5) -> None:
        self.C1: tuple[FQ2, FQ2] = C1
        self.C2: tuple[FQ2, FQ2] = C2
        self.C3: FQ12 = C3
        self.C4: tuple[FQ, FQ] = C4
        self.C5: int = C5

    def to_evm_args(self) -> list[int]:
        """
        @returns the entire cyphertext as a list of 19 uints
        """

        return [
            # C1
            int(str(self.C1[0].coeffs[0])),
            int(str(self.C1[0].coeffs[1])),
            int(str(self.C1[1].coeffs[0])),
            int(str(self.C1[1].coeffs[1])),

            # C2
            int(str(self.C2[0].coeffs[0])),
            int(str(self.C2[0].coeffs[1])),
            int(str(self.C2[1].coeffs[0])),
            int(str(self.C2[1].coeffs[1])),

            # C3
            int(str(self.C3.coeffs[ 0])),
            int(str(self.C3.coeffs[ 1])),
            int(str(self.C3.coeffs[ 2])),
            int(str(self.C3.coeffs[ 3])),
            int(str(self.C3.coeffs[ 4])),
            int(str(self.C3.coeffs[ 5])),
            int(str(self.C3.coeffs[ 6])),
            int(str(self.C3.coeffs[ 7])),
            int(str(self.C3.coeffs[ 8])),
            int(str(self.C3.coeffs[ 9])),
            int(str(self.C3.coeffs[10])),
            int(str(self.C3.coeffs[11])),

            # C4
            int(str(self.C4[0].n)),
            int(str(self.C4[1].n)),

            # C5
            self.C5,
        ]


def _H(a: tuple[FQ2, FQ2]) -> bytes:
    """
    Hash function: G2 -> {0, 1}^(l(n)) ; where l(n) is the size of the output in our case hardcoded to 256 bits which
    is the security parameter chosen. Using sha3_256 as the underlying hash function on the big endian unsigned
    encoded values representing the points in the passed groups.

    @param a - G2 = tuple[field_elements.FQ2, field_elements.FQ2]

    Note: Not very tidy how elements from G2 are extracted, hopefully it is stable.
    """
    alg = sha3_256()

    values: List[int] = []

    values.extend(get_list_of_items_from_G2(a))

    for x in values:
        alg.update(x.to_bytes(length=256 // 8, byteorder="big", signed=False))

    res = alg.digest()

    return res


def _TCR(a: tuple[FQ2, FQ2], b: FQ12, p: int) -> int:
    """
    Hash function: G2 X G12 -> Z modulo p ; using sha3_256 as the underlying hash function on the big endian unsigned
    encoded values representing the points in the passed groups.

    @param a - G2 = tuple[field_elements.FQ2, field_elements.FQ2]
    @param b - G12 = field_elements.FQ12
    @param p - prime of the curve

    Note: Not very tidy how elements from G2 and G12 are extracted, hopefully it is stable.
    """
    alg = sha3_256()

    values: List[int] = []
    # get elements from first parameter 'a'
    values.extend(get_list_of_items_from_G2(a))
    # get elements from first parameter 'b'
    values.extend(get_list_of_items_from_G12(b))

    for x in values:
        alg.update(x.to_bytes(length=256 // 8, byteorder="big", signed=False))

    res = int.from_bytes(alg.digest(), byteorder="big", signed=False) % p

    return res

def _TCRp(a: tuple[FQ2, FQ2], p: int) -> int:
    """
    Hash function: G2 -> Z modulo p ; using sha3_256 as the underlying hash funciton on the big endiand unsigned
    encoded values representing the points in the passed groups.

    @param a - G2 = tuple[field_elements.FQ2, field_elements.FQ2]
    @param p - prime of the curve

    @return integer in modulo p

    Note: Not very tidy how elements from G2 are extracted, hopefully it is stable.
    """

    res = int.from_bytes(_H(a), byteorder="big", signed=False) % p

    return res

class _SYM:
    @staticmethod
    def enc(key: bytes, pt: bytes) -> tuple[bytes, bytes]:
        """
        Symmetric encryption function.

        @param key - size of 256 because of security parameter
        @param pt - plaintext to encrypt

        @return (cyphertext, iv)
        """

        iv: bytes = secrets.token_bytes(algorithms.AES256.block_size // 8)

        cipher: Cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        cyphertext: bytes = encryptor.update(pt) + encryptor.finalize()

        return (cyphertext, iv)

    @staticmethod
    def dec(key: bytes, ct: bytes, iv: bytes) -> bytes:
        """
        Symmetric decryption function.

        @param key - size of 256 because of security parameter
        @param ct - cyphertext to decrypt
        @param iv - initialization vector needed bt AES, can be public

        @return plaintext
        """

        cipher: Cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        plaintext: bytes = decryptor.update(ct) + decryptor.finalize()

        return plaintext

"""
paper: https://www.researchgate.net/publication/264041628_Proxy_Re-Encryption_in_a_Stronger_Security_Model_Extended_from_CT-RSA2012

Warning!: because of the approximation from 253 to 256 for the security parameter, the random sampling of points from
the curve is not uniformly random.

"""
class Isshiki:
    """
    In the paper a security parameter lambda is given ot the generator. It is hardcoded to 253 because of the
    choice of the prime number in bn128, read above 'Note' explanation.
    """
    SECURITY_PARAMETER: int = 253
    P: int = bn128_curve.field_modulus
    Q: int = bn128_curve.curve_order

    H: Callable[[tuple[FQ2, FQ2]], bytes] = _H
    TCRp: Callable[[tuple[FQ2, FQ2], int], int] = _TCRp
    TCR: Callable[[tuple[FQ2, FQ2], FQ12, int], int]  = _TCR
    SYM = _SYM # with .enc and .dec

    def __init__(self, public_params: Isshiki_PublicParameters | None = None) -> None:
        if public_params is None:
            # calculate a random points/generators for our algorithm by going from G1/G2 a random number of times
            self.g: tuple[FQ2, FQ2] = bn128_curve.multiply(bn128_curve.G2, get_secure_pseudo_rand_in_range(Isshiki.Q))
            self.g1: tuple[FQ, FQ]  = bn128_curve.multiply(bn128_curve.G1, get_secure_pseudo_rand_in_range(Isshiki.Q))
            self.h: tuple[FQ2, FQ2] = bn128_curve.multiply(bn128_curve.G2, get_secure_pseudo_rand_in_range(Isshiki.Q))
            self.u: tuple[FQ, FQ]   = bn128_curve.multiply(bn128_curve.G1, get_secure_pseudo_rand_in_range(Isshiki.Q))
            self.v: tuple[FQ, FQ]   = bn128_curve.multiply(bn128_curve.G1, get_secure_pseudo_rand_in_range(Isshiki.Q))
            self.d: tuple[FQ, FQ]   = bn128_curve.multiply(bn128_curve.G1, get_secure_pseudo_rand_in_range(Isshiki.Q))
        else:
            self.g: tuple[FQ2, FQ2] = public_params.g
            self.g1: tuple[FQ, FQ]  = public_params.g1
            self.h: tuple[FQ2, FQ2] = public_params.h
            self.u: tuple[FQ, FQ]   = public_params.u
            self.v: tuple[FQ, FQ]   = public_params.v
            self.d: tuple[FQ, FQ]   = public_params.d


    @property
    def public_params(self) -> Isshiki_PublicParameters:
        return Isshiki_PublicParameters(
            g=self.g,
            g1=self.g1,
            h=self.h,
            u=self.u,
            v=self.v,
            d=self.d,
        )


    def gen_pub_key(self, sk: Isshiki_PrivateKey) -> Isshiki_PublicKey:
        return self._gen_pub_key(sk.sk1, sk.sk2)

    def _gen_pub_key(self, x: int, y: int) -> Isshiki_PublicKey:
        pk1: tuple[FQ2, FQ2] = bn128_curve.multiply(self.g, x)
        pk2: tuple[FQ, FQ]   = bn128_curve.multiply(self.g1, (x ** 2))
        pk3: tuple[FQ2, FQ2] = bn128_curve.multiply(self.g, y)

        return Isshiki_PublicKey(pk1, pk2, pk3)

    def key_gen(self) -> Isshiki_PrivateKey:
        x: int = get_secure_pseudo_rand_in_range(self.P)
        y: int = get_secure_pseudo_rand_in_range(self.P)

        return Isshiki_PrivateKey(x, y)

    def re_key(self, ski: Isshiki_PrivateKey, pkj: Isshiki_PublicKey) -> Isshiki_ReEncKey:
        pkj2 = pkj.pk2
        ski1: int = ski.sk1
        one_over_ski1 = pow(ski1, -1, self.Q) % self.Q

        rekey: tuple[FQ, FQ] = bn128_curve.multiply(pkj2, one_over_ski1)

        return Isshiki_ReEncKey(rekey)

    def pub_check(self, rekey: Isshiki_ReEncKey, pki: Isshiki_PublicKey, pkj: Isshiki_PublicKey) -> bool:
        print(f"{pki.pk1=}")
        print(f"{rekey.rekey=}")
        print(f"{self.g=}")
        print(f"{pkj.pk2=}")
        res = (bn128_pairing.pairing(pki.pk1, rekey.rekey) == bn128_pairing.pairing(self.g, pkj.pk2))

        return res

    def get_random_exponent(self) -> int:
        """
        Obtain a random number to be the exponent in modulo q
        """
        return get_secure_pseudo_rand_in_range(self.Q)

    def get_random_int_in_space(self) -> int:
        """
        Obtain a random number in Z modulo p
        """
        return get_secure_pseudo_rand_in_range(self.P)

    def prepare_plaintext(self, mp: int) -> FQ12:
        """
        @param mp: random number in Z modulo p
        """
        res = bn128_pairing.pairing(bn128_curve.multiply(self.g, mp), self.g1)

        return res


    def enc1(self, pki: Isshiki_PublicKey, message: FQ12) -> Isshiki_Cyphertext_LV1 | None:
        """
        message is a pairing in G12, m = e(g, g1) ^ mp, mp random from Integers modulo p
        """
        try:
            return self._enc1(pki, message)
        except:
            return None

    def _enc1(self, pki: Isshiki_PublicKey, message: FQ12) -> Isshiki_Cyphertext_LV1:
        """
        message is a pairing in G12, m = e(g, g1) ^ mp, mp random from Integers modulo p
        """
        r : int = get_secure_pseudo_rand_in_range(self.P)
        R : int = get_secure_pseudo_rand_in_range(self.P)
        rp: int = get_secure_pseudo_rand_in_range(self.P)
        s : int = get_secure_pseudo_rand_in_range(self.P)

        # C2 = h^r <- G2
        C2 = bn128_curve.multiply(self.h, r)

        # C3 = e(g, g1)^r * m <- G12
        # m = e(g, g1)^mp <- G12; m random from Integers modulo p
        C3: FQ12 = bn128_pairing.pairing(
                bn128_curve.multiply(self.g, r),
                self.g1
            ) * message

        # t = TCR(C2, C3) <- Z modulo p
        t: int = Isshiki.TCR(C2, C3, self.P)

        # C4 = (u^t + v^s + d)^r
        C4 = bn128_curve.multiply(
            bn128_curve.add(
                bn128_curve.add(
                    bn128_curve.multiply(self.u, t),
                    bn128_curve.multiply(self.v, s)
                ),
                self.d
            ),
            r
        )

        # C5 = s <- Z modulo p
        C5 = s

        # C6 = pk_i2^(r * R) <- G1
        C6 = bn128_curve.multiply(
            bn128_curve.multiply(pki.pk2, R),
            r
        )

        # C7 = pk_i2 ^ R <- G1
        C7 = bn128_curve.multiply(pki.pk2, R)

        # C8 = g^(1/R) <- G2
        one_over_R = pow(R, -1, self.Q) % self.Q
        C8 = bn128_curve.multiply(self.g, one_over_R)

        # serialize CTp_i = C2 || C3 || C4 || C5 || C6 || C7 || C8 ; || - concatenation
        # CTp_i - 864 bytes, 27 integers squeezed inside, each one 32 bytes long
        CTp_i = _serialize_CTp_originaly_lv1_enc(C2, C3, C4, C5, C6, C7, C8)
        if len(CTp_i) != 864:
            print("\n\n------------Different length looks like for Originally Lv. 1------------\n\n", end="")

        # A = g^rp <- G2
        A = bn128_curve.multiply(self.g, rp)

        # tp = TCRp(A) <- Z modulo p
        tp = Isshiki.TCRp(A, self.P)

        # B = (pki_3^tp + h)^r
        B = bn128_curve.multiply(
                bn128_curve.add(
                    bn128_curve.multiply(
                        pki.pk3, tp
                    ),
                    self.h
                ),
                rp
        )

        # C = SYM.ENC( key = H(pki_3^rp), pt = CTp_i )
        C, C_iv = Isshiki.SYM.enc(
            Isshiki.H(
                bn128_curve.multiply(pki.pk3, rp)
            ),
            CTp_i
        )

        CT_i = Isshiki_Cyphertext_LV1(A, B, C, C_iv, True)

        return CT_i


    def enc2(self, pki: Isshiki_PublicKey, message: FQ12) -> Isshiki_Cyphertext_LV2:
        """
        message is a pairing in G12, m = e(g, g1) ^ mp, mp random from Integers modulo p
        """
        return self._enc2(pki, message)

    def _enc2(self, pki: Isshiki_PublicKey, message: FQ12) -> Isshiki_Cyphertext_LV2:
        """
        message is a pairing in G12, m = e(g, g1) ^ mp, mp random from Integers modulo p
        """
        r: int = get_secure_pseudo_rand_in_range(self.P)
        s: int = get_secure_pseudo_rand_in_range(self.P)

        # C1 = pk_i1^r <- G2
        C1 = bn128_curve.multiply(pki.pk1, r)

        # C2 = h^r <- G2
        C2 = bn128_curve.multiply(self.h, r)

        # C3 = e(g, g1)^r * m <- G12
        C3 = bn128_pairing.pairing(
            bn128_curve.multiply(self.g, r),
            self.g1
        ) * message

        # t = TCR(C2, C3) <- Z modulo p
        t: int = Isshiki.TCR(C2, C3, self.P)

        # C4 = (u^t + v^s + d)^r <- G1
        C4 = bn128_curve.multiply(
            bn128_curve.add(
                bn128_curve.add(
                    bn128_curve.multiply(self.u, t),
                    bn128_curve.multiply(self.v, s)
                ),
                self.d
            ),
            r
        )

        # C5 = s <- Z modulo p
        C5: int = s

        return Isshiki_Cyphertext_LV2(C1, C2, C3, C4, C5)


    # we use j to denote a possible source of the cyphertext being a re-encryption and now j decrypts
    def dec1(self, pkj: Isshiki_PublicKey, skj: Isshiki_PrivateKey, CT_j: Isshiki_Cyphertext_LV1) -> FQ12 | None:
        try:
            return self._dec1(pkj, skj, CT_j)
        except AssertionError:
            return None

    # we use j to denote a possible source of the cyphertext being a re-encryption and now j decrypts
    def _dec1(self, pkj: Isshiki_PublicKey, skj: Isshiki_PrivateKey, CT_j: Isshiki_Cyphertext_LV1) -> FQ12 | None:

        A = CT_j.A
        B = CT_j.B
        C = CT_j.C
        C_iv = CT_j.C_iv

        tp = Isshiki.TCRp(CT_j.A, self.P)

        # Need to make checks so that we know we can decrypt

        # Check 3: e(A, pkj_e^tp + h) == e(g, B)
        # Not working because we have e(G2, G2) and we only can operate on e(G2, G1)
        # assert (bn128_pairing.pairing(
        #         A,
        #         bn128_curve.add(
        #             bn128_curve.multiply(
        #                 pkj.pk3,
        #                 tp
        #             ),
        #             self.h
        #         )
        #     ) == bn128_pairing.pairing(
        #         self.g,
        #         B
        #     )
        # )

        CTp_j = Isshiki.SYM.dec(
                Isshiki.H(
                    bn128_curve.multiply(A, skj.sk2)
                ), C, C_iv
        )

        (C2, C3, C4, C5, C6, C7, C8) = _deserialize_CTp(CTp_j, CT_j.original)

        t: int = Isshiki.TCR(C2, C3, self.P)
        # Check 4: e(h, C4) == e(C2, u^t + v^C5 + d)
        assert (
            bn128_pairing.pairing(self.h, C4) == bn128_pairing.pairing(
                C2,
                bn128_curve.add(
                    bn128_curve.add(
                        bn128_curve.multiply(self.u, t),
                        bn128_curve.multiply(self.v, C5)
                    ),
                    self.d
                )
            )
        )

        # Check 5:
        if CT_j.original:
            # Case 1 with original = True: e(C8, C7) == e(g, pkj_2)
            assert (bn128_pairing.pairing(C8, C7) == bn128_pairing.pairing(self.g, pkj.pk2))
        else:
            # Case 2 with original = False: e(C7, C8) == e(g, pkj_2)
            assert (bn128_pairing.pairing(C7, C8) == bn128_pairing.pairing(self.g, pkj.pk2))

        # Check 6:
        if CT_j.original:
            # Case 1 with original = True: e(h, C6) == e(C2, C7)
            assert (bn128_pairing.pairing(self.h, C6) == bn128_pairing.pairing(C2, C7))
        else:
            # Case 2 with original = False: e(C6, h) == XXX e(C2, C7) OR e(C7, C2) XXX does not work!
            # e(C2, C7) <- e(G2, G2) (not permitted by the library)
            # e(C7, C2) <- e(G2, G2) (not permitted by the library)

            # TODO: maybe find another check
            pass


        # Obtain the plaintext message
        # TODO: refactor this if else because it can be very small and easy
        pt = None
        if CT_j.original:
            # Case 1 with original = True: m = C3 / ( e(C8, C6) ^ (1/ (skj_1 ^ 2) ) ) = C3 / ( e(C8 ^ (1/skj_1), C6 ^ (1/skj_1))  )
            pt = C3 / (
                bn128_pairing.pairing(
                    bn128_curve.multiply(
                        C8,
                        pow(skj.sk1, -1, self.Q) % self.Q
                    ),
                    bn128_curve.multiply(
                        C6,
                        pow(skj.sk1, -1, self.Q) % self.Q
                    )
                )
            )
        else:
            # Case 2 with original = False: m = C3 / ( e(C6, C8) ^ (1/ (skj_1 ^ 2) ) ) = C3 / ( e(C6 ^ (1/skj_1), C8 ^ (1/skj_1))  )
            pt = C3 / (
                bn128_pairing.pairing(
                    bn128_curve.multiply(
                        C6,
                        pow(skj.sk1, -1, self.Q) % self.Q
                    ),
                    bn128_curve.multiply(
                        C8,
                        pow(skj.sk1, -1, self.Q) % self.Q
                    )
                )
            )
        return pt


    def dec2(self, pki: Isshiki_PublicKey, ski: Isshiki_PrivateKey, CT: Isshiki_Cyphertext_LV2) -> FQ12 | None:
        try:
            return self._dec2(pki, ski, CT)
        except AssertionError:
            return None

    def _dec2(self, pki: Isshiki_PublicKey, ski: Isshiki_PrivateKey, CT: Isshiki_Cyphertext_LV2) -> FQ12 | None:
        C1      = CT.C1
        C2      = CT.C2
        C3      = CT.C3
        C4      = CT.C4
        C5: int = CT.C5

        # t = TCR(C2, C3) <- Z modulo p
        t = Isshiki.TCR(C2, C3, self.P)

        # Check 1: e(h, C1) == e(C2, pk_i1) <- XXX e(G2, G2) == e(G2, G2) XXX not supported by the library
        assert(self.check_1(C1, C2, pki))

        # Check 2: e(h, C4) == e(C2, u^t + v^s + d)
        assert(self.check_2(C2, C4, C5, t))

        # m = C3 / e(C1, g1) ^ (1 / sk_i1)
        pt = C3 / bn128_pairing.pairing(
            bn128_curve.multiply(
                C1,
                pow(ski.sk1, -1, self.Q) % self.Q
            ),
            self.g1
        )

        return pt


    def reenc(self, rekey: Isshiki_ReEncKey, CT_i: Isshiki_Cyphertext_LV2, pki: Isshiki_PublicKey, pkj: Isshiki_PublicKey) -> Isshiki_Cyphertext_LV1 | None:
        """
        @param rekey - re-encryption key from i to j
        @param CT_i - level 2 cyphertext encrypted by i
        @param pki - public key of i
        @param pkj - public key of j
        """
        try:
            return self._reenc(rekey, CT_i, pki, pkj)
        except AssertionError:
            return None

    def _reenc(self, rekey: Isshiki_ReEncKey, CT_i: Isshiki_Cyphertext_LV2, pki: Isshiki_PublicKey, pkj: Isshiki_PublicKey) -> Isshiki_Cyphertext_LV1:
        """
        @param rekey - re-encryption key from i to j
        @param CT_i - level 2 cyphertext encrypted by i
        @param pki - public key of i
        @param pkj - public key of j
        """

        C1      = CT_i.C1
        C2      = CT_i.C2
        C3      = CT_i.C3
        C4      = CT_i.C4
        C5: int = CT_i.C5

        # t = TCR(C2, C3) <- Z modulo p
        t = Isshiki.TCR(C2, C3, self.P)

        # Check 1: e(h, C1) == e(C2, pk_i1) <- XXX e(G2, G2) == e(G2, G2) XXX not supported by the library
        assert(self.check_1(C1, C2, pki))

        # Check 2: e(h, C4) == e(C2, u^t + v^s + d)
        assert(self.check_2(C2, C4, C5, t))

        R : int = get_secure_pseudo_rand_in_range(self.P)
        rp: int = get_secure_pseudo_rand_in_range(self.P)

        # C6 = C1^R <- G2
        C6 = bn128_curve.multiply(C1, R)

        # C7 = pk_i1^R <- G2
        C7 = bn128_curve.multiply(pki.pk1, R)

        # C8 = rekey^(1/R)
        C8 = bn128_curve.multiply(
            rekey.rekey,
            pow(R, -1, self.Q) % self.Q
        )


        # serialize CTp_i = C2 || C3 || C4 || C5 || C6 || C7 || C8 ; || - concatenation
        # CTp_j - 928 bytes, 29 integers squeezed inside, each one 32 bytes long
        CTp_j = _serialize_CTp_originaly_lv2_enc(C2, C3, C4, C5, C6, C7, C8)
        if len(CTp_j) != 928:
            print("\n\n------------Different length looks like for originaly Lv. 2 CT------------\n\n", end="")


        # A = g^rp <- G2
        A = bn128_curve.multiply(self.g, rp)

        # tp = TCRp(A) <- Z modulo p
        tp = Isshiki.TCRp(A, self.P)

        # B = (pki_3^tp + h)^r
        B = bn128_curve.multiply(
                bn128_curve.add(
                    bn128_curve.multiply(
                        pki.pk3, tp
                    ),
                    self.h
                ),
                rp
        )

        # C = SYM.ENC( key = H(pki_3^rp), pt = CTp_i )
        C, C_iv = Isshiki.SYM.enc(
            Isshiki.H(
                bn128_curve.multiply(pkj.pk3, rp)
            ),
            CTp_j
        )

        CT_j = Isshiki_Cyphertext_LV1(A, B, C, C_iv, False)

        return CT_j


    def check_1(self, C1, C2, pki: Isshiki_PublicKey) -> bool:
        # e(h, C1) == e(C2, pk_i1) <- XXX e(G2, G2) == e(G2, G2) XXX not supported by the library
        return True
        return bn128_pairing.pairing(
            self.h, C1
        ) == bn128_pairing.pairing(
            C2, pki.pk1
        )


    def check_2(self, C2, C4, C5: int, t: int) -> bool:
        # e(h, C4) == e(C2, u^t + v^s + d)
        return bn128_pairing.pairing(
            self.h, C4
        ) == bn128_pairing.pairing(
            C2,
            bn128_curve.add(
                bn128_curve.add(
                    bn128_curve.multiply(self.u, t),
                    bn128_curve.multiply(self.v, C5)
                ),
                self.d
            ),
        )

def _serialize_CTp_originaly_lv1_enc(
        C2: tuple[FQ2, FQ2], C3: FQ12, C4: tuple[FQ, FQ], C5: int,
        C6: tuple[FQ, FQ], C7: tuple[FQ, FQ], C8: tuple[FQ2, FQ2]
    ) -> bytes:
    """
    C2 <- G2
    C3 <- G12
    C4 <- G1
    C5 <- int
    C6 <- G1 (for an originally level 1 encryption, G2 for an originally level 2 encryption)
    C7 <- G1 (for an originally level 1 encryption, G2 for an originally level 2 encryption)
    C8 <- G2 (for an originally level 1 encryption, G2 for an originally level 2 encryption)
    """

    # print("\n\n")
    # print("C2:", C2)
    # print("C3:", C3)
    # print("C4:", C4)
    # print("C5:", C5)
    # print("C6:", C6)
    # print("C7:", C7)
    # print("C8:", C8)
    # print("\n\n")

    C2_elems: List[int] = get_list_of_items_from_G2(C2)
    C3_elems: List[int] = get_list_of_items_from_G12(C3)
    C4_elems: List[int] = get_list_of_items_from_G1(C4)
    C5_elems: List[int] = [C5]
    C6_elems: List[int] = get_list_of_items_from_G1(C6)
    C7_elems: List[int] = get_list_of_items_from_G1(C7)
    C8_elems: List[int] = get_list_of_items_from_G2(C8)

    concatenated: List[int] = []
    concatenated.extend(C2_elems)
    concatenated.extend(C3_elems)
    concatenated.extend(C4_elems)
    concatenated.extend(C5_elems)
    concatenated.extend(C6_elems)
    concatenated.extend(C7_elems)
    concatenated.extend(C8_elems)

    serialized_list: List[bytes] = [x.to_bytes(length=256//8, byteorder="big", signed=False) for x in concatenated]

    serialized_data: bytes = b""
    for x in serialized_list:
        serialized_data += x

    return serialized_data

def _serialize_CTp_originaly_lv2_enc(
        C2: tuple[FQ2, FQ2], C3: FQ12, C4: tuple[FQ, FQ], C5: int,
        C6: tuple[FQ2, FQ2], C7: tuple[FQ2, FQ2], C8: tuple[FQ, FQ]
    ) -> bytes:
    """
    C2 <- G2
    C3 <- G12
    C4 <- G1
    C5 <- int
    C6 <- G2 (for an originally level 2 encryption, G1 for an originally level 1 encryption)
    C7 <- G2 (for an originally level 2 encryption, G1 for an originally level 1 encryption)
    C8 <- G2 (for an originally level 2 encryption, G2 for an originally level 1 encryption)
    """

    C2_elems: List[int] = get_list_of_items_from_G2(C2)
    C3_elems: List[int] = get_list_of_items_from_G12(C3)
    C4_elems: List[int] = get_list_of_items_from_G1(C4)
    C5_elems: List[int] = [C5]
    C6_elems: List[int] = get_list_of_items_from_G2(C6)
    C7_elems: List[int] = get_list_of_items_from_G2(C7)
    C8_elems: List[int] = get_list_of_items_from_G1(C8)

    concatenated: List[int] = []
    concatenated.extend(C2_elems)
    concatenated.extend(C3_elems)
    concatenated.extend(C4_elems)
    concatenated.extend(C5_elems)
    concatenated.extend(C6_elems)
    concatenated.extend(C7_elems)
    concatenated.extend(C8_elems)

    serialized_list: List[bytes] = [x.to_bytes(length=256//8, byteorder="big", signed=False) for x in concatenated]

    serialized_data: bytes = b""
    for x in serialized_list:
        serialized_data += x

    return serialized_data


def _deserialize_CTp(CTp: bytes, original: bool
        ) -> tuple[
            tuple[FQ2, FQ2], FQ12, tuple[FQ, FQ], int,
            Union[tuple[FQ, FQ], tuple[FQ2, FQ2]],
            Union[tuple[FQ, FQ], tuple[FQ2, FQ2]],
            Union[tuple[FQ2, FQ2], tuple[FQ, FQ]]
        ]:
    """
    Breaks CTp into its components from: C2 || C3 || C4 || C5 || C6 || C7 || C8 ; || meaning concatenation.
    C6, C7 and C8 can have different sizes as noted down in the return tuple information.

    @param CTp - serialized data to be deserialized
    @param original - bool is true if originally the data came from a 1st level encryption, else false and it came from
        a 2nd level encryption over which the re-encryption step was applied.

    @return tuple(C2, C3, C4, C5, C6, C7, C8) where C6, C7 and C8 are from groups G1, G1 and G2 respectively if is an
        original 1st level encryption, or they are from groups G2, G2 and G1 respectively if they are from a second
        level encryption on which the re-encryption step was applied.
    """

    # size check: how many integers (256 bits = 32 bytes) are needed for each component of CTp: C2, C3, C4, C5
    chunk_divission: List[int] = [2 * 2, 12, 2 * 1, 1]
    if original:
        chunk_divission.extend([2 * 1, 2 * 1, 2 * 2])
    else:
        chunk_divission.extend([ 2 * 2,  2 * 2, 2 * 1])
    integers_needed: int = sum(chunk_divission)
    if integers_needed != (len(CTp) // 32):
        raise RuntimeError(
            f"Expected size of cyphertext to be {integers_needed} but got {len(CTp) // 32}"
        )

    # perform the extraction
    C2_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
        CTp[ 0 * 32 :  1 * 32], CTp[ 1 * 32 :  2 * 32], CTp[ 2 * 32 :  3 * 32], CTp[ 3 * 32 :  4 * 32]]
    ]
    C3_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
        CTp[ 4 * 32 :  5 * 32], CTp[ 5 * 32 :  6 * 32], CTp[ 6 * 32 :  7 * 32], CTp[ 7 * 32 :  8 * 32],
        CTp[ 8 * 32 :  9 * 32], CTp[ 9 * 32 : 10 * 32], CTp[10 * 32 : 11 * 32], CTp[11 * 32 : 12 * 32],
        CTp[12 * 32 : 13 * 32], CTp[13 * 32 : 14 * 32], CTp[14 * 32 : 15 * 32], CTp[15 * 32 : 16 * 32]]
    ]
    C4_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
        CTp[16 * 32 : 17 * 32], CTp[17 * 32 : 18 * 32]]
    ]
    C5_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
        CTp[18 * 32 : 19 * 32]]
    ]
    C6_elems: List[int] = []
    C7_elems: List[int] = []
    C8_elems: List[int] = []
    if original:
        C6_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
            CTp[19 * 32 : 20 * 32], CTp[20 * 32 : 21 * 32]]
        ]
        C7_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
            CTp[21 * 32 : 22 * 32], CTp[22 * 32 : 23 * 32]]
        ]
        C8_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
            CTp[23 * 32 : 24 * 32], CTp[24 * 32 : 25 * 32], CTp[25 * 32 : 26 * 32], CTp[26 * 32 : 27 * 32]]
        ]
    else:
        C6_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
            CTp[19 * 32 : 20 * 32], CTp[20 * 32 : 21 * 32], CTp[21 * 32 : 22 * 32], CTp[22 * 32 : 23 * 32]]
        ]
        C7_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
            CTp[23 * 32 : 24 * 32], CTp[24 * 32 : 25 * 32], CTp[25 * 32 : 26 * 32], CTp[26 * 32 : 27 * 32]]
        ]
        C8_elems: List[int] = [int.from_bytes(x, byteorder="big", signed=False) for x in [
            CTp[27 * 32 : 28 * 32], CTp[28 * 32 : 29 * 32]]
        ]

    C2 = build_bn128_G2(C2_elems)
    C3 = build_bn128_G12(C3_elems)
    C4 = build_bn128_G1(C4_elems)
    C5 = C5_elems[0] # this should be just an integer
    C6 = None
    C7 = None
    C8 = None
    if original:
        C6 = build_bn128_G1(C6_elems)
        C7 = build_bn128_G1(C7_elems)
        C8 = build_bn128_G2(C8_elems)
    else:
        C6 = build_bn128_G2(C6_elems)
        C7 = build_bn128_G2(C7_elems)
        C8 = build_bn128_G1(C8_elems)

    # print("C2:", C2)
    # print("C3:", C3)
    # print("C4:", C4)
    # print("C5:", C5)
    # print("C6:", C6)
    # print("C7:", C7)
    # print("C8:", C8)

    return (C2, C3, C4, C5, C6, C7, C8)
