# from py_ecc.bn128 import G1, G2, pairing, add, multiply, eq
# from py_ecc.bn128 import bn128_curve, bn128_pairing

# A = multiply(G2, 5)
# B = multiply(G1, 6)
# # C = multiply(G2, 5 * 6)

# # res = (pairing(A, B) == pairing(C, G1))

# # print(res)
# pAB = pairing(A, B)
# r = bn128_curve.multiply(bn128_curve.G1, 3)
# r = pairing(bn128_curve.G2, r)
# print("pAB:", pAB)
# print("type:", type(r))
# print("r:", r, end="\n\n")

# pAB_r = pAB * r
# print("pAB * r:", pAB_r, end="\n\n")

# maybe_old_pAB = pAB_r / r
# print("maybe_old_pAB:", maybe_old_pAB, end="\n\n")

# maybe_old_r = pAB_r / pAB
# print("maybe_old_r:", maybe_old_r, end="\n\n")

# pAB_3 = pAB * 3000000000000000000
# print("pAB_3: ", pAB_3)
# maybe_old_pAB = pAB_3 / 3000000000000000000
# print("maybe_old_pAB:", maybe_old_pAB, end="\n\n")

# maybe_m = pAB_3 / pAB
# print("maybe_m:", maybe_m, end="\n\n")

# exit(0)

from isshiki_2013 import Isshiki, Isshiki_PrivateKey, Isshiki_PublicKey, Isshiki_ReEncKey, Isshiki_Cyphertext_LV1

import utils
from py_ecc.bn128 import bn128_curve, bn128_pairing

"""
Initialization
"""
algo: Isshiki = Isshiki()

"""
Alice
"""
ska: Isshiki_PrivateKey = algo.key_gen()
pka: Isshiki_PublicKey  = algo.gen_pub_key(ska)

print("ska.sk1:", ska.sk1)
print("ska.sk2:", ska.sk2)
print("pka.pk1:", pka.pk1)
print("pka.pk2:", pka.pk2)
print("pka.pk3:", pka.pk3)


"""
Bob
"""
skb: Isshiki_PrivateKey = algo.key_gen()
pkb: Isshiki_PublicKey = algo.gen_pub_key(skb)

print("skb.sk1:", skb.sk1)
print("skb.sk2:", skb.sk2)
print("pkb.pk1:", pkb.pk1)
print("pkb.pk2:", pkb.pk2)
print("pkb.pk3:", pkb.pk3)

"""
Re-encryption Key
"""
rekey_a_to_b: Isshiki_ReEncKey = algo.re_key(ska, pkb)

print("rekey_a_to_b:", rekey_a_to_b.rekey)

"""
Charlie
"""
skc: Isshiki_PrivateKey = algo.key_gen()
pkc: Isshiki_PublicKey = algo.gen_pub_key(skc)

print("skc.sk1:", skc.sk1)
print("skc.sk2:", skc.sk2)
print("pkc.pk1:", pkc.pk1)
print("pkc.pk2:", pkc.pk2)
print("pkc.pk3:", pkc.pk3)

"""
Re-encryption Key Public Verification
"""
# res = algo.pub_check(rekey_a_to_b, pka, pkb)
# print("IS VALID rekey_a_to_b with alice and bob? ", res)

# res = algo.pub_check(rekey_a_to_b, pkb, pka)
# print("IS VALID rekey_a_to_b with bob and alice? ", res)

# res = algo.pub_check(rekey_a_to_b, pka, pkc)
# print("IS VALID rekey_a_to_b with alice and charlie? ", res)

# res = algo.pub_check(rekey_a_to_b, pkc, pka)
# print("IS VALID rekey_a_to_b with charlie and alice? ", res)

# res = algo.pub_check(rekey_a_to_b, pkb, pkc)
# print("IS VALID rekey_a_to_b with bob and charlie? ", res)

# res = algo.pub_check(rekey_a_to_b, pkc, pkb)
# print("IS VALID rekey_a_to_b with charlie and bob? ", res)

print("\n\n")

mp: int = utils.get_secure_pseudo_rand_in_range(algo.p)
pt = bn128_pairing.pairing(bn128_curve.multiply(algo.g, mp), algo.g1)
ct: Isshiki_Cyphertext_LV1 = algo.enc1(pka, pt)

pt_recovered = algo.dec1(pka, ska, ct)

print("pt:", pt, end="\n\n")
print("pt_recovered:", pt_recovered)
