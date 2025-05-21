from py_ecc.fields.field_elements import FQ, FQ2, FQ12
from py_ecc.fields import bn128_FQ, bn128_FQ2, bn128_FQ12

from typing import List, Tuple

def _get_list_of_items_from_FQ(obj: FQ) -> List[int]:
    if not isinstance(obj, FQ):
        raise TypeError(
            f"Expected a field_elements.FQ object but got type {type(obj)}"
        )

    res: List[int] = []

    res.append(obj.n)

    return res

def _get_list_of_items_from_FQ2(obj: FQ2) -> List[int]:
    if not isinstance(obj, FQ2):
        raise TypeError(
            f"Expected a field_elements.FQ2 object but got type {type(obj)}"
        )

    res: List[int] = []

    fq_first:  FQ = obj.coeffs[0]
    fq_second: FQ = obj.coeffs[1]

    res.extend(_get_list_of_items_from_FQ(fq_first))
    res.extend(_get_list_of_items_from_FQ(fq_second))

    return res


def get_list_of_items_from_G1(obj: Tuple[FQ, FQ]) -> List[int]:
    if not isinstance(obj, tuple):
        raise TypeError(
            f"Expected a Tuple[field_elements.FQ, field_elements.FQ] object but got type {type(obj)}"
        )

    res: List[int] = []

    fq_first:  FQ = obj[0]
    fq_second: FQ = obj[1]

    res.extend(_get_list_of_items_from_FQ(fq_first))
    res.extend(_get_list_of_items_from_FQ(fq_second))

    return res

def get_list_of_items_from_G2(obj: Tuple[FQ2, FQ2]) -> List[int]:
    if not isinstance(obj, tuple):
        raise TypeError(
            f"Expected a Tuple[field_elements.FQ2, field_elements.FQ2] object but got type {type(obj)}"
        )

    res: List[int] = []

    fq2_first:  FQ2 = obj[0]
    fq2_second: FQ2 = obj[1]

    res.extend(_get_list_of_items_from_FQ2(fq2_first))
    res.extend(_get_list_of_items_from_FQ2(fq2_second))

    return res

def get_list_of_items_from_G12(obj: FQ12) -> List[int]:
    if not isinstance(obj, FQ12):
        raise TypeError(
            f"Expected a field_elements.FQ12 object but got type {type(obj)}"
        )

    elements: Tuple[FQ] = obj.coeffs
    if len(elements) != 12:
        raise RuntimeError(
            f"Expected tuple with coefficients to have 12 elements but has {len(elements)}"
        )

    res: List[int] = []

    for x in elements:
        res.extend(_get_list_of_items_from_FQ(x))

    return res


def build_bn128_G1(elems: List[int]) -> Tuple[FQ, FQ]:
    if 2 != len(elems):
        raise RuntimeError(
            f"Expected 2 integers into `elems` but got {len(elems)}"
        )

    return (bn128_FQ(elems[0]), bn128_FQ(elems[1]))

def build_bn128_G2(elems: List[int]) -> Tuple[FQ2, FQ2]:
    if 4 != len(elems):
        raise RuntimeError(
            f"Expected 4 integers into `elems` but got {len(elems)}"
        )

    return (bn128_FQ2(elems[0 : 2]), bn128_FQ2(elems[2 : 4]))

def build_bn128_G12(elems: List[int]) -> FQ12:
    if 12 != len(elems):
        raise RuntimeError(
            f"Expected 12 integers into `elems` but got {len(elems)}"
        )

    return bn128_FQ12(elems)
