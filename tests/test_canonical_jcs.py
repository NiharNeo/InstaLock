"""Published RFC 8785 vectors for the exact JCS engine used by canonicalize.

Source: https://www.rfc-editor.org/rfc/rfc8785.html
General JCS permits IEEE-754 floats. These engine conformance tests deliberately
exercise them separately; the proposed-action admission boundary rejects floats.
"""
import json
import struct

import pytest
from rfc8785 import FloatDomainError
from app.core.canonical import _jcs_dumps


# RFC 8785 Appendix B, all non-error rows (IEEE-754 hex -> expected JSON).
NUMBER_VECTORS = [
    ('0000000000000000','0'), ('8000000000000000','0'),
    ('0000000000000001','5e-324'), ('8000000000000001','-5e-324'),
    ('7fefffffffffffff','1.7976931348623157e+308'),
    ('ffefffffffffffff','-1.7976931348623157e+308'),
    ('4340000000000000','9007199254740992'),
    ('c340000000000000','-9007199254740992'),
    ('4430000000000000','295147905179352830000'),
    ('44b52d02c7e14af5','9.999999999999997e+22'),
    ('44b52d02c7e14af6','1e+23'),
    ('44b52d02c7e14af7','1.0000000000000001e+23'),
    ('444b1ae4d6e2ef4e','999999999999999700000'),
    ('444b1ae4d6e2ef4f','999999999999999900000'),
    ('444b1ae4d6e2ef50','1e+21'),
    ('3eb0c6f7a0b5ed8c','9.999999999999997e-7'),
    ('3eb0c6f7a0b5ed8d','0.000001'),
    ('41b3de4355555553','333333333.3333332'),
    ('41b3de4355555554','333333333.33333325'),
    ('41b3de4355555555','333333333.3333333'),
    ('41b3de4355555556','333333333.3333334'),
    ('41b3de4355555557','333333333.33333343'),
    ('becbf647612f3696','-0.0000033333333333333333'),
    ('43143ff3c1cb0959','1424953923781206.2'),
]


@pytest.mark.parametrize('ieee_hex,expected',NUMBER_VECTORS)
def test_rfc8785_appendix_b(ieee_hex: str, expected: str) -> None:
    value = struct.unpack('>d',bytes.fromhex(ieee_hex))[0]
    assert _jcs_dumps(value) == expected.encode('ascii')


@pytest.mark.parametrize('ieee_hex',['7fffffffffffffff','7ff0000000000000','fff0000000000000'])
def test_rfc8785_invalid_numbers(ieee_hex: str) -> None:
    value = struct.unpack('>d',bytes.fromhex(ieee_hex))[0]
    with pytest.raises(FloatDomainError):
        _jcs_dumps(value)


def test_rfc8785_section_3_2_3_and_utf8_vector() -> None:
    value = {
        'numbers':[333333333.33333329,1e30,4.50,2e-3,1e-27],
        'string':"€$\x0f\nA'B\"\\\\\"/",
        'literals':[None,True,False],
    }
    # Section 3.2.4 publishes these exact canonical UTF-8 bytes.
    expected = bytes.fromhex(
        '7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d'
        '62657273223a5b3333333333333333332e333333333333332c31652b33302c342e35'
        '2c302e3030322c31652d32375d2c22737472696e67223a22e282ac245c75303030'
        '665c6e4127425c225c5c5c5c5c222f227d'
    )
    assert _jcs_dumps(value) == expected


def test_rfc8785_section_3_2_3_utf16_key_order() -> None:
    # Published keys in original order; numeric fixture values expose the order
    # without copying the RFC's explanatory labels.
    value = {'€':0,'\r':1,'\ufb33':2,'1':3,'😀':4,'\u0080':5,'ö':6}
    result = _jcs_dumps(value)
    assert list(json.loads(result).values()) == [1,3,5,6,0,4,2]
    assert result == '{"\\r":1,"1":3,"\u0080":5,"ö":6,"€":0,"😀":4,"דּ":2}'.encode()
