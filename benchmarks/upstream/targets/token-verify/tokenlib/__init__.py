from .api_jws import (
    JwS,
    get_unverified_header,
    register_algorithm,
    unregister_algorithm,
)
from .api_jwt import JwT, decode, encode
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
    JwKClientError,
    JwKError,
    JwKSetError,
    JwTError,
)

__version__ = "2.3.0"

__title__ = "tokenlib"
__description__ = "JSON Web Token implementation in Python"
__url__ = ""
__uri__ = __url__
__doc__ = f"{__description__} <{__uri__}>"

__author__ = ""
__email__ = ""

__license__ = "MIT"
__copyright__ = ""


__all__ = [
    "JwS",
    "JwT",
    "decode",
    "encode",
    "get_unverified_header",
    "register_algorithm",
    "unregister_algorithm",
    # Exceptions
    "DecodeError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InvalidAlgorithmError",
    "InvalidAudienceError",
    "InvalidIssuedAtError",
    "InvalidIssuerError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidTokenError",
    "MissingRequiredClaimError",
    "JwKClientError",
    "JwKError",
    "JwKSetError",
    "JwTError",
]
