import hashlib
import logging

from cryptojwt.utils import b64e

from oidcendpoint.exception import ProcessError

LOGGER = logging.getLogger(__name__)

CC_METHOD = {"S256": hashlib.sha256, "S384": hashlib.sha384, "S512": hashlib.sha512}


def post_authn_parse(request, client_id, endpoint_context, **kwargs):
    """

    :param request:
    :param client_id:
    :param endpoint_context:
    :param kwargs:
    :return:
    """
    if endpoint_context.args["pkce"]["essential"] is True:
        if not "code_challenge" in request:
            raise ValueError("Missing required code_challenge")
        if not "code_challenge_method" in request:
            if "plain" not in endpoint_context.args["pkce"]["code_challenge_method"]:
                raise ValueError("No support for code_challenge_method=plain")

            request["code_challenge_method"] = "plain"
    else:  # May or may not
        if "code_challenge" in request:
            if not "code_challenge_method" in request:
                if (
                    "plain"
                    not in endpoint_context.args["pkce"]["code_challenge_method"]
                ):
                    raise ValueError("No support for code_challenge_method=plain")

                request["code_challenge_method"] = "plain"
    return request


def verify_code_challenge(code_verifier, code_challenge, code_challenge_method="S256"):
    """
    Verify a PKCE (RFC7636) code challenge.


    :param code_verifier: The origin
    :param code_challenge: The transformed verifier used as challenge
    :return:
    """
    _h = CC_METHOD[code_challenge_method](code_verifier.encode("ascii")).digest()
    _cc = b64e(_h)
    if _cc.decode("ascii") != code_challenge:
        LOGGER.error("PKCE Code Challenge check failed")
        raise ProcessError("PCKE check failed")

    LOGGER.debug("PKCE Code Challenge check succeeded")


def post_token_parse(request, client_id, endpoint_context, **kwargs):
    """
    To be used as a post_parse_request function.

    :param token_request:
    :return:
    """
    if "code_verifier" in request:
        try:
            _info = endpoint_context.sdb[request["code"]]
        except KeyError:
            raise ProcessError("Unknown access grant")

        _authn_req = _info["authn_req"]
        if "code_challenge" in _authn_req:
            try:
                _method = _info["authn_req"]["code_challenge_method"]
            except KeyError:
                _method = "S256"

            verify_code_challenge(
                request["code_verifier"], _info["authn_req"]["code_challenge"], _method
            )
        else:
            raise ProcessError("Missing code_challenge in authorization request")

    return request


def add_pkce_support(endpoint, **kwargs):
    endpoint["authorization"].post_parse_request.append(post_authn_parse)

    # Set defaults
    if "essential" not in kwargs:
        kwargs["essential"] = False
    if "code_challenge" not in kwargs:
        kwargs["code_challenge"] = list(CC_METHOD.keys())

    endpoint["authorization"].endpoint_context.args["pkce"] = kwargs

    endpoint["token"].post_parse_request.append(post_token_parse)
