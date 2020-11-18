import hashlib
import logging

from cryptojwt.utils import b64e
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oidc import TokenErrorResponse

LOGGER = logging.getLogger(__name__)


def hash_fun(f):
    def wrapper(code_verifier):
        _h = f(code_verifier.encode("ascii")).digest()
        _cc = b64e(_h)
        return _cc.decode("ascii")

    return wrapper


CC_METHOD = {
    "plain": lambda x: x,
    "S256": hash_fun(hashlib.sha256),
    "S384": hash_fun(hashlib.sha384),
    "S512": hash_fun(hashlib.sha512),
}


def post_authn_parse(request, client_id, endpoint_context, **kwargs):
    """

    :param request:
    :param client_id:
    :param endpoint_context:
    :param kwargs:
    :return:
    """
    if (
        endpoint_context.args["pkce"]["essential"]
        and "code_challenge" not in request
    ):
        return AuthorizationErrorResponse(
            error="invalid_request",
            error_description="Missing required code_challenge",
        )

    if "code_challenge_method" not in request:
        request["code_challenge_method"] = "plain"

    if (
        "code_challenge" in request
        and (
            request["code_challenge_method"]
            not in endpoint_context.args["pkce"]["code_challenge_methods"]
        )
    ):
        return AuthorizationErrorResponse(
            error="invalid_request",
            error_description="Unsupported code_challenge_method={}".format(
                request["code_challenge_method"]
            ),
        )

    return request


def verify_code_challenge(
    code_verifier, code_challenge, code_challenge_method="S256"
):
    """
    Verify a PKCE (RFC7636) code challenge.


    :param code_verifier: The origin
    :param code_challenge: The transformed verifier used as challenge
    :return:
    """
    if CC_METHOD[code_challenge_method](code_verifier) != code_challenge:
        LOGGER.error("PKCE Code Challenge check failed")
        return False

    LOGGER.debug("PKCE Code Challenge check succeeded")
    return True


def post_token_parse(request, client_id, endpoint_context, **kwargs):
    """
    To be used as a post_parse_request function.

    :param token_request:
    :return:
    """
    if isinstance(request, AuthorizationErrorResponse):
        return request

    try:
        _info = endpoint_context.sdb[request["code"]]
    except KeyError:
        return TokenErrorResponse(
            error="invalid_grant", error_description="Unknown access grant"
        )
    _authn_req = _info["authn_req"]

    if "code_challenge" in _authn_req:
        if "code_verifier" not in request:
            return TokenErrorResponse(
                error="invalid_grant",
                error_description="Missing code_verifier",
            )

        _method = _info["authn_req"]["code_challenge_method"]

        if not verify_code_challenge(
            request["code_verifier"],
            _info["authn_req"]["code_challenge"],
            _method,
        ):
            return TokenErrorResponse(
                error="invalid_grant", error_description="PKCE check failed"
            )

    return request


def add_pkce_support(endpoint, **kwargs):
    authn_endpoint = endpoint.get("authorization")
    if authn_endpoint is None:
        LOGGER.warning(
            "No authorization endpoint found, skipping PKCE configuration"
        )
        return

    token_endpoint = endpoint.get("token")
    if token_endpoint is None:
        LOGGER.warning(
            "No token endpoint found, skipping PKCE configuration"
        )
        return

    authn_endpoint.post_parse_request.append(post_authn_parse)

    if "essential" not in kwargs:
        kwargs["essential"] = False

    code_challenge_methods = kwargs.get(
        "code_challenge_methods", CC_METHOD.keys()
    )

    kwargs["code_challenge_methods"] = {}
    for method in code_challenge_methods:
        if method not in CC_METHOD:
            raise ValueError("Unsupported method: {}".format(method))
        kwargs["code_challenge_methods"][method] = CC_METHOD[method]

    authn_endpoint.endpoint_context.args["pkce"] = kwargs

    token_endpoint.post_parse_request.append(post_token_parse)
