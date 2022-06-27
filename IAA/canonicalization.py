import json

# Canonicalize the credential
def _get_claims(JsonCredential, claims_list, claim):

    if isinstance(JsonCredential, dict):
        to_iter = JsonCredential
        prfx = ""
    elif isinstance(JsonCredential, list):
        to_iter = range(len(JsonCredential))
        prfx = "#id"

    for key in to_iter:
        claim.append(prfx + str(key))
        value = JsonCredential[key]

        if isinstance(value, dict):
            _get_claims(value, claims_list, claim)
        elif isinstance(value, list):
            _get_claims(value, claims_list, claim)
        else:
            claim_res = '.'.join(claim)
            claim_res += ": " + str(value)
            claims_list.append(claim_res)

        claim.pop()
    return claims_list

def JCan(Credential):
    claims = _get_claims(Credential, [], [])
    return claims
