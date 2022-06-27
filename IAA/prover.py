import json
from canonicalization import JCan
from ursa_bbs_signatures import BlsKeyPair, ProofMessage, ProofMessageType, CreateProofRequest, create_proof

class Prover:
    def _get_proof_messages(self, messages, revealed_messages):
        if not (set(revealed_messages) <= set(messages)):
            raise ValueError("Revealed messages is not subset of the initial messages")
        
        # get messages for the proof
        proof_messages = []
        for msg in messages:
            if msg in revealed_messages:
                proof_messages.append(ProofMessage(msg, ProofMessageType(1)))
            else:
                proof_messages.append(ProofMessage(msg, ProofMessageType(2)))      
        return proof_messages

    def _frame_message(self, message:dict, frame:dict, result:dict={})-> dict:
        if isinstance(message, dict):
            to_iter = message
        elif isinstance(message, list):
            to_iter = range(len(message))
        else: to_iter = message

        for key in to_iter:
            if str(key) in frame:
                if isinstance(message[key], dict):

                    if isinstance(result, list):  result.append({})
                    elif isinstance(result, dict): result[key] = {}
                    else: raise ValueError("Invalid key or value")

                    self._frame_message(message[key], frame[str(key)], result[key])
                elif isinstance(message[key], list):
        
                    if isinstance(result, list):  result.append([])
                    elif isinstance(result, dict): result[key] = []
                    else: raise ValueError("Invalid key or value")
        
                    self._frame_message(message[key], frame[str(key)], result[key])
                else: 
                    result[key] = message[key]

        return result

    def generate_zkp(self, public_key: bytes, message:str, frame:str, signature:bytes) -> tuple[int, str, bytes]:
        bls_pub_key = BlsKeyPair(public_key=public_key)
        signed_messages = JCan(json.loads(message))
        revealed_message_json = self._frame_message(json.loads(message),json.loads(frame))
        revealed_messages = JCan(revealed_message_json)

        # get the proof messages
        proof_messages = self._get_proof_messages(signed_messages, revealed_messages)

        # get bbs key from bls key (the bls key + the generators)
        claims = len(signed_messages)
        bbs_pub_key = bls_pub_key.get_bbs_key(claims)

        # create proof
        proof_request = CreateProofRequest(public_key=bbs_pub_key,
                                    messages=proof_messages, 
                                    signature=signature, 
                                    nonce=b'PROOF_NONCE') #<---------Fix that

        proof = create_proof(proof_request)
        return claims, json.dumps(revealed_message_json), proof