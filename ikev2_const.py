# DEFAULTs

DEFAULT_IKE_PORT = 500
DEFAULT_IKE_NAT_TRAVERSAL_PORT = 4500

DEFAULT_SERVER = '1.2.3.4'

DEFAULT_COM = '/dev/ttyUSB2'
DEFAULT_MCC = '123'
DEFAULT_MNC = '456'
DEFAULT_APN = 'internet'
DEFAULT_TIMEOUT_UDP = 2

# IMEI (15 digits) and IMEISV (16 digits) - DEVICE_IDENTITY defaults; override with --imei / --imeisv
IMEI                                    = '123456789012347'   # 15 digits. The last digit (7) is the checksum digit.
IMEISV                                  = '1234567890123456'  # 16 digits


NONE = 0

# IKEv2 Payload Types
SA =      33
KE =      34
IDI =     35
IDR =     36 
CERT =    37
CERTREQ = 38
AUTH =    39
NINR =    40
N =       41
D =       42
V =       43
TSI =     44
TSR =     45
SK =      46
CP =      47 
EAP =     48

# IKEv2 Exchange Types
IKE_SA_INIT =     34
IKE_AUTH =        35
CREATE_CHILD_SA = 36
INFORMATIONAL =   37

RESERVED = 0
IKE = 1
AH =  2
ESP = 3   

# Transform Type Values
ENCR = 1
PRF = 2
INTEG = 3
D_H = 4
ESN = 5


# Transform Type 1 - Encryption Algorithm Transform IDs
ENCR_DES_IV64 =    1
ENCR_DES=          2
ENCR_3DES =        3
ENCR_RC5 =         4
ENCR_IDEA =        5
ENCR_CAST =        6
ENCR_BLOWFISH =    7
ENCR_3IDEA =       8
ENCR_DES_IV32 =    9
ENCR_NULL =       11 # Not allowed
ENCR_AES_CBC =    12
ENCR_AES_CTR =    13
ENCR_AES_CCM_8 =  14
ENCR_AES_CCM_12 = 15
ENCR_AES_CCM_16 = 16
ENCR_AES_GCM_8 =  18
ENCR_AES_GCM_12 = 19
ENCR_AES_GCM_16 = 20

# Transform Type 2 - Pseudorandom Function Transform IDs
PRF_HMAC_MD5 =          1
PRF_HMAC_SHA1 =         2
PRF_HMAC_TIGER =        3
PRF_AES128_XCBC =       4
PRF_HMAC_SHA2_256 =     5
PRF_HMAC_SHA2_384 =     6
PRF_HMAC_SHA2_512 =     7
PRF_AES128_CMAC =       8

# Transform Type 3 - Integrity Algorithm Transform IDs
NONE =                      0
AUTH_HMAC_MD5_96 =	        1
AUTH_HMAC_SHA1_96 =         2
AUTH_DES_MAC =	            3
AUTH_KPDK_MD5 =             4
AUTH_AES_XCBC_96 =          5
AUTH_HMAC_MD5_128 =         6
AUTH_HMAC_SHA1_160 =        7
AUTH_AES_CMAC_96 =          8
AUTH_AES_128_GMAC =         9
AUTH_AES_192_GMAC =        10
AUTH_AES_256_GMAC =        11
AUTH_HMAC_SHA2_256_128 =   12
AUTH_HMAC_SHA2_384_192 =   13
AUTH_HMAC_SHA2_512_256 =   14

# Transform Type 4 - Diffie-Hellman Group Transform IDs
MODP_768_bit =          1
MODP_1024_bit =         2
MODP_1536_bit =         5
MODP_2048_bit =        14
MODP_3072_bit =        15
MODP_4096_bit =        16
MODP_6144_bit =        17
MODP_8192_bit =        18
ECP_256_bit =          19
ECP_384_bit =          20
ECP_521_bit =          21


ESN_NO_ESN = 0
ESN_ESN =    1

TLV = 0
TV =  1

# IKEv2 Transform Attribute Types
KEY_LENGTH = (14, TV)


# States
OK =                            0
TIMEOUT =                       1
REPEAT_STATE =                  2
DECODING_ERROR =                3
MANDATORY_INFORMATION_MISSING = 4
OTHER_ERROR =                   5
REPEAT_STATE_COOKIE =           6


# IKEv2 Notify Message Types - Error Types
UNSUPPORTED_CRITICAL_PAYLOAD            =     1
INVALID_IKE_SPI                         =     4
INVALID_MAJOR_VERSION                   =     5
INVALID_SYNTAX                          =     7
INVALID_MESSAGE_ID                      =     9
INVALID_SPI                             =    11
NO_PROPOSAL_CHOSEN                      =    14
INVALID_KE_PAYLOAD                      =    17
AUTHENTICATION_FAILED                   =    24
SINGLE_PAIR_REQUIRED                    =    34
NO_ADDITIONAL_SAS                       =    35
INTERNAL_ADDRESS_FAILURE                =    36
FAILED_CP_REQUIRED                      =    37
TS_UNACCEPTABLE                         =    38
INVALID_SELECTORS                       =    39
TEMPORARY_FAILURE                       =    43
CHILD_SA_NOT_FOUND                      =    44
# from 24.302                                        
PDN_CONNECTION_REJECTION                =  8192
MAX_CONNECTION_REACHED                  =  8193
SEMANTIC_ERROR_IN_THE_TFT_OPERATION     =  8241
SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION  =  8242
SEMANTIC_ERRORS_IN_PACKET_FILTERS       =  8244
SYNTACTICAL_ERRORS_IN_PACKET_FILTERS    =  8245
NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED      =  9000
USER_UNKNOWN                            =  9001
NO_APN_SUBSCRIPTION                     =  9002
AUTHORIZATION_REJECTED                  =  9003
ILLEGAL_ME                              =  9006
NETWORK_FAILURE                         = 10500
RAT_TYPE_NOT_ALLOWED                    = 11001
IMEI_NOT_ACCEPTED                       = 11005
PLMN_NOT_ALLOWED                        = 11011
UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED = 11055

# IKEv2 Notify Message Types - Status Types
INITIAL_CONTACT                         = 16384
SET_WINDOW_SIZE                         = 16385
ADDITIONAL_TS_POSSIBLE                  = 16386
IPCOMP_SUPPORTED                        = 16387      
NAT_DETECTION_SOURCE_IP                 = 16388      
NAT_DETECTION_DESTINATION_IP            = 16389
COOKIE                                  = 16390
USE_TRANSPORT_MODE                      = 16391
HTTP_CERT_LOOKUP_SUPPORTED              = 16392
REKEY_SA                                = 16393
ESP_TFC_PADDING_NOT_SUPPORTED           = 16394
NON_FIRST_FRAGMENTS_ALSO                = 16395

EAP_ONLY_AUTHENTICATION                 = 16417
# from 24.302                                        
REACTIVATION_REQUESTED_CAUSE            = 40961
BACKOFF_TIMER                           = 41041
PDN_TYPE_IPv4_ONLY_ALLOWED              = 41050
PDN_TYPE_IPv6_ONLY_ALLOWED              = 41051
DEVICE_IDENTITY                         = 41101
EMERGENCY_SUPPORT                       = 41112
EMERGENCY_CALL_NUMBERS                  = 41134
NBIFOM_GENERIC_CONTAINER                = 41288
P_CSCF_RESELECTION_SUPPORT              = 41304
PTI                                     = 41501
IKEV2_MULTIPLE_BEARER_PDN_CONNECTIVITY  = 42011
EPS_QOS                                 = 42014
EXTENDED_EPS_QOS                        = 42015
TFT                                     = 42017
MODIFIED_BEARER                         = 42020
APN_AMBR                                = 42094
EXTENDED_APN_AMBR                       = 42095
N1_MODE_CAPABILITY                      = 51015

NOTIFY_NAMES = {
    UNSUPPORTED_CRITICAL_PAYLOAD: 'UNSUPPORTED_CRITICAL_PAYLOAD',
    INVALID_IKE_SPI: 'INVALID_IKE_SPI',
    INVALID_MAJOR_VERSION: 'INVALID_MAJOR_VERSION',
    INVALID_SYNTAX: 'INVALID_SYNTAX',
    INVALID_MESSAGE_ID: 'INVALID_MESSAGE_ID',
    INVALID_SPI: 'INVALID_SPI',
    NO_PROPOSAL_CHOSEN: 'NO_PROPOSAL_CHOSEN',
    INVALID_KE_PAYLOAD: 'INVALID_KE_PAYLOAD',
    AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
    SINGLE_PAIR_REQUIRED: 'SINGLE_PAIR_REQUIRED',
    NO_ADDITIONAL_SAS: 'NO_ADDITIONAL_SAS',
    INTERNAL_ADDRESS_FAILURE: 'INTERNAL_ADDRESS_FAILURE',
    FAILED_CP_REQUIRED: 'FAILED_CP_REQUIRED',
    TS_UNACCEPTABLE: 'TS_UNACCEPTABLE',
    INVALID_SELECTORS: 'INVALID_SELECTORS',
    TEMPORARY_FAILURE: 'TEMPORARY_FAILURE',
    CHILD_SA_NOT_FOUND: 'CHILD_SA_NOT_FOUND',
    PDN_CONNECTION_REJECTION: 'PDN_CONNECTION_REJECTION',
    MAX_CONNECTION_REACHED: 'MAX_CONNECTION_REACHED',
    SEMANTIC_ERROR_IN_THE_TFT_OPERATION: 'SEMANTIC_ERROR_IN_THE_TFT_OPERATION',
    SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION: 'SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION',
    SEMANTIC_ERRORS_IN_PACKET_FILTERS: 'SEMANTIC_ERRORS_IN_PACKET_FILTERS',
    SYNTACTICAL_ERRORS_IN_PACKET_FILTERS: 'SYNTACTICAL_ERRORS_IN_PACKET_FILTERS',
    NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED: 'NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED',
    USER_UNKNOWN: 'USER_UNKNOWN',
    NO_APN_SUBSCRIPTION: 'NO_APN_SUBSCRIPTION',
    AUTHORIZATION_REJECTED: 'AUTHORIZATION_REJECTED',
    ILLEGAL_ME: 'ILLEGAL_ME',
    NETWORK_FAILURE: 'NETWORK_FAILURE',
    RAT_TYPE_NOT_ALLOWED: 'RAT_TYPE_NOT_ALLOWED',
    IMEI_NOT_ACCEPTED: 'IMEI_NOT_ACCEPTED',
    PLMN_NOT_ALLOWED: 'PLMN_NOT_ALLOWED',
    UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED: 'UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED',
    INITIAL_CONTACT: 'INITIAL_CONTACT',
    COOKIE: 'COOKIE',
    NAT_DETECTION_SOURCE_IP: 'NAT_DETECTION_SOURCE_IP',
    NAT_DETECTION_DESTINATION_IP: 'NAT_DETECTION_DESTINATION_IP',
    DEVICE_IDENTITY: 'DEVICE_IDENTITY',
    PDN_TYPE_IPv4_ONLY_ALLOWED: 'PDN_TYPE_IPv4_ONLY_ALLOWED',
    PDN_TYPE_IPv6_ONLY_ALLOWED: 'PDN_TYPE_IPv6_ONLY_ALLOWED',
}


def notify_name(code):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return str(code)
    return NOTIFY_NAMES.get(code, str(code))

# IKEv2 Authenticaton Method
RSA_DIGITAL_SIGNATURE             = 1
SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2
DSS_DIGITAL_SIGNATURE             = 3

# IKEv2 Traffic Selector Types
TS_IPV4_ADDR_RANGE = 7
TS_IPV6_ADDR_RANGE = 8

# IP Protocol IDs
ANY =   0
TCP =   6
UDP =  17
ICMP =  1
ESP_PROTOCOL = 50

NAT_TRAVERSAL = 4500

# IKEv2 Configuration Payload CFG Types
CFG_REQUEST =       1
CFG_REPLY =         2
CFG_SET =           3
CFG_ACK =           4

# IKEv2 Configuration Payload Attribute Types (num, length) None = more
INTERNAL_IP4_ADDRESS	           = 1
INTERNAL_IP4_NETMASK	           = 2
INTERNAL_IP4_DNS	               = 3
INTERNAL_IP4_NBNS	               = 4
INTERNAL_IP4_DHCP		           = 6
APPLICATION_VERSION		           = 7
INTERNAL_IP6_ADDRESS	           = 8
INTERNAL_IP6_DNS	               = 10
INTERNAL_IP6_DHCP	               = 12
INTERNAL_IP4_SUBNET	               = 13
SUPPORTED_ATTRIBUTES	           = 14
INTERNAL_IP6_SUBNET	               = 15
MIP6_HOME_PREFIX	               = 16
INTERNAL_IP6_LINK	               = 17
INTERNAL_IP6_PREFIX	               = 18
HOME_AGENT_ADDRESS	               = 19
P_CSCF_IP4_ADDRESS	               = 20
P_CSCF_IP6_ADDRESS	               = 21
FTT_KAT		                       = 22
EXTERNAL_SOURCE_IP4_NAT_INFO       = 23
TIMEOUT_PERIOD_FOR_LIVENESS_CHECK  = 24
INTERNAL_DNS_DOMAIN	               = 25
INTERNAL_DNSSEC_TA                 = 26

# IKEv2 Identification Payload ID Types
ID_IPV4_ADDR     = 1
ID_FQDN	         = 2
ID_RFC822_ADDR	 = 3
ID_IPV6_ADDR	 = 5
ID_DER_ASN1_DN	 = 9
ID_DER_ASN1_GN	 = 10
ID_KEY_ID	     = 11
ID_FC_NAME	     = 12
ID_NULL	         = 13


# EAP COde type
EAP_REQUEST  = 1
EAP_RESPONSE = 2
EAP_SUCCESS  = 3
EAP_FAILURE  = 4

# IANA EAP Type
EAP_IDENTITY = 1
EAP_AKA = 23


def eap_permanent_nai(imsi, mnc, mcc):
    return '0' + imsi + '@nai.epc.mnc' + mnc + '.mcc' + mcc + '.3gppnetwork.org'


def encode_eap_identity_response(identifier, identity):
    identity_bytes = identity.encode('utf-8')
    length = 5 + len(identity_bytes)
    return (
        bytes([EAP_RESPONSE, identifier & 0xff])
        + length.to_bytes(2, 'big')
        + bytes([EAP_IDENTITY])
        + identity_bytes
    )


def is_eap_identity_request(decoded):
    return (
        isinstance(decoded, (list, tuple))
        and len(decoded) >= 3
        and decoded[0] == EAP_REQUEST
        and decoded[2] == EAP_IDENTITY
    )


def eap_identity_reply(decoded_eap, imsi, mnc, mcc):
    if not is_eap_identity_request(decoded_eap):
        return None
    return encode_eap_identity_response(
        decoded_eap[1],
        eap_permanent_nai(imsi, mnc, mcc),
    )

# EAP-AKA/EAP-SIM Subtypes:
AKA_Challenge = 1
AKA_Authentication_Reject = 2
AKA_Synchronization_Failure = 4
AKA_Identity = 5
SIM_Start = 10
SIM_Challenge = 11
AKA_Notification = 12
SIM_Notification = 12
AKA_Reauthentication = 13
SIM_Reauthentication = 13
AKA_Client_Error = 14
SIM_Client_Error = 14

# EAP-AKA/EAP-SIM Attributes:
AT_RAND = 1
AT_AUTN = 2
AT_RES = 3
AT_AUTS = 4
AT_PADDING = 6
AT_NONCE_MT = 7
AT_PERMANENT_ID_REQ = 10
AT_MAC = 11
AT_NOTIFICATION = 12
AT_ANY_ID_REQ = 13
AT_IDENTITY = 14
AT_VERSION_LIST = 15
AT_SELECTED_VERSION = 16
AT_FULLAUTH_ID_REQ = 17
AT_COUNTER = 19
AT_COUNTER_TOO_SMALL = 20
AT_NONCE_S = 21
AT_CLIENT_ERROR_CODE = 22
AT_IV = 129
AT_ENCR_DATA = 130
AT_NEXT_PSEUDONYM = 132
AT_NEXT_REAUTH_ID = 133
AT_CHECKCODE = 134
AT_RESULT_IND = 135


# Role
ROLE_INITIATOR = 1
ROLE_RESPONDER = 0
