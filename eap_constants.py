# 定义EAPOL类型
EAPOL_TYPE_EAP = 0x888e
EAPOL_VERSION = 0x01

# 定义EAP类型
EAP_TYPE_IDENTITY = 1
EAP_TYPE_MD5_CHALLENGE = 4
EAP_TYPE_TLS = 13
EAP_TYPE_PEAP = 25
EAP_TYPE_TTLS = 21

# EAPOL帧类型
EAPOL_TYPE_EAP_PACKET = 0
EAPOL_TYPE_EAPOL_START = 1
EAPOL_TYPE_LOGOFF = 2
EAPOL_TYPE_KEY = 3
EAPOL_TYPE_ASF = 4

# 定义EAP代码
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4


# RADIUS属性
RADIUS_EAP_MESSAGE = 79
RADIUS_USER_NAME = 1
RADIUS_STATE = 24

# 认证模式
RADIUS_MODE_RELAY = 0
RADIUS_MODE_TERMINATE = 1

EAP_MD5_CHALLENGE_LENGTH = 16

RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCESS_CHALLENGE = 11


# ---------------------------
# EAP 代码
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

# EAP 类型
EAP_IDENTITY = 1
EAP_MD5 = 4
EAP_TLS = 13
EAP_PEAP = 25

# RADIUS 消息类型
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11

# 认证模式
MODE_RELAY = 0
MODE_TERMINATE = 1

STATE_STEP_REQ_IDENTITY = 1
STATE_STEP_ACK_IDENTITY = 2
STATE_STEP_REQ_MD5_CHALLENGE = 3
STATE_STEP_ACK_MD5_CHALLENGE = 4
STATE_STEP_INIT_DONE = 5
