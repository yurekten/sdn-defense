from ryu.ofproto import ofproto_v1_4

CONTROLLER_IP= "127.0.0.1"
CONTROLLER_PORT = 6653

SDN_CONTROLLER_APP_KEY = "SDN_CONTROLLER_APP"
HTTP_SERVER = "127.0.0.1"
HTTP_SERVER_PORT = 8080
HTTP_URL = "http://" + HTTP_SERVER + ":" + str(HTTP_SERVER_PORT)
HTTP_DEFAULT_HEADER = {'Content-type': 'application/json', 'Cache-Control': 'no-cache'}
