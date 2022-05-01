from server import MyTCPHandler
import json
import random
import hashlib
import base64

# 
def handleWebSocket(TCP: MyTCPHandler, RequestLine, data):

    data = b''
    while True:
        received_data = MyTCPHandler.request.recv(1024)

        i = 0 
        # FIN 1, RSV (0)
        first_8 = int(received_data[i])
        
        # opcode -- specifies type of info contained in payload, 0001 for text, 0010 for binary, 1000 close connection
        opcode = first_8 & 15
        if opcode == 8:
            # find websocket in websocket_connections and remove
            MyTCPHandler.websocket_connections.remove({'username': username, 'socket': MyTCPHandler})
            break

        # mask + payload length = frame length
        i += 1 # to go through the bytes array
        
        mask = int(received_data[i]) & 128
        payload_length = int(received_data[i]) & 127

        if payload_length == 126: # next 16 bits (2 bytes) represents payload_length
            new_payload = 0
            for x in range(0,2):
                i += 1
                new_payload = (new_payload << 8) | received_data[i]
            payload_length = new_payload
        elif payload_length == 127: # next 64 bits (8 bytes) represents payload_length
            new_payload = 0
            for x in range(0,8):
                i += 1
                new_payload = (new_payload << 8) | received_data[i]
            payload_length = new_payload
        else: # payload < 126
            payload_length = payload_length

        data += received_data

        # handle messages of arbitrary size
        if payload_length > 1024: # 1024 is the recv byte size
            payload_bytes_counter = payload_length
            payload_bytes_counter -= 1024 # from first read
            
            while payload_bytes_counter > 0:
                received_data = MyTCPHandler.request.recv(1024)
                payload_bytes_counter -= 1024
                data += received_data
                

        # mask - set to 1 if mask is being used/receiving messages from client, 0 if no mask is being used
        masking_key = [] # if MASK bit == 1, next 4 bytes (32 bits) is the mask, else payload begins []
        
        if mask == 128: # int & 128 = 128 if mask = 1
            for x in range(0,4):
                i += 1
                masking_key.append(data[i])

        byte_counter = payload_length
        message = b''

        while byte_counter >= 4:
            for x in range(0,4):
                i += 1
                message += (data[i] ^ masking_key[x]).to_bytes(1,"big")
            byte_counter -= 4
        
        if byte_counter != 0: # not multiple of 4
            for x in range(0, byte_counter):
                i += 1
                message += (data[i] ^ masking_key[x]).to_bytes(1,"big")
            byte_counter = 0
        
        message = message.decode("utf-8")
        message = replace_HTML(message)
        
        message_json = json.loads(message)

        # check messageType
        if message_json['messageType'] == 'webRTC-offer':
            json_message = {'messageType': 'webRTC-offer', 'offer': message_json['offer']}
            message_as_bytes = json.dumps(json_message).encode()
            webframe = convert_webframe(MyTCPHandler, message_as_bytes)
            for client in MyTCPHandler.websocket_connections:
                if client['socket'] != MyTCPHandler:
                    client['socket'].request.sendall(webframe)
            data = b''
        elif message_json['messageType'] == 'webRTC-answer':
            json_message = {'messageType': 'webRTC-answer', 'answer': message_json['answer']}
            message_as_bytes = json.dumps(json_message).encode()
            webframe = convert_webframe(MyTCPHandler, message_as_bytes)
            for client in MyTCPHandler.websocket_connections:
                if client['socket'] != MyTCPHandler:
                    client['socket'].request.sendall(webframe)
            data = b''
        elif message_json['messageType'] == 'webRTC-candidate':
            json_message = {'messageType': 'webRTC-candidate', 'candidate': message_json['candidate']}
            message_as_bytes = json.dumps(json_message).encode()
            webframe = convert_webframe(MyTCPHandler, message_as_bytes)
            for client in MyTCPHandler.websocket_connections:
                if client['socket'] != MyTCPHandler:
                    client['socket'].request.sendall(webframe)
            data = b''
        elif message_json['messageType'] == 'chatMessage':
            json_message = {'messageType': 'chatMessage', 'username': username, 'comment': message_json['comment']}
            db_msg = {'username': username, 'comment': message_json['comment']}
            chat_collection.insert_one(db_msg)
            message_as_bytes = json.dumps(json_message).encode()
            webframe = convert_webframe(MyTCPHandler, message_as_bytes)
            for client in MyTCPHandler.websocket_connections:
                client['socket'].request.sendall(webframe)
            data = b''
    
    return

def compute_accept(key: str):
    # appends a specific GUID to key
    websocket_key = key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    print('Appended Sec-WebSocket-Key + R665 Key: ' + websocket_key)
    # computes the SHA-1 hash
    hash_object = hashlib.sha1(websocket_key.encode()).digest()
    # base64 encode the hash
    base64_encoded = base64.b64encode(hash_object)
    
    return base64_encoded

def websocket_request(self, headers):
    key = headers['Sec-WebSocket-Key']
    accept = compute_accept(key)
    response = generate_socket_response('101 Switching Protocols', accept)
    self.request.sendall(response)

    # generate user's usernames and store websocket for future uses
    username = "User" + str(random.randint(0,1000))
    self.websocket_connections.append({'username': username, 'socket': self})

    handleWebSocket(self, username)

def generate_socket_response(responseCode: str, accept_response: bytes):
    response = b'HTTP/1.1 ' + responseCode.encode()
    response += b'\r\nConnection: Upgrade'
    response += b'\r\nUpgrade: websocket'
    response += b'\r\nSec-WebSocket-Accept: ' + accept_response
    response += b'\r\n\r\n'
    return response

def convert_webframe(self, message: bytes):

    msg_length = len(message)
    return_frame = 0

    if msg_length < 126:
        return_frame = (129).to_bytes(1, "big") + (msg_length).to_bytes(1, "big")
    elif msg_length >= 126 and msg_length < 65536:
        return_frame = (129).to_bytes(1, "big") + (126).to_bytes(1, "big") + (msg_length).to_bytes(2, "big")
    else:
        return_frame = (129).to_bytes(1, "big") + (127).to_bytes(1, "big") + (msg_length).to_bytes(8, "big")

    return_frame += message
    return return_frame