import json

import requests

# url = 'http://localhost:31364/match'

url = 'http://localhost:31364/match'

# myjson = { "img_url":"https://shotfy.s3-sa-east-1.amazonaws.com/test_imgs/images/Instagram/IMG_0927.PNG"}
myjson = { "p": 23, "g": 5}

x = requests.post(url, json = myjson)

# print the response text (the content of the requested file):



print(x.text)
print(x.status_code)

json_msg = bytes(x.text, 'utf-8')

json_obj = json.loads(json_msg)

print(json_obj['server_mix'])