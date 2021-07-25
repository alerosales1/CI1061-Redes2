import requests

# url = 'http://localhost:31364/match'

url = 'http://localhost:31364/match'

# myjson = { "img_url":"https://shotfy.s3-sa-east-1.amazonaws.com/test_imgs/images/Instagram/IMG_0927.PNG"}
myjson = '{ "img_url": "test", "name": "Alejandro"}'

x = requests.post(url, json = myjson)

# print the response text (the content of the requested file):

print(x.text)
print(x.status_code)