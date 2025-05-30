import requests
import simplejson
import cv2
import json
from json import loads


addr = 'http://localhost:443'
test_url = addr + '/api/test'


# prepare headers for http request
content_type = 'image/jpeg'
headers = {'content-type': content_type}
name = 'face.jpg'
print (name)
img = cv2.imread(name)
# encode image as jpeg
_, img_encoded = cv2.imencode('.jpg', img)
# send http request with image and receive response
#enviar = requests.post(name)
#print (enviar)
response = requests.post(test_url, data=img_encoded.tostring(), headers=headers)
print(test_url)
#print(img_encoded.tostring())
print(headers)
# decode response
example = json.loads(response.text)
print (example)
#return json.loads(data.decode("utf-8"))


# expected output: {u'message': u'image received. size=124x124'}