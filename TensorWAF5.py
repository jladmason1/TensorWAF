# Tensor WAF 
# version 0.5
# By Jason Adamson 
# This is a Neural Network based WAF that learns what an attack is based on training data
# It also responds to attacks with Anti-AI techniques to poison Offensive AIs. 

from numpy import loadtxt
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from numpy import array
from http.server import HTTPServer, BaseHTTPRequestHandler
import base64
import random
####################################################
# The ML partition
####################################################

#Global Vars
TrainingID = "12345678901234567890"
responseValue = 0
sitelist = ["127.0.0.1:8080", "127.0.0.1", "testsite1.testing.com"]
webroot = "c:\\users\\adamsjl\\downloads\\tools\\scripts\\ai\\webroot\\"


#set up default decision value
decision = "Allow"

# load the training dataset
dataset = loadtxt('tensortestdata.txt', delimiter=',')

# split into input (X) and output (y) variables
X = dataset[:,0:8]
y = dataset[:,8]

# define the keras model
model = Sequential()
model.add(Dense(12, input_shape=(8,), activation='relu'))
model.add(Dense(8, activation='relu'))
model.add(Dense(8, activation='relu'))
model.add(Dense(1, activation='sigmoid'))

# compile the keras model
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# train the keras model on the training dataset
model.fit(X, y, epochs=150, batch_size=10, verbose=1)


####################################################
# The parsing of incoming requests
####################################################

#Method to parse the HTTP Method of the incoming request and assign a value
def v1Method(self):
    print("[]HTTP Method = ",self.command)
    if self.command == "GET":
        value1 = 1
    elif self.command == "POST":
        value1 = 2
    elif self.command == "OPTIONS":
        value1 = 3
    elif self.command == "PUT":
        value1 = 4
    elif self.command == "DELETE":
        value1 = 5
    elif self.command == "TRACK":
        value1 = 6
    elif self.command == "TRACE":
        value1 = 7
    elif self.command == "CONNECT":
        value1 = 9
    else:
        value1 = 8
    return value1

#function for parsing URI and params,
#value is a cumulitive value based on the types of chars and words in the URI path.
def v2URI(self):
    print("[]URI = ",self.path)
    value2 = 0
    uri = self.path.split("?")
    for section in uri:
        if "[" in section:
            value2 = value2 + (1 * (section.count("[")))
        if '"' in section:
            value2 = value2 + (2 * (section.count('"')))
        if "]" in section:
            value2 = value2 + (1  * (section.count("]")))
        if "(" in section:
            value2 = value2 + (40  * (section.count("(")))
        if ")" in section:
            value2 = value2 + (40  * (section.count(")")))
        if "{" in section: 
            value2 = value2 + (40  * (section.count("{")))
        if "}" in section:
            value2 = value2 + (40  * (section.count("}")))
        if "%3C" in section:
            value2 = value2 + (200  * (section.count("%3C")))
        if "<" in section:
            value2 = value2 + (200  * (section.count("<")))
        if ">" in section:
            value2 = value2 + (200  * (section.count(">")))
        if "%3E" in section:
            value2 = value2 + (200  * (section.count("%3E")))
        if "bin/bash" in section:
            value2 = value2 + (500  * (section.count("/bin/bash")))
        if "cmd.exe" in section:
            value2 = value2 + (500  * (section.count("cmd.exe")))
        if "passwd" in section:
            value2 = value2 + (400  * (section.count("passwd")))
        if "'" in section:
            value2 = value2 + (20  * (section.count("'")))
        if "%27" in section:
            value2 = value2 + (20  * (section.count("%27")))
        if "UNION" in section:
            value2 = value2 + (200  * (section.count("UNION")))
        if "SELECT" in section:
            value2 = value2 + (500  * (section.count("SELECT")))
        if "*" in section:
            value2 = value2 + (10  * (section.count("*")))
        if "SLEEP(" in section:
            value2 = value2 + (500  * (section.count("SLEEP")))
            global responseValue
            responseValue = 1
        if "BENCHMARK" in section:
            value2 = value2 + (300  * (section.count("BENCHMARK")))
        if "@@version" in section:
            value2 = value2 + (500  * (section.count("@@version")))
        if ";" in section:
            value2 = value2 + (500  * (section.count(";")))
        if "../" in section:
            value2 = value2 + (500  * (section.count("../")))
        if "WAIT FOR DELAY" in section:
            value2 = value2 + (300  * (section.count("WAIT FOR DELAY")))
    
    return value2

# function to base64 decode URL params to see if someone is hiding an attack
#    ToDo - make this more efficent, and add more char checks
def v3base64(self):
    print("[]Inspection for hiding attacks with base64")
    value3 = 0
    uri = self.path.split("=")
    for section in uri:
        try:
            if "<" in base64.b64decode(section).decode(): 
               decodeval = base64.b64decode(section).decode()
               value3 = value3 + (200  * (decodeval.count("<")))
            if ">" in base64.b64decode(section).decode(): 
               decodeval = base64.b64decode(section).decode()
               value3 = value3 + (200  * (decodeval.count(">")))
        except Exception:
            print("[]ERROR: base64 deocde error on value = ", section)
    return value3

def v4POSTdata(self): 
    value4 = 0
    try:
        content_length = int(self.headers.get('Content-Length'))
        section = self.rfile.read(content_length).decode()
        print("[]POST DATA parsing")
        print("[]POST payload value = ",section)
        if "[" in section:
            value4 = value4 + (1 * (section.count("[")))
        if '"' in section:
            value4 = value4 + (2 * (section.count('"')))
        if "]" in section:
            value4 = value4 + (1  * (section.count("]")))
        if "(" in section:
            value4 = value4 + (40  * (section.count("(")))
        if ")" in section:
            value4 = value4 + (40  * (section.count(")")))
        if "{" in section: 
            value4 = value4 + (40  * (section.count("{")))
        if "}" in section:
            value4 = value4 + (40  * (section.count("}")))
        if "%3C" in section:
            value4 = value4 + (200  * (section.count("%3C")))
        if "<" in section:
            value4 = value4 + (200  * (section.count("<")))
        if ">" in section:
            value4 = value4 + (200  * (section.count(">")))
        if "%3E" in section:
            value4 = value4 + (200  * (section.count("%3E")))
        if "bin/bash" in section:
            value4 = value4 + (500  * (section.count("/bin/bash")))
        if "cmd.exe" in section:
            value4 = value4 + (500  * (section.count("cmd.exe")))
        if "passwd" in section:
            value4 = value4 + (400  * (section.count("passwd")))
        if "'" in section:
            value4 = value4 + (20  * (section.count("'")))
        if "%27" in section:
            value4 = value4 + (20  * (section.count("%27")))
        if "UNION" in section:
            value4 = value4 + (200  * (section.count("UNION")))
        if "SELECT" in section:
            value4 = value4 + (500  * (section.count("SELECT")))
        if "*" in section:
            value4 = value4 + (10  * (section.count("*")))
        if "SLEEP(" in section:
            value4 = value4 + (500  * (section.count("SLEEP")))
        if "BENCHMARK" in section:
            value4 = value4 + (300  * (section.count("BENCHMARK")))
        if "@@version" in section:
            value4 = value4 + (500  * (section.count("@@version")))
        if ";" in section:
            value4 = value4 + (500  * (section.count(";")))
        if "../" in section:
            value4 = value4 + (500  * (section.count("../")))
    except Exception:
        print("[]POST parse fail")
    return value4
    
    
def v5HostHeader(self):
    value5 = 0
    try:
        if self.headers['Host'] :
            print("[]Host Header Detected")
            if self.headers['Host'] not in sitelist:
                print("[]Host header not matching siteList")
                value5 = 1
            else:
                print("[]Host header value found in siteList")
        else:
            print("[]Host header not found")
    except:
        print("[]Error parsing Host Header Found")
    return value5

#def v6UserAgent(self):

#def v7OtherHeaders(self):

#def v8UserHistory(?):

#def blockResponse(?):

####################################################
# The WAF decision function based on the parsing output
####################################################

# Function used  for AI WAF decision making. 
def waf(self):
    decision = "Allow"
    #each data
    
    v1 = v1Method(self)
    v2 = v2URI(self)
    v3 = v3base64(self)
#    v3 = 0
    v4 = v4POSTdata(self)
#    v4 = 34
#    v5 = 0
    v5 = v5HostHeader(self)
    v6 = 32.6
    v7 = 0.627
    v8 = 50
    A = [[v1,v2,v3,v4,v5,v6,v7,v8,1]]
    #convert the list into a numpy array
    A = array(A)
    #slice the data to feed the neural network
    B = A[:,0:8]
    C = A[:,8]
    predictions = (model.predict(B) > 0.5).astype(int)
    print('%s => %d (expected %d if it was an attack)' % (B[0].tolist(), predictions[0], C[0]))
    if predictions[0] == 1 :
        decision = "Deny"
    print("waf decision = ",decision)
# if training Method used, send WAF parsing details to training data file
    try:
        if TrainingID in self.headers['Training_Attack'] :
            print("[]Attack Training data detected")
            file1 = open("tensortestdata.txt", "a")
            file1.write("\n")
            addvalue = "%s,%s,%s,%s,%s,%s,%s,%s,1" % (v1,v2,v3,v4,v5,v6,v7,v8)
            file1.write(addvalue)
            file1.close()
    except:
        print("[]No Training_Attack header found")
    try:    
        if TrainingID in self.headers['Training_Valid'] :
            print("[]Valid Training data detected")
            file2 = open("tensortestdata.txt", "a")
            file2.write("\n")
            addvalue = "%s,%s,%s,%s,%s,%s,%s,%s,0" % (v1,v2,v3,v4,v5,v6,v7,v8)
            file2.write(addvalue)
            file2.close()
    except:
        print("[]No Training_Valid header found")
    return decision

####################################################
# The Web Server section. 
####################################################

def webServerHandler(self):
    serverVersion = ['Nginx 13.45', 'Apache Tomcat version 7.9', '7331 Server v.8.6.7.5309', 'StuffServer Version 4.4']
    self.server_version = random.choice(serverVersion)
    self.sys_version = ""
    response = [1,2,3]
#   Looking for training data, and if you see it, add it to training data file.
#   But check to see if the request has the key in the headers.
    file_to_open = "initialization"
    if self.path == '/':
        self.path = '/index.html'
    try:
        #check the WAF decision
        if waf(self) == "Allow":
            filepath = webroot + self.path[1:]
            print(filepath)
            file_to_open = open(filepath).read()
            self.send_response(200)
        else:
            # send responses.  If "Deny" from WAF, send random response 
            # SQLi confusion attack
#            print("[] Response Value = ",responseValue)
#            if responseValue == 1:
#                sleep(8)  #sleep to confuse SQLi
            responseChoice = random.choice(response)
            if responseChoice == 1:
                file_to_open = "Stop right there!!"
                self.send_response(404)
            if responseChoice == 2:
                self.path = '/index.html'
                file_to_open = open(self.path[1:]).read()
                self.send_response(200)
            if responseChoice == 3:
                self.send_response(302)
                responseRedirect = '%s%s'%('http://yahoo.com', self.path)
                self.send_header('Location', responseRedirect)
    except:
        file_to_open = "File not found"
        self.send_response(404)
    self.send_header("Test", "1.2.3")
    self.end_headers()
    self.wfile.write(bytes(file_to_open, 'utf-8'))
    
    
#Main web server class
class Serv(BaseHTTPRequestHandler):

    def do_GET(self):
        webServerHandler(self)
    
    def do_POST(self):
        webServerHandler(self)

    def do_OPTIONS(self):
        webServerHandler(self)
    
    def do_PUT(self):
        webServerHandler(self)
    
    def do_DELETE(self):
        webServerHandler(self)
    
    def do_TRACK(self):
        webServerHandler(self)
    
    def do_TRACE(self):
        webServerHandler(self)
        
    def do_HEAD(self):
        webServerHandler(self)
    
    def do_CONNECT(self):
        webServerHandler(self)
    

# just a loop to run the web server forever
httpd = HTTPServer(('localhost', 8080), Serv)
httpd.serve_forever()
