from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
import subprocess
import json

#for some reason if i have these as class members, they get overwritten all the time
nonce = ""
cnonce = ""

#The password of your device. TODO: make this configurable in burb
PASSWORD = "insert your password here"

#Taken from the javascript of the device, seems to always be bcswebapp1234567
IV = "bcswebapp1234567"

#since jython does not support pycrodome library, we have to use a separate script for encryption, and decryption.
def run_external(payload):
    proc = subprocess.Popen(payload,stdout=subprocess.PIPE)
    output = proc.stdout.read().strip()
    proc.stdout.close()
    return output

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Reolink AES decryptor")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return AesDecryptTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#

class AesDecryptTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
    def getTabCaption(self):
        return "Decrypted body"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        return True
        
    def setMessage(self, content, isRequest):
        global nonce
        global cnonce
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            #get info about the request
            analyzedRequest = self._extender._helpers.analyzeRequest(content)
            
            #find the offset of the body so we can extract it
            body_offset = analyzedRequest.getBodyOffset()

            body = self._extender._helpers.bytesToString(content)[body_offset:]
            #check for nonce and cnonce in the json, which means you are at the login screen
            #set the values in global variables
            try:
                x = json.loads(body)
                self.nonce = x[0]["param"]["Digest"]["Nonce"]
                self.cnonce = x[0]["param"]["Digest"]["Cnonce"]
                nonce = x[0]["param"]["Digest"]["Nonce"]
                cnonce = x[0]["param"]["Digest"]["Cnonce"]
            except:
                print("no json")
            #decrypt the body with external script
            args = ["python", "command_line_decrypt.py",PASSWORD, nonce, cnonce, IV, "True", body]
            decrypt = run_external(args)
            
            if len(decrypt) > 5:
                self._txtInput.setText(decrypt)
                self._txtInput.setEditable(self._editable)
        # remember the displayed content
        self._currentMessage = content
    
    def getMessage(self):
        # determine whether the user modified the deserialized data
        if self._txtInput.isTextModified():
            modifiedBody = self._txtInput.getText()
            modifiedBody  = self._extender._helpers.bytesToString(self._txtInput.getText())
            
            #encrypt the message again if its been modified
            args = ["python", "command_line_decrypt.py",PASSWORD, self.nonce, self.cnonce, IV, "False", modifiedBody]
            decrypt = run_external(args)

            currentAnalyzed = self._extender._helpers.analyzeRequest(self._currentMessage)
            body_offset = currentAnalyzed.getBodyOffset()
            current_without_message = self._extender._helpers.bytesToString(self._currentMessage)[:body_offset]
            updated_request = current_without_message + decrypt
            self._currentMessage = self._extender._helpers.stringToBytes(updated_request)

        return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
