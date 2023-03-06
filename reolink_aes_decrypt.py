from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
import subprocess
import json

# nonce = ""
# cnonce = ""
#should be configured in burp
# PASSWORD = "carlerkul2"
PASSWORD = "fredrikerkulere"
IV = "bcswebapp1234567"

#since jython does not support pycrodome library, we have to use a separate script for encryption, and decryption.
def run_external(payload):
    #https://github.com/externalist/aes-encrypt-decrypt-burp-extender-plugin-example
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
        self.nonce = ""
        self.cnonce = ""
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "Decrypted body"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing a data parameter
        return True
        # return isRequest and not self._extender._helpers.getRequestParameter(content, "data") is None
        
    def setMessage(self, content, isRequest):
        if not isRequest:
            print("not request!!!", self._extender._helpers.bytesToString(content))
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            analyzedRequest = self._extender._helpers.analyzeRequest(content)
            
            body_offset = analyzedRequest.getBodyOffset()

            body = self._extender._helpers.bytesToString(content)[body_offset:]
            try:
                x = json.loads(body)
                self.nonce = x[0]["param"]["Digest"]["Nonce"]
                self.cnonce = x[0]["param"]["Digest"]["Cnonce"]
                print("nonce and cnonce have been set", self.nonce, self.cnonce)
            except:
                print("Could not find json")
            print("Nonce, Cnonce:", self.nonce, self.cnonce)
            args = ["python", "command_line_decrypt.py",PASSWORD, self.nonce, self.cnonce, IV, "True", body]
            print("args: ", args)
            decrypt = run_external(args)
            print("decrypt request: ", decrypt)
            if len(decrypt) > 5:
                self._txtInput.setText(decrypt)
                self._txtInput.setEditable(self._editable)
        # remember the displayed content
        self._currentMessage = content
    
    def getMessage(self):
        # determine whether the user modified the deserialized data
        print("getmessage()")
        if self._txtInput.isTextModified():
            print("getmess inni")
            modifiedBody = self._txtInput.getText()
            print("hvordan ser denne ut?", modifiedBody)
            modifiedBody  = self._extender._helpers.bytesToString(self._txtInput.getText())
            
            # input = self._extender._helpers.urlEncode(self._extender._helpers.base64Encode(text))
            #base64 encode first, so nullbytes are not lost in translation
            # modifiedBody = base64.b64encode(modifiedBody)
            # print(modifiedBody)
            args = ["python", "command_line_decrypt.py",PASSWORD, self.nonce, self.cnonce, IV, "False", modifiedBody]
            print("args encrypt ", args)
            decrypt = run_external(args)
            print("encrypted request: ", decrypt)
            # update the request with the new parameter value
            currentAnalyzed = self._extender._helpers.analyzeRequest(self._currentMessage)
            body_offset = currentAnalyzed.getBodyOffset()
            current_without_message = self._extender._helpers.bytesToString(self._currentMessage)[:body_offset]
            updated_request = current_without_message + decrypt
            print("updated: ", updated_request)
            self._currentMessage = self._extender._helpers.stringToBytes(updated_request)

        return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
