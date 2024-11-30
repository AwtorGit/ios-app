import AuthenticationServices
import GoogleSignIn

typealias Extension = (Any, ViewController,
                       @escaping (String?, String?) -> ()) -> ();

var extensions: [String: Extension] = [
    "signIn": signIn,
];

enum LoginError: Error {
    case reject(String)
}
extension String: Error {}

func signIn(_ provider: String, ctrl: ViewController, completion: @escaping (String?, String?) -> ()) -> () {
    switch provider{
    case "apple":
        
        let authorizationProvider = ASAuthorizationAppleIDProvider()
        let currentUser = KeyChain.load(key: "user")
        if currentUser != nil {
            let userId = String(data: currentUser!, encoding: .utf8)
            authorizationProvider.getCredentialState(forUserID: userId!) { (state, error) in
                switch state {
                case .authorized:
                    let data = KeyChain.load(key: "userData");
                    let dataString = String(data: data!, encoding: .utf8)
                    completion(dataString, "")
                    break
                default:
                    authApple(ctrl: ctrl, completion: completion)
                    break
                }
            }
        } else {
            authApple(ctrl: ctrl, completion: completion)
        }
        break
    case "google":
        GIDSignIn.sharedInstance.signIn(withPresenting: ctrl) { (result, error) in
            if error != nil {
                completion("", error?.localizedDescription)
                return
            }
            completion(result?.user.accessToken, nil)
        }
        break
    default:
        completion("", "Sign in with \(provider) is not implemented")
        break
    }
}
func authApple(ctrl: ViewController, completion: @escaping (String?, String?) -> ()) -> () {
    let authorizationProvider = ASAuthorizationAppleIDProvider()
    let request = authorizationProvider.createRequest()
    request.requestedScopes = [.email, .fullName]
    let authorizationController = ASAuthorizationController(authorizationRequests: [request])
    authorizationController.delegate = ctrl
    authorizationController.presentationContextProvider = ctrl
    authorizationController.performRequests()
    func handler(user: AppleUser?, error: String?) {
        if (user == nil){
            completion("", error)
            return
        }
        do {
            let jsonData = try JSONEncoder().encode(user)
            KeyChain.save(key: "userData", data: jsonData)
            let jsonString = String(data: jsonData, encoding: .utf8)
            completion(jsonString, "")
        } catch {
            completion("", "error")
        }
    }
    complitionHandler = handler
}


struct AppleUser : Encodable{
    var email: String?
    var fName: String?
    var lName: String?
    var identifier = ""
    var authorizationCode: Data? = nil
    var idToken: Data? = nil
}
var complitionHandler: ((AppleUser?, String?)->())?

@available(iOS 13.0, *)
extension ViewController: ASAuthorizationControllerDelegate {
    
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            return
        }
        print("AppleID Credential Authorization: userId: \(appleIDCredential.user), email: \(String(describing: appleIDCredential.email)),  name: \(String(describing: appleIDCredential.fullName))")
        
        KeyChain.save(key: "user", data: appleIDCredential.user.data(using: .utf8)!)
        
        var user =  AppleUser()
        user.email = appleIDCredential.email
        user.fName = appleIDCredential.fullName?.givenName
        user.lName = appleIDCredential.fullName?.familyName
        user.identifier = appleIDCredential.user
        user.authorizationCode = appleIDCredential.authorizationCode
        user.idToken = appleIDCredential.identityToken
        complitionHandler?(user, nil)
        
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        complitionHandler?(nil, error.localizedDescription)
        print("AppleID Credential failed with error: \(error.localizedDescription)")
        
    }
}
    
    @available(iOS 13.0, *)
    extension ViewController: ASAuthorizationControllerPresentationContextProviding {
        func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
            return self.webviewView.window!
        }
    }
    
    // Keychain Extension to store user data on first use.
    
    class KeyChain {
        class func save(key: String, data: Data) -> OSStatus {
            let query = [
                kSecClass as String       : kSecClassGenericPassword as String,
                kSecAttrAccount as String : key,
                kSecValueData as String   : data ] as [String : Any]
            
            SecItemDelete(query as CFDictionary)
            
            return SecItemAdd(query as CFDictionary, nil)
        }
        
        class func load(key: String) -> Data? {
            let query = [
                kSecClass as String       : kSecClassGenericPassword,
                kSecAttrAccount as String : key,
                kSecReturnData as String  : kCFBooleanTrue!,
                kSecMatchLimit as String  : kSecMatchLimitOne ] as [String : Any]
            
            var dataTypeRef: AnyObject? = nil
            
            let status: OSStatus = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
            
            if status == noErr {
                return dataTypeRef as! Data?
            } else {
                return nil
            }
        }
        
        class func createUniqueID() -> String {
            let uuid: CFUUID = CFUUIDCreate(nil)
            let cfStr: CFString = CFUUIDCreateString(nil, uuid)
            
            let swiftString: String = cfStr as String
            return swiftString
        }
    }
    
    extension Data {
        
        init<T>(from value: T) {
            var value = value
            self.init(buffer: UnsafeBufferPointer(start: &value, count: 1))
        }
        
        func to<T>(type: T.Type) -> T {
            return self.withUnsafeBytes { $0.load(as: T.self) }
        }
    }
