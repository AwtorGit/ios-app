import AuthenticationServices
import GoogleSignIn

typealias Extension = (String, ViewController,
                       @escaping (String?, String?) -> ()) -> ();

var extensions: [String: Extension] = [
    "signIn": signIn,
];

enum LoginError: Error {
    case reject(String)
}
extension String: Error {}

func signIn(_ provider: String, ctrl: ViewController, completion: @escaping (User?, String?) -> ()) -> () {
    switch provider{
    case "apple":
        authApple(ctrl: ctrl, completion: completion)
        break
    case "google":
        authGoogle(ctrl: ctrl, completion: completion)
        break
    default:
        completion("", "Sign in with \(provider) is not implemented")
        break
    }
}

struct User : Encodable{
    var firstName: String?
    var lastName: String?
    var idToken: String?
}

func authGoogle(ctrl: ViewController, completion: @escaping (String?, String?) -> ()) -> () {
    GIDSignIn.sharedInstance.signIn(withPresenting: ctrl) { (result, error) in
        if error != nil {
            completion("", error?.localizedDescription)
            return
        }
        let user = User()
        user.idToken = result?.user.idToken?.tokenString
        let jsonData = try JSONEncoder().encode(user)
        let jsonString = String(data: jsonData, encoding: .utf8)
        completion(jsonString, nil)
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
    func handler(user: User?, error: String?) {
        let jsonData = try JSONEncoder().encode(user)
        let jsonString = String(data: jsonData, encoding: .utf8)
        completion(jsonString, error)
    }
    complitionHandler = handler
}

var complitionHandler: ((User?, String?)->())?

@available(iOS 13.0, *)
extension ViewController: ASAuthorizationControllerDelegate {
    
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            return
        }
        let user = User()
        user.idToken = String(data: appleIDCredential.identityToken!, encoding: .utf8)
        user.firstName = appleIDCredential.fullName?.givenName
        user.lastName = appleIDCredential.fullName?.familyName
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
