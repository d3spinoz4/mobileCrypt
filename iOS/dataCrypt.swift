//
//  dataCrypt.swift
//  WildFi
//
//  Created by David Espinoza on 5/28/22.
//

import Foundation
import CommonCrypto
import CryptoKit
import OSLog

protocol Cryptable {
    func encrypt(_ string: String, keyString: String) throws -> String
    func decrypt(_ data: String, keyString: String) throws -> String
}

struct AESCrypt {
    private let key: Data

    init(keyString: String) throws {
        guard keyString.count == kCCKeySizeAES256 else {
            throw Error.invalidKeySize
        }
        self.key = AESCrypt.pbkdf2(password: keyString, saltData: AESCrypt.generateRandomBytes()!, keyByteCount: 32, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: 65536)!
    }

    private static func pbkdf2(password: String, saltData: Data, keyByteCount: Int, prf: CCPseudoRandomAlgorithm, rounds: Int) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        let derivedCount = derivedKeyData.count
        let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            let keyBuffer: UnsafeMutablePointer<UInt8> =
                derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return saltData.withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    passwordData.count,
                    saltBuffer,
                    saltData.count,
                    prf,
                    UInt32(rounds),
                    keyBuffer,
                    derivedCount)
            }
        }
        return derivationStatus == kCCSuccess ? derivedKeyData : nil
    }
}

extension AESCrypt {
    enum Error: Swift.Error {
        case invalidKeySize
        case generateRandomIVFailed
        case encryptionFailed
        case decryptionFailed
        case dataToStringFailed
    }
}

private extension AESCrypt {

    private static func generateRandomBytes() -> Data? {

        var keyData = Data(count: 32)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return keyData
        } else {
            os_log("%{public}@", "\nWild-Fi-Log: Problem generating random bytes")
            return nil
        }
    }
}

extension AESCrypt: Cryptable {
    
    func encrypt(_ string: String, keyString: String) throws -> String {
        
        let saltd = AESCrypt.generateRandomBytes()!
        let kay = AESCrypt.pbkdf2(password: keyString, saltData: saltd, keyByteCount: 32, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: 65536)!
        
        let iv = AES.GCM.Nonce()
        let sealedBox = try! AES.GCM.seal(string.data(using: .utf8)!, using: SymmetricKey(data: kay), nonce: iv)

        let separator = ":"
        let saltbase64 = saltd.base64EncodedString()
        let nonceb64 = Data(iv).base64EncodedString()
        let combox = sealedBox.ciphertext.base64EncodedString()
        let gcmtag = sealedBox.tag.base64EncodedString()
        let allstring = saltbase64 + separator + nonceb64 + separator + combox + separator + gcmtag
        return allstring
    }

    func decrypt(_ data: String, keyString: String) throws -> String {

        let stringParts = data.split(separator: ":")
        let saltb64 = Data(base64Encoded: String(stringParts[0]))!
        let nonceb64 = try AES.GCM.Nonce(data: Data(base64Encoded: String(stringParts[1]))!)
        let cTextb64 = Data(base64Encoded: String(stringParts[2]))!
        let gcmtagb64 = Data(base64Encoded: String(stringParts[3]))!
        print(Data(base64Encoded: saltb64, options: Data.Base64DecodingOptions.ignoreUnknownCharacters) as Any)
        
        let kay = AESCrypt.pbkdf2(password: keyString, saltData: saltb64, keyByteCount: 32, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: 65536)!

        let sealedBoxRestored = try! AES.GCM.SealedBox(nonce: nonceb64, ciphertext: cTextb64, tag: gcmtagb64)
        let decrypted = try! AES.GCM.open(sealedBoxRestored, using: SymmetricKey(data: kay))

        return String(data: decrypted, encoding: .utf8)!
    }
}

class dataCrypt {
    
    func runEnCrypt(stringToEncrypt: String) -> String {
        do {
            let stringkii = (Bundle.main.infoDictionary?["API_KEY"] as? String)!
            let aes = try AESCrypt(keyString: stringkii)

            let encryptedData: String = try aes.encrypt(stringToEncrypt, keyString: stringkii)
            return encryptedData

        } catch {
            os_log("%{public}@", "\nWild-Fi-Log:  \(String(describing: error))")
            return "Something went wrong: \(error)"
        }
    }
    
    func runDeCrypt(stringData: String) -> String {
        do {
            let stringkii = (Bundle.main.infoDictionary?["API_KEY"] as? String)!
            let aes = try AESCrypt(keyString: stringkii)

            let decryptedData: String = try aes.decrypt(stringData, keyString: stringkii)
            return decryptedData

        } catch {
            os_log("%{public}@", "\nWild-Fi-Log:  \(String(describing: error))")
            return "Something went wrong: \(error)"
        }
    }
}
