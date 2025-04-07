// Copyright 2024 LY Corporation
//
// LY Corporation licenses this file to you under the Apache License,
// version 2.0 (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at:
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

import Foundation
import LocalAuthentication

public final class KeyStorage {
    private let keychain: KeychainProtocol
    private var access: SecAccessControl?

    init(_ type: AuthenticatorType, keychain: KeychainProtocol = Keychain()) {
        self.keychain = keychain
        let accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        switch type {
        case .biometric:
            access = SecAccessControlCreateWithFlags(nil, accessibility, .biometryCurrentSet, nil)
        case .deviceCredential:
            access = SecAccessControlCreateWithFlags(nil, accessibility, .userPresence, nil)
        }
    }

    func load(_ kid: String, context: LAContext? = nil) -> Result<SecKey?, KeyStorageError> {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: kid,
            kSecReturnRef as String: true
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var queryResult: AnyObject?
        let keychainResponse = keychain.get(query)
        queryResult = keychainResponse.queryResult
        let status = keychainResponse.status
        guard status != errSecItemNotFound else {
            return .success(nil)
        }
        guard status == errSecSuccess else {
            return .failure(.loadFailed(status: status))
        }
        guard let item = queryResult else {
            return .failure(.invalidItemFound)
        }
        return .success((item as! SecKey))
    }

    func store(_ id: String, key: SecKey, context: LAContext? = nil) -> Result<(), KeyStorageError> {
        let result = load(id, context: context)
        switch result {
        case .failure(let error):
            return .failure(error)
        case .success(let val):
            if let _ = val {
                var query: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrLabel as String: id
                ]
                if let context {
                    query[kSecUseAuthenticationContext as String] = context
                }
                let attributes: [String: Any] = [kSecValueRef as String: key]
                let status = keychain.update(query, with: attributes)
                guard status == errSecSuccess else {
                    return .failure(.updateFailed(status: status))
                }
            } else {
                guard let access = access else {
                    return .failure(.accessFailed)
                }
                var query: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrLabel as String: id,
                    kSecAttrAccessControl as String: access,
                    kSecValueRef as String: key
                ]
                if let context {
                    query[kSecUseAuthenticationContext as String] = context
                }
                let status = keychain.add(query)
                guard status == errSecSuccess else {
                    return .failure(.storeFailed(status: status))
                }
            }
            return .success(())
        }
    }

    func delete(_ id: String) -> Result<(), KeyStorageError> {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: id
        ]
        let status = keychain.delete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            return .failure(.deleteFailed(status: status))
        }
        return .success(())
    }
}
