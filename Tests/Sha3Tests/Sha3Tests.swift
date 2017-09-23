//
//  Sha3.swift
//  Sha3
//
//  Created by Bernardo Breder on 17/01/17.
//
//

import XCTest
import Foundation
@testable import Sha3

class Sha3Tests: XCTestCase {

	func test() throws {
        let str = "Hello, playground"
        let data = str.data(using: .utf8)!
        let bytes = [UInt8](data)
        XCTAssertEqual(32, SHA3(variant: SHA3.Variant.sha256).calculate(for: bytes).count)
	}
    
    func testSha1() {
        let token = UUID().uuidString
        let message = token + ":" + "username" + ":" + "password"
        let data = message.data(using: .utf8)!
        let sha = Data(bytes: SHA3(variant: .sha256).calculate(for: [UInt8](data)))
        let base64 = sha.base64EncodedString()
        XCTAssertEqual(44, base64.characters.count)
    }

}

