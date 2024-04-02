import Foundation

public protocol IMessage {
    var version: TransactionVersion { get }
    var header: MessageHeader { get }
    var recentBlockhash: String { get }
    var staticAccountKeys: [PublicKey] { get }

    func serialize() throws -> Data
    func getAccountKeys(addressLookupTableAccounts: [AddressLookupTableAccount]) throws -> MessageAccountKeys
}
