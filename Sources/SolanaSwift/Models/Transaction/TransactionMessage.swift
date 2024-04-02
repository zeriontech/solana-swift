import Foundation

public struct TransactionMessage {
    public var instructions: [TransactionInstruction]
    public var recentBlockhash: String
    public var payerKey: PublicKey

    public init(instructions: [TransactionInstruction], recentBlockhash: String, payerKey: PublicKey) {
        self.instructions = instructions
        self.recentBlockhash = recentBlockhash
        self.payerKey = payerKey
    }

    public static func decompile(message: VersionedMessage, addressLookupTableAccounts: [AddressLookupTableAccount]) throws -> Self {
        let header = message.header
        let compiledInstructions = message.compiledInstructions
        let recentBlockhash = message.recentBlockhash
        
        let numRequiredSignatures = header.numRequiredSignatures
        let numReadonlySignedAccounts = header.numReadonlySignedAccounts
        let numReadonlyUnsignedAccounts = header.numReadonlyUnsignedAccounts
        
        let numWritableSignedAccounts = numRequiredSignatures - numReadonlySignedAccounts
        guard numWritableSignedAccounts > 0 else {
            throw TransactionMessageError.invalidHeader
        }
        
        let numWritableUnsignedAccounts = message.staticAccountKeys.count - numRequiredSignatures - numReadonlyUnsignedAccounts
        guard numWritableUnsignedAccounts >= 0 else {
            throw TransactionMessageError.invalidHeader
        }
        
        guard let accountKeys = try? message.getAccountKeys(addressLookupTableAccounts: addressLookupTableAccounts) else {
            throw TransactionMessageError.noAccountKeys
        }
        
        guard let payerKey = accountKeys[0] else {
            throw TransactionMessageError.noPayerKey
        }
        
        var instructions: [TransactionInstruction] = []
        for compiledIx in compiledInstructions {
            var keys: [AccountMeta] = []
            for keyIndex in compiledIx.accountKeyIndexes {
                guard let pubkey = accountKeys[Int(keyIndex)] else {
                    throw TransactionMessageError.keyNotFound
                }
                
                let isSigner = keyIndex < numRequiredSignatures
                let isWritable: Bool
                if isSigner {
                    isWritable = keyIndex < numWritableSignedAccounts
                } else if keyIndex < accountKeys.staticAccountKeys.count {
                    isWritable = Int(keyIndex) - numRequiredSignatures < numWritableUnsignedAccounts
                } else {
                    let writableCount = accountKeys.accountKeysFromLookups!.writable.count
                    isWritable = Int(keyIndex) - accountKeys.staticAccountKeys.count < writableCount
                }
                
                keys.append(AccountMeta(publicKey: pubkey, isSigner: isSigner, isWritable: isWritable))
            }
            
            guard let programId = accountKeys[Int(compiledIx.programIdIndex)] else {
                throw TransactionMessageError.programIdNotFound
            }
            
            instructions.append(TransactionInstruction(keys: keys, programId: programId, data: compiledIx.data))
        }
        
        return TransactionMessage(instructions: instructions, recentBlockhash: recentBlockhash, payerKey: payerKey)
    }

    public func compileToLegacyMessage() throws -> Message {
        try Transaction(
            instructions: instructions,
            recentBlockhash: recentBlockhash,
            feePayer: payerKey
        )
        .compileMessage()
    }

    public func compileToV0Message(
        addressLookupTableAccounts: [AddressLookupTableAccount]? = nil
    ) throws -> MessageV0 {
        try MessageV0.compile(
            payerKey: payerKey,
            instructions: instructions,
            recentBlockHash: recentBlockhash,
            addressLookupTableAccounts: addressLookupTableAccounts
        )
    }
}

public enum TransactionMessageError: Error, Equatable {
    case invalidHeader
    case noAccountKeys
    case noPayerKey
    case keyNotFound
    case programIdNotFound
}
