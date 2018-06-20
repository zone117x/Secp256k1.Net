﻿using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Secp256k1Net.Interop;

namespace Secp256k1Net
{
    public unsafe class Secp256k1 : IDisposable
    {
        public IntPtr Context => _ctx;

        IntPtr _ctx;

        public const int SERIALIZED_PUBKEY_LENGTH = 65;
        public const int PUBKEY_LENGTH = 64;
        public const int PRIVKEY_LENGTH = 32;
        public const int UNSERIALIZED_SIGNATURE_SIZE = 65;
        public const int SERIALIZED_SIGNATURE_SIZE = 64;

        public Secp256k1()
        {
            _ctx = secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// Recover an ECDSA public key from a signature.
        /// </summary>
        /// <param name="publicKeyOutput">Output for the 64 byte recovered public key to be written to.</param>
        /// <param name="signature">The initialized signature that supports pubkey recovery.</param>
        /// <param name="message">The 32-byte message hash assumed to be signed.</param>
        /// <returns>
        /// True if the public key successfully recovered (which guarantees a correct signature).
        /// </returns>
        public bool EcdsaRecover(Span<byte> publicKeyOutput, Span<byte> signature, Span<byte> message)
        {
            if (publicKeyOutput.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKeyOutput)} must be {PUBKEY_LENGTH} bytes");
            }
            if (signature.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signature)} must be {UNSERIALIZED_SIGNATURE_SIZE} bytes");
            }
            if (message.Length < 32)
            {
                throw new ArgumentException($"{nameof(message)} must be 32 bytes");
            }

            var publicKeyPtr = Unsafe.AsPointer(ref publicKeyOutput[0]);
            var sigPtr = Unsafe.AsPointer(ref signature[0]);
            var msgPtr = Unsafe.AsPointer(ref message[0]);
            var result = secp256k1_ecdsa_recover(_ctx, publicKeyPtr, sigPtr, msgPtr);

            // Verify we succeeded
            return result == 1;
        }

        /// <summary>
        /// Gets the public key for a given private key.
        /// </summary>
        /// <param name="publicKeyOutput">Output for the 64 byte recovered public key to be written to.</param>
        /// <param name="privateKeyInput">The input private key to obtain the public key for.</param>
        /// <returns>
        /// True if the private key is valid and public key was obtained.
        /// </returns>
        public bool EcdsaGetPublicKey(Span<byte> publicKeyOutput, Span<byte> privateKeyInput)
        {
            if (publicKeyOutput.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKeyOutput)} must be {PUBKEY_LENGTH} bytes");
            }
            if (privateKeyInput.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(privateKeyInput)} must be {PRIVKEY_LENGTH} bytes");
            }

            var pubKeyPtr = Unsafe.AsPointer(ref publicKeyOutput[0]);
            var privKeyPtr = Unsafe.AsPointer(ref privateKeyInput[0]);
            var result = secp256k1_ec_pubkey_create(_ctx, pubKeyPtr, privKeyPtr);

            // Verify we succeeded
            return result == 1;
        }

        /// <summary>
        /// Parse a compact ECDSA signature (64 bytes + recovery id).
        /// </summary>
        /// <param name="signatureOutput">Output for the signature to be written to.</param>
        /// <param name="compactSignature">The 64-byte compact signature input.</param>
        /// <param name="recoveryID">The recovery id (0, 1, 2 or 3).</param>
        /// <returns>True when the signature could be parsed.</returns>
        public bool EcdsaRecoverableSignatureParseCompact(Span<byte> signatureOutput, Span<byte> compactSignature, int recoveryID)
        {
            if (signatureOutput.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be 64 bytes");
            }
            if (compactSignature.Length < SERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(compactSignature)} must be 64 bytes");
            }

            var sigPtr = Unsafe.AsPointer(ref signatureOutput[0]);
            var intputPtr = Unsafe.AsPointer(ref compactSignature[0]);
            var result = secp256k1_ecdsa_recoverable_signature_parse_compact(_ctx, sigPtr, intputPtr, recoveryID);

            return result == 1;
        }

        /// <summary>
        /// Create a recoverable ECDSA signature.
        /// </summary>
        /// <param name="signatureOutput">Output where the signature will be placed.</param>
        /// <param name="messageHash">The 32-byte message hash being signed.</param>
        /// <param name="secretKey">A 32-byte secret key.</param>
        /// <returns>
        /// True if signature created, false if the nonce generation function failed, or the private key was invalid.
        /// </returns>
        public bool EcdsaSignRecoverable(Span<byte> signatureOutput, Span<byte> messageHash, Span<byte> secretKey)
        {
            if (signatureOutput.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be 65 bytes");
            }
            if (messageHash.Length < 32)
            {
                throw new ArgumentException($"{nameof(messageHash)} must be 32 bytes");
            }
            if (secretKey.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(secretKey)} must be 32 bytes");
            }

            var sigPtr = Unsafe.AsPointer(ref signatureOutput[0]);
            var msgPtr = Unsafe.AsPointer(ref messageHash[0]);
            var secPtr = Unsafe.AsPointer(ref secretKey.Slice(secretKey.Length - 32)[0]);
            var result = secp256k1_ecdsa_sign_recoverable(_ctx, sigPtr, msgPtr, secPtr, IntPtr.Zero, IntPtr.Zero);

            // Verify we didn't fail.
            return result == 1;
        }


        /// <summary>
        /// Serialize an ECDSA signature in compact format (64 bytes + recovery id).
        /// </summary>
        /// <param name="compactSignatureOutput">Output for the 64-byte array of the compact signature.</param>
        /// <param name="recoveryID">The recovery ID.</param>
        /// <param name="signature">The initialized signature.</param>
        public bool EcdsaRecoverableSignatureSerializeCompact(Span<byte> compactSignatureOutput, out int recoveryID, byte[] signature)
        {
            if (compactSignatureOutput.Length < SERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(compactSignatureOutput)} must be {SERIALIZED_SIGNATURE_SIZE} bytes");
            }
            if (signature.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signature)} must be {UNSERIALIZED_SIGNATURE_SIZE} bytes");
            }

            int recID = 0;
            var compactSigPtr = Unsafe.AsPointer(ref compactSignatureOutput[0]);
            var sigPtr = Unsafe.AsPointer(ref signature[0]);
            var result = secp256k1_ecdsa_recoverable_signature_serialize_compact(_ctx, compactSigPtr, ref recID, sigPtr);
            recoveryID = recID;

            return result == 1;
        }

        /// <summary>
        /// Serialize a pubkey object into a serialized byte sequence.
        /// </summary>
        /// <param name="serializedPublicKeyOutput">65-byte (if compressed==0) or 33-byte (if compressed==1) output to place the serialized key in.</param>
        /// <param name="publicKey">The secp256k1_pubkey initialized public key.</param>
        /// <param name="flags">SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.</param>
        public bool EcdsaPublicKeySerialize(Span<byte> serializedPublicKeyOutput, Span<byte> publicKey, Flags flags = Flags.SECP256K1_EC_UNCOMPRESSED)
        {
            if (serializedPublicKeyOutput.Length < SERIALIZED_PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(serializedPublicKeyOutput)} must be {SERIALIZED_PUBKEY_LENGTH} bytes");
            }
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }
            var serializedPtr = Unsafe.AsPointer(ref serializedPublicKeyOutput[0]);
            var pubKeyPtr = Unsafe.AsPointer(ref publicKey[0]);

            uint newLength = SERIALIZED_PUBKEY_LENGTH;
            var result = secp256k1_ec_pubkey_serialize(_ctx, serializedPtr, ref newLength, pubKeyPtr, (uint)flags);
            return result == 1 && newLength == SERIALIZED_PUBKEY_LENGTH;
        }


        public void Dispose()
        {
            if (_ctx != IntPtr.Zero)
            {
                secp256k1_context_destroy(_ctx);
                _ctx = IntPtr.Zero;
            }
        }



    }
}