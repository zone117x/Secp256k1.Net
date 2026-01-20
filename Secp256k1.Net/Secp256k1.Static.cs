using System;
using System.Security.Cryptography;

namespace Secp256k1Net
{
    public partial class Secp256k1
    {
        [ThreadStatic]
        private static Secp256k1 _instance;

        /// <summary>
        /// Gets a thread-local instance with its own context and error callback.
        /// Each thread gets an isolated context. Do not dispose this instance.
        /// </summary>
        private static Secp256k1 Instance => _instance ??= new Secp256k1();

        #region Static Helper Methods

        /// <summary>
        /// Generates a new random secret key using a cryptographically secure random number generator.
        /// </summary>
        /// <returns>32-byte secret key.</returns>
        public static byte[] CreateSecretKey()
        {
            var secretKey = new byte[SECRET_LENGTH];
            using var rng = RandomNumberGenerator.Create();
            while (true)
            {
                rng.GetBytes(secretKey);
                if (IsValidSecretKey(secretKey))
                    return secretKey;
            }
        }

        /// <summary>
        /// Creates a serialized public key from a secret key.
        /// </summary>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <param name="compressed">If true, returns 33-byte compressed format; otherwise 65-byte uncompressed.</param>
        /// <returns>Serialized public key (33 or 65 bytes).</returns>
        /// <exception cref="ArgumentException">Thrown when the secret key is invalid.</exception>
        public static byte[] CreatePublicKey(ReadOnlySpan<byte> secretKey, bool compressed = true)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyCreate(pubkeyInternal, secretKey))
                throw new ArgumentException("Invalid secret key", nameof(secretKey));

            var outputLen = compressed ? SERIALIZED_COMPRESSED_PUBKEY_LENGTH : SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            var result = new byte[outputLen];
            var len = (nuint)outputLen;
            var flags = compressed ? Secp256k1EcFlags.Compressed : Secp256k1EcFlags.Uncompressed;
            Instance.EcPubkeySerialize(result, ref len, pubkeyInternal, flags);
            return result;
        }

        /// <summary>
        /// Creates a serialized x-only public key from a secret key.
        /// </summary>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <returns>Tuple of 32-byte x-only public key and parity (0 or 1).</returns>
        /// <exception cref="ArgumentException">Thrown when the secret key is invalid.</exception>
        public static (byte[] XOnlyPublicKey, byte Parity) CreateXOnlyPublicKey(ReadOnlySpan<byte> secretKey)
        {
            const int KEYPAIR_LENGTH = 96;
            const int XONLY_PUBKEY_LENGTH = 64;
            const int XONLY_SERIALIZED_LENGTH = 32;

            Span<byte> keypair = stackalloc byte[KEYPAIR_LENGTH];
            if (!Instance.KeypairCreate(keypair, secretKey))
                throw new ArgumentException("Invalid secret key", nameof(secretKey));

            Span<byte> xonlyInternal = stackalloc byte[XONLY_PUBKEY_LENGTH];
            Instance.KeypairXonlyPub(xonlyInternal, out int parity, keypair);

            var result = new byte[XONLY_SERIALIZED_LENGTH];
            Instance.XonlyPubkeySerialize(result, xonlyInternal);
            return (result, (byte)parity);
        }

        /// <summary>
        /// Creates a new key pair (secret key and public key).
        /// </summary>
        /// <param name="compressed">If true, returns 33-byte compressed public key; otherwise 65-byte uncompressed.</param>
        /// <returns>Tuple of 32-byte secret key and serialized public key.</returns>
        public static (byte[] SecretKey, byte[] PublicKey) CreateKeyPair(bool compressed = true)
        {
            var secretKey = CreateSecretKey();
            var publicKey = CreatePublicKey(secretKey, compressed);
            return (secretKey, publicKey);
        }
        
        /// <summary>
        /// Verifies that a secret key is valid.
        /// </summary>
        /// <param name="secretKey">32-byte secret key to validate.</param>
        /// <returns>True if the secret key is valid, false otherwise.</returns>
        public static bool IsValidSecretKey(ReadOnlySpan<byte> secretKey)
        {
            if (secretKey.Length < SECRET_LENGTH)
                return false;
            return Instance.EcSeckeyVerify(secretKey);
        }

        /// <summary>
        /// Verifies that a serialized public key is valid.
        /// </summary>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <returns>True if the public key is valid, false otherwise.</returns>
        public static bool IsValidPublicKey(ReadOnlySpan<byte> publicKey)
        {
            if (publicKey.Length != SERIALIZED_COMPRESSED_PUBKEY_LENGTH &&
                publicKey.Length != SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH)
                return false;

            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            return Instance.EcPubkeyParse(pubkeyInternal, publicKey);
        }

        /// <summary>
        /// Compresses a public key to 33-byte format.
        /// </summary>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <returns>33-byte compressed public key.</returns>
        /// <exception cref="ArgumentException">Thrown when the public key is invalid.</exception>
        public static byte[] CompressPublicKey(ReadOnlySpan<byte> publicKey)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                throw new ArgumentException("Invalid public key", nameof(publicKey));

            var result = new byte[SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
            var len = (nuint)SERIALIZED_COMPRESSED_PUBKEY_LENGTH;
            Instance.EcPubkeySerialize(result, ref len, pubkeyInternal, Secp256k1EcFlags.Compressed);
            return result;
        }

        /// <summary>
        /// Decompresses a public key to 65-byte uncompressed format.
        /// </summary>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <returns>65-byte uncompressed public key.</returns>
        /// <exception cref="ArgumentException">Thrown when the public key is invalid.</exception>
        public static byte[] DecompressPublicKey(ReadOnlySpan<byte> publicKey)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                throw new ArgumentException("Invalid public key", nameof(publicKey));

            var result = new byte[SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            var len = (nuint)SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            Instance.EcPubkeySerialize(result, ref len, pubkeyInternal, Secp256k1EcFlags.Uncompressed);
            return result;
        }

        /// <summary>
        /// Creates an ECDSA signature in compact format.
        /// </summary>
        /// <param name="messageHash">32-byte message hash to sign.</param>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <returns>64-byte compact signature.</returns>
        /// <exception cref="ArgumentException">Thrown when signing fails (invalid secret key or nonce generation failure).</exception>
        public static byte[] Sign(ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> secretKey)
        {
            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            if (!Instance.EcdsaSign(sigInternal, messageHash, secretKey))
                throw new ArgumentException("Signing failed - invalid secret key or nonce generation failure");

            var result = new byte[SERIALIZED_SIGNATURE_SIZE];
            Instance.EcdsaSignatureSerializeCompact(result, sigInternal);
            return result;
        }

        /// <summary>
        /// Verifies an ECDSA signature.
        /// </summary>
        /// <param name="signature">64-byte compact signature.</param>
        /// <param name="messageHash">32-byte message hash that was signed.</param>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> publicKey)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                return false;

            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            if (!Instance.EcdsaSignatureParseCompact(sigInternal, signature))
                return false;

            return Instance.EcdsaVerify(sigInternal, messageHash, pubkeyInternal);
        }

        /// <summary>
        /// Creates a recoverable ECDSA signature.
        /// </summary>
        /// <param name="messageHash">32-byte message hash to sign.</param>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <returns>Tuple of 64-byte compact signature and recovery ID (0-3).</returns>
        /// <exception cref="ArgumentException">Thrown when signing fails.</exception>
        public static (byte[] Signature, byte RecoveryId) SignRecoverable(ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> secretKey)
        {
            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_SIZE];
            if (!Instance.EcdsaSignRecoverable(sigInternal, messageHash, secretKey))
                throw new ArgumentException("Signing failed - invalid secret key or nonce generation failure");

            var signature = new byte[SERIALIZED_SIGNATURE_SIZE];
            Instance.EcdsaRecoverableSignatureSerializeCompact(signature, out int recid, sigInternal);
            return (signature, (byte)recid);
        }

        /// <summary>
        /// Recovers a public key from a recoverable ECDSA signature.
        /// </summary>
        /// <param name="signature">64-byte compact signature.</param>
        /// <param name="recoveryId">Recovery ID (0-3).</param>
        /// <param name="messageHash">32-byte message hash that was signed.</param>
        /// <param name="compressed">If true, returns 33-byte compressed format; otherwise 65-byte uncompressed.</param>
        /// <returns>Serialized public key (33 or 65 bytes).</returns>
        /// <exception cref="ArgumentException">Thrown when recovery fails.</exception>
        public static byte[] RecoverPublicKey(ReadOnlySpan<byte> signature, byte recoveryId, ReadOnlySpan<byte> messageHash, bool compressed = true)
        {
            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_SIZE];
            if (!Instance.EcdsaRecoverableSignatureParseCompact(sigInternal, signature, recoveryId))
                throw new ArgumentException("Invalid signature or recovery ID");

            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcdsaRecover(pubkeyInternal, sigInternal, messageHash))
                throw new ArgumentException("Public key recovery failed");

            var outputLen = compressed ? SERIALIZED_COMPRESSED_PUBKEY_LENGTH : SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            var result = new byte[outputLen];
            var len = (nuint)outputLen;
            var flags = compressed ? Secp256k1EcFlags.Compressed : Secp256k1EcFlags.Uncompressed;
            Instance.EcPubkeySerialize(result, ref len, pubkeyInternal, flags);
            return result;
        }

        /// <summary>
        /// Computes an ECDH shared secret.
        /// </summary>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <returns>32-byte shared secret.</returns>
        /// <exception cref="ArgumentException">Thrown when the public key is invalid or ECDH computation fails.</exception>
        public static byte[] ComputeSharedSecret(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> secretKey)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                throw new ArgumentException("Invalid public key", nameof(publicKey));

            var result = new byte[SECRET_LENGTH];
            if (!Instance.Ecdh(result, pubkeyInternal, secretKey))
                throw new ArgumentException("ECDH computation failed - invalid secret key");

            return result;
        }

        /// <summary>
        /// Creates a Schnorr signature (BIP-340).
        /// For variable-length messages, use <see cref="TaggedHash"/> to create a 32-byte hash with domain separation.
        /// </summary>
        /// <param name="messageHash">32-byte message hash to sign. Use <see cref="TaggedHash"/> to hash variable-length messages.</param>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <param name="auxRand">Optional 32 bytes of auxiliary randomness. If null, zeros are used.</param>
        /// <param name="verify">If true (default), verifies the signature after signing to strictly follow BIP-340. Set to false for better performance when verification is not required.</param>
        /// <returns>64-byte Schnorr signature.</returns>
        /// <exception cref="ArgumentException">Thrown when signing or verification fails.</exception>
        public static byte[] SignSchnorr(ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> auxRand = default, bool verify = true)
        {
            const int KEYPAIR_LENGTH = 96;
            const int XONLY_PUBKEY_LENGTH = 64;

            if (messageHash.Length != 32)
                throw new ArgumentException($"Message hash must be exactly 32 bytes. Use {nameof(TaggedHash)}() to create a 32-byte hash with domain separation for variable-length messages.", nameof(messageHash));

            Span<byte> keypair = stackalloc byte[KEYPAIR_LENGTH];
            if (!Instance.KeypairCreate(keypair, secretKey))
                throw new ArgumentException("Invalid secret key", nameof(secretKey));

            Span<byte> auxRandActual = stackalloc byte[32];
            if (!auxRand.IsEmpty)
            {
                if (auxRand.Length < 32)
                    throw new ArgumentException("Auxiliary randomness must be at least 32 bytes", nameof(auxRand));
                auxRand.Slice(0, 32).CopyTo(auxRandActual);
            }

            var signature = new byte[SERIALIZED_SIGNATURE_SIZE];
            if (!Instance.SchnorrsigSign32(signature, messageHash, keypair, auxRandActual))
                throw new ArgumentException("Schnorr signing failed");

            if (verify)
            {
                Span<byte> xonlyPubkey = stackalloc byte[XONLY_PUBKEY_LENGTH];
                Instance.KeypairXonlyPub(xonlyPubkey, out _, keypair);
                if (!Instance.SchnorrsigVerify(signature, messageHash, xonlyPubkey))
                    throw new ArgumentException("Schnorr signature verification failed");
            }

            return signature;
        }

        /// <summary>
        /// Verifies a Schnorr signature (BIP-340).
        /// </summary>
        /// <param name="signature">64-byte Schnorr signature.</param>
        /// <param name="message">Message that was signed (variable length).</param>
        /// <param name="publicKey">Public key in any format: 32-byte x-only, 33-byte compressed, or 65-byte uncompressed.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        /// <exception cref="ArgumentException">Thrown when the public key format is invalid.</exception>
        public static bool VerifySchnorr(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
        {
            const int XONLY_PUBKEY_LENGTH = 64;

            Span<byte> xonlyInternal = stackalloc byte[XONLY_PUBKEY_LENGTH];

            if (publicKey.Length == 32)
            {
                // X-only public key
                if (!Instance.XonlyPubkeyParse(xonlyInternal, publicKey))
                    throw new ArgumentException("Invalid x-only public key", nameof(publicKey));
            }
            else if (publicKey.Length == 33 || publicKey.Length == 65)
            {
                // Compressed or uncompressed public key - parse and convert to x-only
                Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
                if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                    throw new ArgumentException("Invalid public key", nameof(publicKey));
                Instance.XonlyPubkeyFromPubkey(xonlyInternal, out _, pubkeyInternal);
            }
            else
            {
                throw new ArgumentException("Public key must be 32 bytes (x-only), 33 bytes (compressed), or 65 bytes (uncompressed)", nameof(publicKey));
            }

            return Instance.SchnorrsigVerify(signature, message, xonlyInternal);
        }

        /// <summary>
        /// Converts a compact signature to DER format.
        /// </summary>
        /// <param name="compactSignature">64-byte compact signature.</param>
        /// <returns>DER-encoded signature (up to 72 bytes).</returns>
        /// <exception cref="ArgumentException">Thrown when the signature is invalid.</exception>
        public static byte[] SignatureToDer(ReadOnlySpan<byte> compactSignature)
        {
            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            if (!Instance.EcdsaSignatureParseCompact(sigInternal, compactSignature))
                throw new ArgumentException("Invalid compact signature", nameof(compactSignature));

            Span<byte> derBuffer = stackalloc byte[SERIALIZED_DER_SIGNATURE_MAX_SIZE];
            var derLen = (nuint)SERIALIZED_DER_SIGNATURE_MAX_SIZE;
            if (!Instance.EcdsaSignatureSerializeDer(derBuffer, ref derLen, sigInternal))
                throw new ArgumentException("Failed to serialize signature to DER format");

            return derBuffer.Slice(0, (int)derLen).ToArray();
        }

        /// <summary>
        /// Converts a DER-encoded signature to compact format.
        /// </summary>
        /// <param name="derSignature">DER-encoded signature.</param>
        /// <returns>64-byte compact signature.</returns>
        /// <exception cref="ArgumentException">Thrown when the signature is invalid.</exception>
        public static byte[] SignatureFromDer(ReadOnlySpan<byte> derSignature)
        {
            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            if (!Instance.EcdsaSignatureParseDer(sigInternal, derSignature))
                throw new ArgumentException("Invalid DER signature", nameof(derSignature));

            var result = new byte[SERIALIZED_SIGNATURE_SIZE];
            Instance.EcdsaSignatureSerializeCompact(result, sigInternal);
            return result;
        }

        /// <summary>
        /// Verifies an ECDSA signature in DER format.
        /// </summary>
        /// <param name="derSignature">DER-encoded signature.</param>
        /// <param name="messageHash">32-byte message hash that was signed.</param>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static bool VerifyDer(ReadOnlySpan<byte> derSignature, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> publicKey)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                return false;

            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            if (!Instance.EcdsaSignatureParseDer(sigInternal, derSignature))
                return false;

            return Instance.EcdsaVerify(sigInternal, messageHash, pubkeyInternal);
        }

        /// <summary>
        /// Normalizes a signature to lower-S form.
        /// </summary>
        /// <param name="signature">64-byte compact signature.</param>
        /// <returns>Normalized 64-byte compact signature in lower-S form.</returns>
        /// <exception cref="ArgumentException">Thrown when the signature is invalid.</exception>
        public static byte[] NormalizeSignature(ReadOnlySpan<byte> signature)
        {
            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            if (!Instance.EcdsaSignatureParseCompact(sigInternal, signature))
                throw new ArgumentException("Invalid signature", nameof(signature));

            Span<byte> normalizedInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            Instance.EcdsaSignatureNormalize(normalizedInternal, sigInternal);

            var result = new byte[SERIALIZED_SIGNATURE_SIZE];
            Instance.EcdsaSignatureSerializeCompact(result, normalizedInternal);
            return result;
        }

        /// <summary>
        /// Checks if a signature is in normalized lower-S form.
        /// </summary>
        /// <param name="signature">64-byte compact signature.</param>
        /// <returns>True if the signature is already normalized, false if it needed normalization.</returns>
        /// <exception cref="ArgumentException">Thrown when the signature is invalid.</exception>
        public static bool IsNormalizedSignature(ReadOnlySpan<byte> signature)
        {
            Span<byte> sigInternal = stackalloc byte[UNSERIALIZED_SIGNATURE_LENGTH];
            if (!Instance.EcdsaSignatureParseCompact(sigInternal, signature))
                throw new ArgumentException("Invalid signature", nameof(signature));

            // EcdsaSignatureNormalize returns true (1) if the signature was NOT normalized
            // Returns false (0) if it was already normalized
            return !Instance.EcdsaSignatureNormalize(Span<byte>.Empty, sigInternal);
        }

        /// <summary>
        /// Tweaks a secret key by adding a tweak value to it.
        /// Used in BIP-32 HD wallet derivation.
        /// </summary>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <param name="tweak">32-byte tweak value.</param>
        /// <returns>32-byte tweaked secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the secret key or tweak is invalid.</exception>
        public static byte[] TweakSecretKeyAdd(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> tweak)
        {
            var result = new byte[SECRET_LENGTH];
            secretKey.Slice(0, SECRET_LENGTH).CopyTo(result);

            if (!Instance.EcSeckeyTweakAdd(result, tweak))
                throw new ArgumentException("Invalid secret key or tweak");

            return result;
        }

        /// <summary>
        /// Tweaks a public key by adding tweak times the generator to it.
        /// Used in BIP-32 HD wallet derivation.
        /// </summary>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <param name="tweak">32-byte tweak value.</param>
        /// <param name="compressed">If true, returns 33-byte compressed format; otherwise 65-byte uncompressed.</param>
        /// <returns>Serialized tweaked public key.</returns>
        /// <exception cref="ArgumentException">Thrown when the public key or tweak is invalid.</exception>
        public static byte[] TweakPublicKeyAdd(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> tweak, bool compressed = true)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                throw new ArgumentException("Invalid public key", nameof(publicKey));

            if (!Instance.EcPubkeyTweakAdd(pubkeyInternal, tweak))
                throw new ArgumentException("Invalid tweak", nameof(tweak));

            var outputLen = compressed ? SERIALIZED_COMPRESSED_PUBKEY_LENGTH : SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            var result = new byte[outputLen];
            var len = (nuint)outputLen;
            var flags = compressed ? Secp256k1EcFlags.Compressed : Secp256k1EcFlags.Uncompressed;
            Instance.EcPubkeySerialize(result, ref len, pubkeyInternal, flags);
            return result;
        }

        /// <summary>
        /// Computes a tagged hash as defined in BIP-340.
        /// Returns SHA256(SHA256(tag) || SHA256(tag) || message).
        /// </summary>
        /// <param name="tag">Tag bytes for domain separation.</param>
        /// <param name="message">Message to hash.</param>
        /// <returns>32-byte hash.</returns>
        public static byte[] TaggedHash(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message)
        {
            var result = new byte[HASH_LENGTH];
            Instance.TaggedSha256(result, tag, message);
            return result;
        }

        /// <summary>
        /// Negates a secret key in place.
        /// </summary>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <returns>32-byte negated secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the secret key is invalid.</exception>
        public static byte[] NegateSecretKey(ReadOnlySpan<byte> secretKey)
        {
            var result = new byte[SECRET_LENGTH];
            secretKey.Slice(0, SECRET_LENGTH).CopyTo(result);

            if (!Instance.EcSeckeyNegate(result))
                throw new ArgumentException("Invalid secret key", nameof(secretKey));

            return result;
        }

        /// <summary>
        /// Negates a public key.
        /// </summary>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <param name="compressed">If true, returns 33-byte compressed format; otherwise 65-byte uncompressed.</param>
        /// <returns>Serialized negated public key.</returns>
        /// <exception cref="ArgumentException">Thrown when the public key is invalid.</exception>
        public static byte[] NegatePublicKey(ReadOnlySpan<byte> publicKey, bool compressed = true)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                throw new ArgumentException("Invalid public key", nameof(publicKey));

            Instance.EcPubkeyNegate(pubkeyInternal);

            var outputLen = compressed ? SERIALIZED_COMPRESSED_PUBKEY_LENGTH : SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            var result = new byte[outputLen];
            var len = (nuint)outputLen;
            var flags = compressed ? Secp256k1EcFlags.Compressed : Secp256k1EcFlags.Uncompressed;
            Instance.EcPubkeySerialize(result, ref len, pubkeyInternal, flags);
            return result;
        }

        /// <summary>
        /// Tweaks a secret key by multiplying it by a tweak value.
        /// </summary>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <param name="tweak">32-byte tweak value.</param>
        /// <returns>32-byte tweaked secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the secret key or tweak is invalid.</exception>
        public static byte[] TweakSecretKeyMul(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> tweak)
        {
            var result = new byte[SECRET_LENGTH];
            secretKey.Slice(0, SECRET_LENGTH).CopyTo(result);

            if (!Instance.EcSeckeyTweakMul(result, tweak))
                throw new ArgumentException("Invalid secret key or tweak");

            return result;
        }

        /// <summary>
        /// Tweaks a public key by multiplying it by a tweak value.
        /// </summary>
        /// <param name="publicKey">Serialized public key (33 or 65 bytes).</param>
        /// <param name="tweak">32-byte tweak value.</param>
        /// <param name="compressed">If true, returns 33-byte compressed format; otherwise 65-byte uncompressed.</param>
        /// <returns>Serialized tweaked public key.</returns>
        /// <exception cref="ArgumentException">Thrown when the public key or tweak is invalid.</exception>
        public static byte[] TweakPublicKeyMul(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> tweak, bool compressed = true)
        {
            Span<byte> pubkeyInternal = stackalloc byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyParse(pubkeyInternal, publicKey))
                throw new ArgumentException("Invalid public key", nameof(publicKey));

            if (!Instance.EcPubkeyTweakMul(pubkeyInternal, tweak))
                throw new ArgumentException("Invalid tweak", nameof(tweak));

            var outputLen = compressed ? SERIALIZED_COMPRESSED_PUBKEY_LENGTH : SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            var result = new byte[outputLen];
            var len = (nuint)outputLen;
            var flags = compressed ? Secp256k1EcFlags.Compressed : Secp256k1EcFlags.Uncompressed;
            Instance.EcPubkeySerialize(result, ref len, pubkeyInternal, flags);
            return result;
        }

        /// <summary>
        /// Combines multiple public keys into a single public key by adding them together.
        /// Useful for multisig and key aggregation schemes.
        /// </summary>
        /// <param name="publicKeys">Array of serialized public keys (each 33 or 65 bytes).</param>
        /// <param name="compressed">If true, returns 33-byte compressed format; otherwise 65-byte uncompressed.</param>
        /// <returns>Serialized combined public key.</returns>
        /// <exception cref="ArgumentException">Thrown when any public key is invalid or combination fails.</exception>
        public static byte[] CombinePublicKeys(byte[][] publicKeys, bool compressed = true)
        {
            if (publicKeys == null || publicKeys.Length == 0)
                throw new ArgumentException("At least one public key is required", nameof(publicKeys));

            // Parse all public keys to internal format
            var internalKeys = new byte[publicKeys.Length][];
            for (int i = 0; i < publicKeys.Length; i++)
            {
                internalKeys[i] = new byte[UNSERIALIZED_PUBKEY_LENGTH];
                if (!Instance.EcPubkeyParse(internalKeys[i], publicKeys[i]))
                    throw new ArgumentException($"Invalid public key at index {i}", nameof(publicKeys));
            }

            var combinedInternal = new byte[UNSERIALIZED_PUBKEY_LENGTH];
            if (!Instance.EcPubkeyCombine(combinedInternal, internalKeys))
                throw new ArgumentException("Failed to combine public keys - result may be point at infinity");

            var outputLen = compressed ? SERIALIZED_COMPRESSED_PUBKEY_LENGTH : SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            var result = new byte[outputLen];
            var len = (nuint)outputLen;
            var flags = compressed ? Secp256k1EcFlags.Compressed : Secp256k1EcFlags.Uncompressed;
            Instance.EcPubkeySerialize(result, ref len, combinedInternal, flags);
            return result;
        }

        #endregion
    }
}
