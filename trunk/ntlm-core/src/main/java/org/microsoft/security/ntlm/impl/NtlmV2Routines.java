/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.MessageDigest;

import static org.microsoft.security.ntlm.impl.Algorithms.ASCII_ENCODING;
import static org.microsoft.security.ntlm.impl.Algorithms.ByteArray;
import static org.microsoft.security.ntlm.impl.Algorithms.UNICODE_ENCODING;
import static org.microsoft.security.ntlm.impl.Algorithms.calculateMD5;
import static org.microsoft.security.ntlm.impl.Algorithms.concat;
import static org.microsoft.security.ntlm.impl.Algorithms.createHmacMD5;
import static org.microsoft.security.ntlm.impl.Algorithms.createMD4;
import static org.microsoft.security.ntlm.impl.Algorithms.createRC4;
import static org.microsoft.security.ntlm.impl.Algorithms.intToBytes;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_128;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_56;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_KEY_EXCH;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.randomDataProvider;

/**
 *
 * How NTLM version is detected: http://davenport.sourceforge.net/ntlm.html#ntlmVersion2
 * Also NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is used to negotiate
 *
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class NtlmV2Routines {

    /*
Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(
    MD4(UNICODE(Passwd)), ConcatenationOf( Uppercase(User),
    UserDom ) )
EndDefine

Define LMOWFv2(Passwd, User, UserDom) as NTOWFv2(Passwd, User,
    UserDom)
EndDefine

Set ResponseKeyNT to NTOWFv2(Passwd, User, UserDom)
Set ResponseKeyLM to LMOWFv2(Passwd, User, UserDom)
     */
    public static byte[] calculateNTOWFv2(String domain, String username, String password) {
        try {
            MessageDigest md4 = createMD4();
            md4.update(password.getBytes(UNICODE_ENCODING));

            Mac hmacMD5 = createHmacMD5(md4.digest());
            hmacMD5.update(username.toUpperCase().getBytes(UNICODE_ENCODING));
            hmacMD5.update(domain.getBytes(UNICODE_ENCODING));
            return hmacMD5.doFinal();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

/*
    private static final org.apache.log4j.Logger log = org.apache.log4j.Logger.getLogger("colt-test.NTLMAuthentication");
    public static byte[] calculateNTLMv2(byte[] ntowfv2, ByteArray serverChallenge, ByteArray time, byte[] clientChallengeArray, ByteArray targetInfo) {
        log.trace("  lm.2-ntowfv2-0: " + bytesToString(ntowfv2));
        byte[] responseKeyNT = ntowfv2;
        byte[] responseKeyLM = ntowfv2;
        ByteArray clientChallenge = new ByteArray(clientChallengeArray);

        byte[] temp2 = concat(serverChallenge, ALL_RESPONSER_VERSION, Z(6), time, clientChallenge, Z(4)
                , targetInfo, Z(4));
        ByteArray temp = new ByteArray(temp2, 8, temp2.length - serverChallenge.getLength()); // temp2 without server challenge
        log.trace("Temp2:" + bytesToString(temp2));

        byte[] ntProofStr = calculateHmacMD5(responseKeyNT, new ByteArray(temp2));
        byte[] ntChallengeResponse = concat(new ByteArray(ntProofStr), temp);


/ *
    Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
            ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
        ClientChallenge )

 * /
        byte[] lmChallengeResponse = concat(new ByteArray(
                calculateHmacMD5(responseKeyLM, new ByteArray(concat(serverChallenge, clientChallenge))))
                , clientChallenge);
        byte[] sessionBaseKey = calculateHmacMD5(responseKeyNT, new ByteArray(ntProofStr));

        log.trace("ntProofStr:" + bytesToString(ntProofStr));
        log.trace("ntChallengeResponse:" + bytesToString(ntChallengeResponse));
        log.trace("lmChallengeResponse:" + bytesToString(lmChallengeResponse));
        log.trace("sessionBaseKey:" + bytesToString(sessionBaseKey));

        return null;
    }
*/

    /*
3.4 Session Security Details

Note In connectionless mode, messages can arrive out of order. Because of this, the sealing key
MUST be reset for every message. Rekeying with the same sealing key for multiple messages would
not maintain message security. Therefore, a per-message sealing key, SealingKey', is computed as
the MD5 hash of the original sealing key and the message sequence number. The resulting
SealingKey' value is used to reinitialize the key state structure prior to invoking the following SIGN,
SEAL, and MAC algorithms. To compute the SealingKey' and initialize the key state structure
identified by the Handle parameter, use the following:

SealingKey' = MD5(ConcatenationOf(SealingKey, SequenceNumber))
RC4Init(Handle, SealingKey')

     */
    public static Cipher reinitSealingKey(byte[] sealingKey, int sequenceNumber) {
        byte[] concat = concat(sealingKey, intToBytes(sequenceNumber));
        return createRC4(calculateMD5(concat));
    }





    /*
    3.4.4 Message Signature Functions

     */


    public static byte[] mac(int negotiateFlags, int seqNum, byte[] signingKey, Cipher sealingKey, byte[] message) {
        return NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.isSet(negotiateFlags)
                ? macWithExtendedSessionSecurity(negotiateFlags, seqNum, signingKey, sealingKey, message)
                : macWithoutExtendedSessionSecurity(seqNum, message);
    }

    /*
3.4.4.1 Without Extended Session Security
When Extended Session Security (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) is not
negotiated and session security (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL) is
negotiated, the message signature for NTLM without extended session security is a 16-byte value
that contains the following components, as described by the NTLMSSP_MESSAGE_SIGNATURE
structure:
A 4-byte version-number value that is set to 1.
A 4-byte random pad.
The 4-bytes of the message's CRC32.
The 4-byte sequence number (SeqNum).
If message integrity is negotiated, the message signature is calculated as follows:
-- Input:
--  SigningKey - The key used to sign the message.
--  SealingKey - The key used to seal the message or checksum.
--  RandomPad - A random number provided by the client. Typically 0.
--  Message - The message being sent between the client and server.
--  SeqNum - Defined in section 3.1.1.
--  Handle - The handle to a key state structure corresponding to the
--  current state of the SealingKey
--
-- Output:
--  An NTLMSSP_MESSAGE_SIGNATURE structure whose fields are defined
    in section 2.2.2.9.
--  SeqNum - Defined in section 3.1.1.
--
-- Functions used:
--  ConcatenationOf() - Defined in Section 6.
--  RC4() - Defined in Section 6.
--  CRC32() - Defined in Section 6.
Define MAC(Handle, SigningKey, SeqNum, Message) as
    Set NTLMSSP_MESSAGE_SIGNATURE.Version to 0x00000001
    Set NTLMSSP_MESSAGE_SIGNATURE.Checksum to CRC32(Message)
    Set NTLMSSP_MESSAGE_SIGNATURE.RandomPad RC4(Handle, RandomPad)
    Set NTLMSSP_MESSAGE_SIGNATURE.Checksum to RC4(Handle, NTLMSSP_MESSAGE_SIGNATURE.Checksum)
    Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum to RC4(Handle, 0x00000000)
    If (connection oriented)
        Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum to
            NTLMSSP_MESSAGE_SIGNATURE.SeqNum XOR SeqNum
        Set SeqNum to SeqNum + 1
    Else
        Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum to
            NTLMSSP_MESSAGE_SIGNATURE.SeqNum XOR
            (application supplied SeqNum)
    Endif
    Set NTLMSSP_MESSAGE_SIGNATURE.RandomPad to 0
EndDefine

     */

    public static byte[] macWithoutExtendedSessionSecurity(int seqNum, byte[] message) {
        return null;
    }

    /*
3.4.4.2 With Extended Session Security
When Extended Session Security (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) is
negotiated and session security (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL) is
negotiated, the message signature for NTLM with extended session security is a 16-byte value that
contains the following components, as described by the NTLMSSP_MESSAGE_SIGNATURE structure:
A 4-byte version-number value that is set to 1.
The first eight bytes of the message's HMAC_MD5.
The 4-byte sequence number (SeqNum).
If message integrity is negotiated, the message signature is calculated as follows:
-- Input:
--  SigningKey - The key used to sign the message.
--  SealingKey - The key used to seal the message or checksum.
--  Message - The message being sent between the client and server.
--  SeqNum - Defined in section 3.1.1.
--  Handle - The handle to a key state structure corresponding to the
--          current state of the SealingKey
--
-- Output:
--  An NTLMSSP_MESSAGE_SIGNATURE structure whose fields are defined
    in section 2.2.2.9.
--  SeqNum - Defined in section 3.1.1.
--
-- Functions used:
--  ConcatenationOf() - Defined in Section 6.
--  RC4() - Defined in Section 6.
--  HMAC_MD5() - Defined in Section 6.

Define MAC(Handle, SigningKey, SeqNum, Message) as
    Set NTLMSSP_MESSAGE_SIGNATURE.Version to 0x00000001
    Set NTLMSSP_MESSAGE_SIGNATURE.Checksum to
        HMAC_MD5(SigningKey,
            ConcatenationOf(SeqNum, Message))[0..7]
    Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum to SeqNum
    Set SeqNum to SeqNum + 1
EndDefine


     */

    /*
If a key exchange key is negotiated, the message signature for the NTLM security service provider is
the same as in the preceding description, except the 8 bytes of the HMAC_MD5 are encrypted with
RC4, as follows:
Define MAC(Handle, SigningKey, SeqNum, Message) as
    Set NTLMSSP_MESSAGE_SIGNATURE.Version to 0x00000001
    Set NTLMSSP_MESSAGE_SIGNATURE.Checksum to RC4(Handle,
        HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7])
    Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum to SeqNum
    Set SeqNum to SeqNum + 1
EndDefine

     */

    private static final byte[] MAC_VERSION = {1, 0, 0, 0};
    public static byte[] macWithExtendedSessionSecurity(int negotiateFlags, int seqNum, byte[] signingKey, Cipher sealingKey, byte[] message) {
        Mac hmacMD5 = createHmacMD5(signingKey);
        hmacMD5.update(intToBytes(seqNum));
        hmacMD5.update(message);
        byte[] md5Result = hmacMD5.doFinal();
        ByteArray checksum;
        if (NTLMSSP_NEGOTIATE_KEY_EXCH.isSet(negotiateFlags)) {
            try {
                checksum = new ByteArray(sealingKey.doFinal(md5Result, 0, 8));
            } catch (Exception e) {
                throw new RuntimeException("Internal error", e);
            }
        } else {
            checksum = new ByteArray(md5Result, 0, 8);
        }
        return concat(MAC_VERSION, checksum, intToBytes(seqNum));
    }



    /*
If NTLM v2 is used, the key exchange key MUST be the 128-bit session base key.

     */
    public static byte[] kxkey(byte[] sessionBaseKey) {
        return sessionBaseKey;
    }


    /*
3.4.5.2 SIGNKEY
If extended session security is not negotiated (section 2.2.2.5), then no signing keys are available
and message signing is not supported.
If extended session security is negotiated, the signing key is a 128-bit value that is calculated as
follows from the random session key and the null-terminated ASCII constants shown.
-- Input:
--  RandomSessionKey - A randomly generated session key.
--  NegFlg - Defined in section 3.1.1.
--  Mode - An enum that defines the local machine performing
    the computation.
    Mode always takes the value "Client" or "Server.
--
-- Output:
--  SignKey - The key used for signing messages.
--
-- Functions used:
--  ConcatenationOf(), MD5(), NIL - Defined in Section 6.

Define SIGNKEY(NegFlg, RandomSessionKey, Mode) as
If (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is set in NegFlg)
    If (Mode equals "Client")
        Set SignKey to MD5(ConcatenationOf(RandomSessionKey,
            "session key to client-to-server signing key magic constant"))
    Else
        Set SignKey to MD5(ConcatenationOf(RandomSessionKey,
            "session key to server-to-client signing key magic constant"))
    Endif
Else
    Set SignKey to NIL
Endif
EndDefine

     */
    public enum SignkeyMode {
        client("session key to client-to-server signing key magic constant\0", "session key to client-to-server sealing key magic constant\0"),
        server("session key to server-to-client signing key magic constant\0", "session key to server-to-client sealing key magic constant\0");

        final ByteArray signingMagicString;
        final ByteArray sealingMagicString;

        SignkeyMode(String signingMagicString, String sealingMagicString) {
            this.signingMagicString = new ByteArray(signingMagicString.getBytes(ASCII_ENCODING));
            this.sealingMagicString = new ByteArray(sealingMagicString.getBytes(ASCII_ENCODING));
        }
    }

    public static byte[] signkey(int negotiateFlags, SignkeyMode mode, byte[] randomSessionKey) {
        if (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.isSet(negotiateFlags)) {
            byte[] signKey = calculateMD5(concat(randomSessionKey, mode.signingMagicString));
            return signKey;
        } else {
            return null;
        }
    }

    /*
3.4.5.3 SEALKEY
The sealing key function produces an encryption key from the random session key and the null-
terminated ASCII constants shown.
If extended session security is negotiated, the sealing key has either 40, 56, or 128 bits of
entropy stored in a 128-bit value.
If extended session security is not negotiated, the sealing key has either 40 or 56 bits of entropy
stored in a 64-bit value.
Note The MD5 hashes completely overwrite and fill the 64-bit or 128-bit value.
-- Input:
--  RandomSessionKey - A randomly generated session key.
--  NegFlg - Defined in section 3.1.1.
--  Mode - An enum that defines the local machine performing
    the computation.
    Mode always takes the value "Client" or "Server.
--
-- Output:
--  SealKey - The key used for sealing messages.
--
-- Functions used:
--  ConcatenationOf(), MD5() - Defined in Section 6.
Define SEALKEY(NegotiateFlags, RandomSessionKey, Mode) as
If (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is set in NegFlg)
    If ( NTLMSSP_NEGOTIATE_128 is set in NegFlg)
        Set SealKey to RandomSessionKey
    ElseIf ( NTLMSSP_NEGOTIATE_56 flag is set in NegFlg)
        Set SealKey to RandomSessionKey[0..6]
    Else
        Set SealKey to RandomSessionKey[0..4]
    Endif
    If (Mode equals "Client")
        Set SealKey to MD5(ConcatenationOf(SealKey, "session key to client-to-server sealing key magic constant"))
    Else
        Set SealKey to MD5(ConcatenationOf(SealKey, "session key to server-to-client sealing key magic constant"))
    Endif
ElseIf (NTLMSSP_NEGOTIATE_56 flag is set in NegFlg)
    Set SealKey to ConcatenationOf(RandomSessionKey[0..6], 0xA0)
Else
    Set SealKey to ConcatenationOf(RandomSessionKey[0..4], 0xE5, 0x38, 0xB0)
Endif
EndDefine

     */
    public static byte[] sealkey(int negotiateFlags, SignkeyMode mode, byte[] randomSessionKey) {
        byte[] sealKey;
        if (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.isSet(negotiateFlags)) {
            if (NTLMSSP_NEGOTIATE_128.isSet(negotiateFlags)) {
                sealKey = randomSessionKey;
            } else if (NTLMSSP_NEGOTIATE_56.isSet(negotiateFlags)) {
                sealKey = randomDataProvider.nonce(7);
            } else {
                sealKey = randomDataProvider.nonce(5);
            }
            sealKey = calculateMD5(concat(sealKey, mode.sealingMagicString));
        } else {
            sealKey = randomDataProvider.nonce(8);
            if (NTLMSSP_NEGOTIATE_56.isSet(negotiateFlags)) {
                sealKey[7] = (byte) 0xA0;
            } else {
                sealKey[5] = (byte) 0xE5;
                sealKey[6] = (byte) 0x38;
                sealKey[7] = (byte) 0xB0;
            }
        }
        return sealKey;
    }


}
