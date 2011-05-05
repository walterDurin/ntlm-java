/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import org.microsoft.security.ntlm.NtlmAuthenticator;
import org.microsoft.security.ntlm.NtlmSession;

import javax.crypto.Cipher;

import static org.microsoft.security.ntlm.NtlmAuthenticator.ConnectionType;
import static org.microsoft.security.ntlm.NtlmAuthenticator.WindowsVersion;
import static org.microsoft.security.ntlm.impl.Algorithms.ByteArray;
import static org.microsoft.security.ntlm.impl.Algorithms.calculateHmacMD5;
import static org.microsoft.security.ntlm.impl.Algorithms.calculateRC4K;
import static org.microsoft.security.ntlm.impl.Algorithms.concat;
import static org.microsoft.security.ntlm.impl.Algorithms.createRC4;
import static org.microsoft.security.ntlm.impl.Algorithms.intToBytes;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_56;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_KEY_EXCH;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_REQUEST_TARGET_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.Z;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.randomDataProvider;
import static org.microsoft.security.ntlm.impl.NtlmV2Routines.SignkeyMode;
import static org.microsoft.security.ntlm.impl.NtlmV2Routines.kxkey;
import static org.microsoft.security.ntlm.impl.NtlmV2Routines.mac;
import static org.microsoft.security.ntlm.impl.NtlmV2Routines.reinitSealingKey;
import static org.microsoft.security.ntlm.impl.NtlmV2Routines.sealkey;
import static org.microsoft.security.ntlm.impl.NtlmV2Routines.signkey;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class NtlmV2Session implements NtlmSession {

    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private static final byte[] WINDOWS_VERSION = WindowsVersion.Windows7.data;

    private NtlmAuthenticator.ConnectionType connectionType;
    private NtlmMessage authenticateMessage;

    private byte[] ntowfv2;
    private String hostname;
    private String domain;
    private String username;
    private byte[] negotiateMessageData;
    private byte[] ntChallengeResponse;
    private byte[] lmChallengeResponse;
    private byte[] clientChallenge;
    private byte[] sessionBaseKey;
    private int negotiateFlags;
    private byte[] exportedSessionKey;
    private byte[] encryptedRandomSessionKey;
    private byte[] clientSigningKey;
    private byte[] serverSigningKey;
    private byte[] clientSealingKey;
    private byte[] serverSealingKey;
    private Cipher clientSealingKeyCipher;
    private Cipher serverSealingKeyCipher;
    private int seqNum;

    public NtlmV2Session(ConnectionType connectionType, byte[] ntowfv2, String hostname, String domain, String username) {
        this.connectionType = connectionType;
        this.ntowfv2 = ntowfv2;
        this.hostname = hostname;
        this.domain = domain;
        this.username = username;

        if (connectionType == ConnectionType.connectionOriented) {
            negotiateFlags = NtlmAuthenticator.NEGOTIATE_FLAGS_CONN;
        }
    }

    @Override
    public byte[] generateNegotiateMessage() {
        if (connectionType == ConnectionType.connectionOriented) {
            NtlmMessage negotiateMessage = new NtlmMessage(1);
            negotiateMessage.appendPlain(intToBytes(negotiateFlags));
            negotiateMessage.appendStructure(domain);
            negotiateMessage.appendStructure(hostname);
            negotiateMessage.appendPlain(WINDOWS_VERSION);
            negotiateMessageData = negotiateMessage.getData();
        } else {
            negotiateMessageData = EMPTY_BYTE_ARRAY;
        }
        return EMPTY_BYTE_ARRAY;
    }


/*
3.1.5.1.2 Client Receives a CHALLENGE_MESSAGE from the Server
When the client receives a CHALLENGE_MESSAGE from the server, it MUST determine if the features
selected by the server are strong enough for the client authentication policy. If not, the client MUST
return an error to the calling application. Otherwise, the client responds with an
AUTHENTICATE_MESSAGE message.

If ClientRequire128bitEncryption == TRUE, then if 128-bit encryption is not negotiated, then the
client MUST return SEC_E_UNSUPPORTED_FUNCTION to the application.

The client processes the CHALLENGE_MESSAGE and constructs an AUTHENTICATE_MESSAGE per
the following pseudocode where all strings are encoded as RPC_UNICODE_STRING ([MS-DTYP]
section 2.3.8):

-- Input:
--  ClientConfigFlags, User, and UserDom - Defined in section 3.1.1.
--  NbMachineName - The NETBIOS machine name of the server.
--  An NTLM NEGOTIATE_MESSAGE whose fields are defined in
    section 2.2.1.2.
--  An NTLM CHALLENGE_MESSAGE whose message fields are defined in
    section 2.2.1.2.
--  An NTLM AUTHENTICATE_MESSAGE whose message fields are
    defined in section 2.2.1.3 with MIC field set to 0.
--  OPTIONAL ClientSuppliedTargetName - Defined in section 3.1.1.2
--  OPTIONAL ClientChannelBindingUnhashed - Defined in section 3.1.1.2
--
-- Output:
--  ClientHandle - The handle to a key state structure corresponding
    to the current state of the ClientSealingKey
--  ServerHandle - The handle to a key state structure corresponding
    to the current state of the ServerSealingKey
--  An NTLM AUTHENTICATE_MESSAGE whose message fields are defined in
    section 2.2.1.3.
--
--  The following NTLM keys generated by the client are defined in
    section 3.1.1:
--  ExportedSessionKey, ClientSigningKey, ClientSealingKey,
    ServerSigningKey, and ServerSealingKey.

-- Temporary variables that do not pass over the wire are defined
   below:
--  KeyExchangeKey, ResponseKeyNT, ResponseKeyLM, SessionBaseKey -
    Temporary variables used to store 128-bit keys.
--  Time - Temporary variable used to hold the 64-bit time.
--  MIC - message integrity for the NTLM NEGOTIATE_MESSAGE,
    CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE
--
-- Functions used:
--  NTOWFv1, LMOWFv1, NTOWFv2, LMOWFv2, ComputeResponse - Defined in
    section 3.3
--  KXKEY, SIGNKEY, SEALKEY - Defined in sections 3.4.5, 3.4.6,
    and 3.4.7
--  Currenttime, NIL, NONCE - Defined in section 6.


If NTLM v2 authentication is used and the CHALLENGE_MESSAGE does not contain both
MsvAvNbComputerName and MsvAvNbDomainName AVPairs and either Integrity is TRUE or
Confidentiality is TRUE, then return STATUS_LOGON_FAILURE.
If NTLM v2 authentication is used and the CHALLENGE_MESSAGE contains a TargetInfo field, the
client SHOULD NOT send the LmChallengeResponse and SHOULD set the LmChallengeResponseLen
and LmChallengeResponseMaxLen fields in the AUTHENTICATE_MESSAGE to zero. <41>
<41> Section 3.1.5.1.2: This functionality is not supported in Windows NT, Windows 2000,
Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008.

Response keys are computed using the ComputeResponse() function, as specified in section 3.3.

Set AUTHENTICATE_MESSAGE.NtChallengeResponse, AUTHENTICATE_MESSAGE.LmChallengeResponse, SessionBaseKey to
ComputeResponse(CHALLENGE_MESSAGE.NegotiateFlags, ResponseKeyNT, ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge,
        AUTHENTICATE_MESSAGE.ClientChallenge, Time, CHALLENGE_MESSAGE.TargetInfo)

Set KeyExchangeKey to KXKEY(SessionBaseKey, LmChallengeResponse, CHALLENGE_MESSAGE.ServerChallenge)
If (NTLMSSP_NEGOTIATE_KEY_EXCH bit is set in CHALLENGE_MESSAGE.NegotiateFlags )
    Set ExportedSessionKey to NONCE(16)
    Set AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey to
        RC4K(KeyExchangeKey, ExportedSessionKey)
Else
    Set ExportedSessionKey to KeyExchangeKey
    Set AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey to NIL
Endif

Set ClientSigningKey to SIGNKEY(NegFlg, ExportedSessionKey, "Client")
Set ServerSigningKey to SIGNKEY(NegFlg, ExportedSessionKey, "Server")
Set ClientSealingKey to SEALKEY(NegFlg, ExportedSessionKey, "Client")
Set ServerSealingKey to SEALKEY(NegFlg, ExportedSessionKey, "Server")

RC4Init(ClientHandle, ClientSealingKey)
RC4Init(ServerHandle, ServerSealingKey)

Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
Set AUTHENTICATE_MESSAGE.MIC to MIC

     */
    @Override
    public void processChallengeMessage(byte[] challengeMessageData) {
        NtlmChallengeMessage challengeMessage = new NtlmChallengeMessage(challengeMessageData);

        negotiateFlags = challengeMessage.getNegotiateFlags();
        if (connectionType == ConnectionType.connectionless) {
            negotiateFlags = (negotiateFlags & NtlmAuthenticator.NEGOTIATE_FLAGS_CONNLESS) | NTLMSSP_REQUEST_TARGET_FLAG;
            if (NTLMSSP_NEGOTIATE_56.isSet(negotiateFlags)) {
                negotiateFlags &= ~NTLMSSP_NEGOTIATE_56.getFlag(); 
            }
        }

        clientChallenge = randomDataProvider.nonce(8);

/*
3.1.5.1.2
If NTLM v2 authentication is used, the client SHOULD send the timestamp in the
CHALLENGE_MESSAGE. <40>
<40> Section 3.1.5.1.2: Not supported by Windows NT, Windows 2000, Windows XP, and Windows
Server 2003.

If there exists a CHALLENGE_MESSAGE.NTLMv2_CLIENT_CHALLENGE.AvId == MsvAvTimestamp
    Set Time to CHALLENGE_MESSAGE.TargetInfo.Value of that AVPair
Else
    Set Time to Currenttime
Endif

 */
        ByteArray time = challengeMessage.getTime();
        if (time == null) {
            // todo [!]
            time = new ByteArray(randomDataProvider.msTimestamp());
        }

        calculateNTLMv2Responce(challengeMessage.getServerChallenge(), time, clientChallenge, challengeMessage.getTargetInfo());
        calculateKeys();

        /*
2.2.1.3 AUTHENTICATE_MESSAGE

         */
        authenticateMessage = new NtlmMessage(3);
        authenticateMessage.appendStructure(lmChallengeResponse);
        authenticateMessage.appendStructure(ntChallengeResponse);
        authenticateMessage.appendStructure(domain);
        authenticateMessage.appendStructure(username);
        authenticateMessage.appendStructure(hostname);
        authenticateMessage.appendStructure(encryptedRandomSessionKey);
        authenticateMessage.appendPlain(intToBytes(negotiateFlags));
        authenticateMessage.appendPlain(WINDOWS_VERSION);

/*
Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
Set AUTHENTICATE_MESSAGE.MIC to MIC
 */
        byte[] mic = calculateHmacMD5(exportedSessionKey,
                connectionType == ConnectionType.connectionOriented ?
                        concat(negotiateMessageData, challengeMessageData, authenticateMessage.getData()) :
                        concat(challengeMessageData, authenticateMessage.getData())
        );
        authenticateMessage.appendStructure(mic);
    }
    

    private void calculateKeys() {
        byte[] keyExchangeKey = kxkey(sessionBaseKey);
        if (NTLMSSP_NEGOTIATE_KEY_EXCH.isSet(negotiateFlags)) {
            exportedSessionKey = randomDataProvider.nonce(16);
            encryptedRandomSessionKey = calculateRC4K(keyExchangeKey, exportedSessionKey);
        } else {
            exportedSessionKey = keyExchangeKey;
            encryptedRandomSessionKey = null;
        }
        clientSigningKey = signkey(negotiateFlags, SignkeyMode.client, exportedSessionKey);
        serverSigningKey = signkey(negotiateFlags, SignkeyMode.server, exportedSessionKey);
        clientSealingKey = sealkey(negotiateFlags, SignkeyMode.client, exportedSessionKey);
        serverSealingKey = sealkey(negotiateFlags, SignkeyMode.server, exportedSessionKey);


        if (connectionType == NtlmAuthenticator.ConnectionType.connectionOriented) {
            clientSealingKeyCipher = createRC4(clientSealingKey);
            serverSealingKeyCipher = createRC4(serverSealingKey);
        }
    }

/*
3.3.2 NTLM v2 Authentication
The following pseudocode defines the details of the algorithms used to calculate the keys used in
NTLM v2 authentication.

Note The NTLM authentication version is not negotiated by the protocol. It MUST be configured on
both the client and the server prior to authentication. The NTOWF v2 and LMOWF v2 functions
defined in this section are NTLM version-dependent and are used only by NTLM v2.

The NT and LM response keys MUST be encoded using the following specific one-way functions
where all strings are encoded as RPC_UNICODE_STRING ([MS-DTYP] section 2.3.8).

-- Explanation of message fields and variables:
--  NegFlg, User, UserDom - Defined in section 3.1.1.
--  Passwd - Password of the user.
--  LmChallengeResponse - The LM response to the server challenge.
    Computed by the client.
--  NTChallengeResponse - The NT response to the server challenge.
    Computed by the client.
--  ClientChallenge - The 8-byte challenge message generated by the
    client.
--  CHALLENGE_MESSAGE.ServerChallenge - The 8-byte challenge message
    generated by the server.
--  ResponseKeyNT - Temporary variable to hold the results of
    calling NTOWF().
--  ResponseKeyLM - Temporary variable to hold the results of
    calling LMGETKEY.
--  ServerName - The TargetInfo field structure of the
    CHALLENGE_MESSAGE payload.
--  KeyExchangeKey - Temporary variable to hold the results of
    calling KXKEY.
--  HiResponserversion - The 1-byte highest response version
    understood by the client. Currently set to 1.
--  Responserversion - The 1-byte response version. Currently set
    to 1.
-- Time - The 8-byte little-endian time in GMT.
--
-- Functions Used:
--  Z(M) - Defined in section 6.


Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(
    MD4(UNICODE(Passwd)), ConcatenationOf( Uppercase(User),
    UserDom ) )
EndDefine

Define LMOWFv2(Passwd, User, UserDom) as NTOWFv2(Passwd, User,
    UserDom)
EndDefine

Set ResponseKeyNT to NTOWFv2(Passwd, User, UserDom)
Set ResponseKeyLM to LMOWFv2(Passwd, User, UserDom)

Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM,
    CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge, Time, ServerName)
As
If (User is set to "" && Passwd is set to "")
    -- Special case for anonymous authentication
    Set NtChallengeResponseLen to 0
    Set NtChallengeResponseMaxLen to 0
    Set NtChallengeResponseBufferOffset to 0
    Set LmChallengeResponse to Z(1)
Else
    Set temp to ConcatenationOf(Responserversion, HiResponserversion,
        Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
    Set NTProofStr to HMAC_MD5(ResponseKeyNT,
        ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
    Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
    Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
            ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
        ClientChallenge )
EndIf

Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
EndDefine


  */
    private static final ByteArray ALL_RESPONSER_VERSION = new ByteArray(new byte[]{1, 1});

    private void calculateNTLMv2Responce(ByteArray serverChallenge,ByteArray time, byte[] clientChallengeArray, ByteArray targetInfo) {
        byte[] responseKeyNT = ntowfv2;
        byte[] responseKeyLM = ntowfv2;
        ByteArray clientChallenge = new ByteArray(clientChallengeArray);

        byte[] temp2 = concat(serverChallenge, ALL_RESPONSER_VERSION, Z(6), time, clientChallenge, Z(4)
                , targetInfo, Z(4));
        ByteArray temp = new ByteArray(temp2, 8, temp2.length - serverChallenge.getLength()); // temp2 without server challenge

        byte[] ntProofStr = calculateHmacMD5(responseKeyNT, temp2);
        ntChallengeResponse = concat(new ByteArray(ntProofStr), temp);


/*
    Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
            ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
        ClientChallenge )

 */
        lmChallengeResponse = concat(
                calculateHmacMD5(responseKeyLM, concat(serverChallenge, clientChallenge))
                , clientChallenge);
        sessionBaseKey = calculateHmacMD5(responseKeyNT, ntProofStr);
    }


    @Override
    public void updateSequenceNumber(int seqNum) {
        if (connectionType != NtlmAuthenticator.ConnectionType.connectionless) { // NTLMSSP_NEGOTIATE_DATAGRAM.isSet(negotiateFlags)
            throw new IllegalArgumentException("Can't update equence number on connection-oriented session");
        }
        clientSealingKeyCipher = reinitSealingKey(clientSealingKey, seqNum);

        this.seqNum = seqNum;
    }


/*
3.4.2 Message Integrity
The function to sign a message MUST be calculated as follows:
-- Input:
--  SigningKey - The key used to sign the message.
--  Message - The message being sent between the client and server.
--  SeqNum - Defined in section 3.1.1.
--  Handle - The handle to a key state structure corresponding to
--      the current state of the SealingKey
--
-- Output:Signed message
-- Functions used:
--  ConcatenationOf() - Defined in Section 6.
--  MAC() - Defined in section 3.4.3.

Define SIGN(Handle, SigningKey, SeqNum, Message) as
ConcatenationOf(Message, MAC(Handle, SigningKey, SeqNum, Message))
EndDefine

Note If the client is sending the message, the signing key is the one that the client calculated. If
the server is sending the message, the signing key is the one that the server calculated. The same
is true for the sealing key. The sequence number can be explicitly provided by the application
protocol or by the NTLM security service provider. If the latter is chosen, the sequence number is
initialized to zero and then incremented by one for each message sent.

On receipt, the message authentication code (MAC) value is computed and compared with the
received value. If they differ, the message MUST be discarded (section 3.4.4).

*/
    public byte[] sign(byte[] message) {
        return null;
    }

    /*
3.4.3 Message Confidentiality
Message confidentiality, if it is negotiated, also implies message integrity. If message confidentiality
is negotiated, a sealed (and implicitly signed) message is sent instead of a signed or unsigned
message. The function that seals a message using the signing key, sealing key, and message
sequence number is as follows:
-- Input:
--  SigningKey - The key used to sign the message.
--  Message - The message to be sealed, as provided to the application.
--  NegFlg, SeqNum - Defined in section 3.1.1.
--  Handle - The handle to a key state structure corresponding to the
--          current state of the SealingKey
--
-- Output:
--  Sealed message – The encrypted message
--  Signature – The checksum of the Sealed message
--
-- Functions used:
--  RC4() - Defined in Section 6 and 3.1.
--  MAC() - Defined in Section 3.4.4.1 and 3.4.4.2.

Define SEAL(Handle, SigningKey, SeqNum, Message) as
    Set Sealed message to RC4(Handle, Message)
    Set Signature to MAC(Handle, SigningKey, SeqNum, Message)
EndDefine

Message confidentiality is available in connectionless mode only if the client configures extended
session security.

     */
    public byte[] seal(byte[] message) {
        if (connectionType != NtlmAuthenticator.ConnectionType.connectionless || !NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.isSet(negotiateFlags)) {
            throw new RuntimeException("Message confidentiality is available in connectionless mode only if the client configures extended session security.");
        }
        return null;
    }

    /*
2.2.2.9 NTLMSSP_MESSAGE_SIGNATURE
The NTLMSSP_MESSAGE_SIGNATURE structure (section 3.4.4), specifies the signature block used
for application message integrity and confidentiality. This structure is then passed back to the
application, which embeds it within the application protocol messages, along with the NTLM-
encrypted or integrity-protected application message data.
This structure MUST take one of the two following forms, depending on whether the
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is negotiated:
NTLMSSP_MESSAGE_SIGNATURE
NTLMSSP_MESSAGE_SIGNATURE for Extended Session Security


2.2.2.9.2 NTLMSSP_MESSAGE_SIGNATURE for Extended Session Security
This version of the NTLMSSP_MESSAGE_SIGNATURE structure MUST be used when the
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is negotiated.
Version (4 bytes): A 32-bit unsigned integer MUST be 0x00000001
Checksum (8 bytes):
SeqNum (4 bytes):


     */

    public byte[] calculateMac(byte[] message) {
        return mac(negotiateFlags, seqNum, clientSigningKey, clientSealingKeyCipher, message);
    }


    
    public byte[] generateAuthenticateMessage() {

        /*
If the CHALLENGE_MESSAGE TargetInfo field (section 2.2.1.2) has an MsvAvTimestamp present,
the client SHOULD provide a MIC<48>:
If there is an AV_PAIR structure (section 2.2.2.1) with the AvId field set to MsvAvFlags,
then in the Value field, set bit 0x2 to 1.
else add an AV_PAIR structure (section 2.2.2.1) and set the AvId field to MsvAvFlags and the
Value field bit 0x2 to 1.

Populate the MIC field with the MIC, where
Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(
CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))


The client SHOULD send the channel binding AV_PAIR <49>:
...

         */

        return authenticateMessage.getData();
    }


}
