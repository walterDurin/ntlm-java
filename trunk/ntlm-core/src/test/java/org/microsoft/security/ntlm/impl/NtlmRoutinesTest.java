/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import org.junit.Assert;
import org.junit.Test;
import org.microsoft.security.ntlm.NtlmAuthenticator;
import org.microsoft.security.ntlm.PrivilegedAccessor;

import javax.crypto.Cipher;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static org.microsoft.security.ntlm.impl.Algorithms.EMPTY_ARRAY;
import static org.microsoft.security.ntlm.impl.Algorithms.calculateCRC32;
import static org.microsoft.security.ntlm.impl.Algorithms.intToBytes;

/**
 * Implementation of [MS-NLMP] 4 Protocol Examples
 *
 * @author <a href="mailto:pmoukhataev@amdocs.com">Pavel Moukhataev</a>
 * @version $Revision: $
 */
public class NtlmRoutinesTest {
    private static final Logger log = Logger.getLogger("ntlm-java.NtlmRoutinesTest");

    private static final int BYTES_PER_LINE = 16;
    private static final int MIN_LINE_LENGTH = 7+2 + BYTES_PER_LINE*3;
    private static final int LINE_LENGTH = 7+2 + BYTES_PER_LINE*4;
    /**
     * 4.2.1 Common Values
     */
    private static final String USER_NAME = "User";
    private static final String DOMAIN_NAME = "Domain";
    private static final String SERVER_NAME = "Server";
    private static final String WORKSTATION_NAME = "COMPUTER";
    private static final String PASSWORD = "Password";

    private static final byte[] RANDOM_SESSION_KEY = block2bytes(
            "0000000: 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 UUUUUUUUUUUUUUUU");

    private static final byte[] TIME = block2bytes(
            "0000000: 00 00 00 00 00 00 00 00                         ........"
            );

    private static final byte[] CLIENT_CHALLENGE = block2bytes(
            "0000000: aa aa aa aa aa aa aa aa                         ........"
            );

    private static final byte[] SERVER_CHALLENGE = block2bytes(
            "0000000: 01 23 45 67 89 ab cd ef                         .#Eg..&#x2550;."
            );


    @Test
    public void testNTLMv1() throws Exception {
        // 4.2.2 NTLM v1 Authentication
        byte[] negotiateFlagBytes = block2bytes(
                "0000000: 33 82 02 e2                                     3..."
        );
        int negotiateFlags = Algorithms.bytesTo4(negotiateFlagBytes, 0);

        // 4.2.2.1.1 LMOWFv1()
        byte[] lmowfv1 = NtlmV1Session.calculateLMOWFv1(DOMAIN_NAME, USER_NAME, PASSWORD);
        byte[] expectedLmowfv1 = block2bytes(
                "0000000: e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d ...gA...J;..?..m"
        );
        Assert.assertSame(expectedLmowfv1, lmowfv1);

        // 4.2.2.1.2 NTOWFv1()
        byte[] ntowfv1 = NtlmV1Session.calculateNTOWFv1(DOMAIN_NAME, USER_NAME, PASSWORD);
        byte[] expectedNtowfv1 = block2bytes(
                "0000000: a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52 ...@e.....N....R"
        );
        Assert.assertSame(expectedNtowfv1, ntowfv1);


        // 4.2.2.1.3 Session Base Key and Key Exchange Key
        NtlmV1Session ntlmV1Session = new NtlmV1Session(NtlmAuthenticator.ConnectionType.connectionOriented, ntowfv1, lmowfv1, SERVER_NAME, DOMAIN_NAME, USER_NAME);
        ntlmV1Session.negotiateFlags = negotiateFlags;
        ntlmV1Session.serverChallenge = new Algorithms.ByteArray(SERVER_CHALLENGE);
        ntlmV1Session.calculateNTLMResponse(new Algorithms.ByteArray(TIME), CLIENT_CHALLENGE, null);
        byte[] expectedSessionBaseKey = block2bytes(
                "0000000: d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84 .rb.....t......."
        );
        Assert.assertSame(expectedSessionBaseKey, ntlmV1Session.sessionBaseKey);

        // 4.2.2.2 Results

        // 4.2.2.2.1 NTLMv1 Response
        byte[] expectedNTLMv1Response = block2bytes(
                "0000000: 67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c g.0......5..O.3.",
                "0000010: 44 bd be d9 27 84 1f 94                         D...'..."
        );
        Assert.assertSame(expectedNTLMv1Response, ntlmV1Session.ntChallengeResponse);


        // 4.2.2.2.2 LMv1 Response
        {
            // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY not set
//        negotiateFlags = NtlmRoutines.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.excludeFlag(negotiateFlags);
            byte[] expectedLMv1Response = block2bytes(
                    "0000000: 98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 .......].......r",
                    "0000010: de f1 1c 7d 5c cd ef 13                         ...}...."
            );
            Assert.assertSame(expectedLMv1Response, ntlmV1Session.lmChallengeResponse);
        }

        {
            // NTLMSSP_NEGOTIATE_LM_KEY is set:
            int negotiateFlags0 = negotiateFlags | NtlmRoutines.NTLMSSP_NEGOTIATE_LM_KEY.getFlag();
            ntlmV1Session.negotiateFlags = negotiateFlags0;
            ntlmV1Session.calculateNTLMResponse(new Algorithms.ByteArray(TIME), CLIENT_CHALLENGE, null);
            byte[] expectedLMv1Response = block2bytes(
                    "0000000: b0 9e 37 9f 7f be cb 1e af 0a fd cb 03 83 c8 a0 ..7............."
            );
            Assert.assertSame(expectedLMv1Response, ntlmV1Session.lmChallengeResponse);
        }
        ntlmV1Session.negotiateFlags = negotiateFlags;

        // 4.2.2.2.3 Encrypted Session Key
        {
            // RC4 encryption of the RandomSessionKey with the KeyExchangeKey:
            PrivilegedAccessor.callMethod(ntlmV1Session, "calculateKeys",
                    new Class[]{byte[].class, byte[].class},
                    new Object[]{new byte[16], new byte[8]}
            );
            byte[] encryptedRandomSessionKey = (byte[]) PrivilegedAccessor.getValue(ntlmV1Session, "encryptedRandomSessionKey");
            byte[] expectedEncryptedSessionKey = block2bytes(
                    "0000000: 51 88 22 b1 b3 f3 50 c8 95 86 82 ec bb 3e 3c b7 Q.....P........."
            );
            Assert.assertSame(expectedEncryptedSessionKey, encryptedRandomSessionKey);
        }

        {
            // NTLMSSP_REQUEST_NON_NT_SESSION_KEY is set:
            int negotiateFlags0 = negotiateFlags | NtlmRoutines.NTLMSSP_REQUEST_NON_NT_SESSION_KEY.getFlag();
            ntlmV1Session.negotiateFlags = negotiateFlags0;
            PrivilegedAccessor.callMethod(ntlmV1Session, "calculateKeys",
                    new Class[]{byte[].class, byte[].class},
                    new Object[]{new byte[16], new byte[8]}
            );
            byte[] encryptedRandomSessionKey = (byte[]) PrivilegedAccessor.getValue(ntlmV1Session, "encryptedRandomSessionKey");
            byte[] expectedEncryptedSessionKey = block2bytes(
                    "0000000: 74 52 ca 55 c2 25 a1 ca 04 b4 8f ae 32 cf 56 fc tR.U........2.V."
            );
            Assert.assertSame(expectedEncryptedSessionKey, encryptedRandomSessionKey);
        }
        
        {
            // NTLMSSP_NEGOTIATE_LM_KEY is set:
            int negotiateFlags0 = negotiateFlags | NtlmRoutines.NTLMSSP_NEGOTIATE_LM_KEY.getFlag();
            ntlmV1Session.negotiateFlags = negotiateFlags0;
            PrivilegedAccessor.callMethod(ntlmV1Session, "calculateKeys",
                    new Class[]{byte[].class, byte[].class},
                    new Object[]{new byte[16], new byte[8]}
            );
            byte[] encryptedRandomSessionKey = (byte[]) PrivilegedAccessor.getValue(ntlmV1Session, "encryptedRandomSessionKey");
            byte[] expectedEncryptedSessionKey = block2bytes(
                    "0000000: 4c d7 bb 57 d6 97 ef 9b 54 9f 02 b8 f9 b3 78 64 L..W....T.....xd"
            );
            Assert.assertSame(expectedEncryptedSessionKey, encryptedRandomSessionKey);
        }
        
        // 4.2.2.3 Messages
        // The CHALLENGE_MESSAGE (section 2.2.1.2):
        byte[] challengeMessage = block2bytes(
                "0000000: 4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00 NTLMSSP.........",
                "0000010: 38 00 00 00 33 82 02 e2 01 23 45 67 89 ab cd ef 8...3....#Eg..=.",
                "0000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................",
                "0000030: 06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00 ..p.....S.e.r.v.",
                "0000040: 65 00 72 00                                     e.r."
        );
        ntlmV1Session.processChallengeMessage(challengeMessage);
        byte[] authenticateMessage = ntlmV1Session.generateAuthenticateMessage();
        
        // The AUTHENTICATE_MESSAGE (section 2.2.1.3):
        byte[] expectedAuthenticateMessage = block2bytes(
                "0000000: 4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 NTLMSSP.........",
                "0000010: 6c 00 00 00 18 00 18 00 84 00 00 00 0c 00 0c 00 l...............",
                "0000020: 48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00 H.......T.......",
                "0000030: 5c 00 00 00 10 00 10 00 9c 00 00 00 35 82 80 e2 ............5...",
                "0000040: 05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00 ..(.....D.o.m.a.",
                "0000050: 69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00 i.n.U.s.e.r.C.O.",
                "0000060: 4d 00 50 00 55 00 54 00 45 00 52 00 98 de f7 b8 M.P.U.T.E.R.....",
                "0000070: 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d ...]...w...r...}",
                "0000080: 5c cd ef 13 67 c4 30 11 f3 02 98 a2 ad 35 ec e6 =...g-0......5..",
                "0000090: 4f 16 33 1c 44 bd be d9 27 84 1f 94 51 88 22 b1 O.3.D...'...Q...",
                "00000A0: b3 f3 50 c8 95 86 82 ec bb 3e 3c b7             ..P......><."
        );
        Assert.assertSame(expectedAuthenticateMessage, authenticateMessage);



        // 4.2.2.4 GSS_WrapEx Examples
        byte[] seqNum = block2bytes(
                "0000000: 00 00 00 00                                     ...."
        );

        byte[] nonce_4 = block2bytes(
                "0000000: 00 00 00 00                                     ...."
        );

        byte[] plaintext = "Plaintext".getBytes(Algorithms.UNICODE_ENCODING);

        PrivilegedAccessor.setValue(ntlmV1Session, "connectionType", NtlmAuthenticator.ConnectionType.connectionless);
        ntlmV1Session.updateSequenceNumber(0);
        Cipher sealingKey = (Cipher) PrivilegedAccessor.getValue(ntlmV1Session, "clientSealingKeyCipher");
        byte[] randomPadIn = Algorithms.EMPTY_ARRAY;
        byte[] message = plaintext;
        byte[] seqNumInArray = seqNum;

        byte[] checksum = calculateCRC32(message);
        byte[] randomPad = sealingKey.doFinal(randomPadIn);
        byte[] checksum2 = sealingKey.doFinal(checksum);
        byte[] seqNum1 = sealingKey.doFinal(EMPTY_ARRAY);
//        byte[] seqNumInArray = intToBytes(seqNumIn);
        byte[] seqNum2 = new byte[4];
        for (int i = 0; i < seqNumInArray.length; i++) {
            seqNum2[i] = (byte) (seqNum1[i] ^ seqNumInArray[i]);
        }

        // Data:
        byte[] expectedSealedData = block2bytes(
                "0000000: 56 fe 04 d8 61 f9 31 9a f0 d7 23 8a 2e 3b 4d 45 V...a.1...#e.;ME",
                "0000010: 7f b8                                           .."
        );
        byte[] sealedData = ntlmV1Session.seal(plaintext);
        Assert.assertSame(expectedSealedData, sealedData);

        // Checksum: CRC32(Message):
        byte[] expectedCRC32 = block2bytes(
                "0000000: 7d 84 aa 93                                     }..."
        );
        Assert.assertSame(expectedCRC32, checksum);

        // RandomPad: RC4(Handle, RandomPad):
        byte[] expectedRandomPad = block2bytes(
                "0000000: 45 c8 44 e5                                     E.D."
        );
        Assert.assertSame(expectedRandomPad, randomPad);

        // Checksum: RC4(Handle, NTLMSSP_MESSAGE_SIGNATURE.Checksum):
        byte[] expectedChecksum = block2bytes(
                "0000000: 09 dc d1 df                                     ...."
        );
        Assert.assertSame(expectedChecksum, checksum2);

        // SeqNum: RC4(Handle, 0x00000000):
        byte[] expectedSeqNum = block2bytes(
                "0000000: 2e 45 9d 36                                     .E.6"
        );
        Assert.assertSame(expectedSeqNum, seqNum1);

        // SeqNum: XOR:
        byte[] expectedSeqNumXOR = block2bytes(
                "0000000: 2e 45 9d 36                                     .E.6"
        );
        Assert.assertSame(expectedSeqNumXOR, seqNum2);
    }



    /*
     */
    private static byte[] block2bytes(String... text) {
        int nextByteNumber = 0;
        List<byte[]> data = new ArrayList<byte[]>();
        for (int lineNumber = 0; lineNumber < text.length; lineNumber++) {
            String inLine = text[lineNumber];
            inLine = inLine.trim();
            if (inLine.length() == 0) continue;
            if (inLine.length() < MIN_LINE_LENGTH || inLine.length() > LINE_LENGTH) {
                throw new RuntimeException("Can't parse line[" + lineNumber + "] invalid length: " + inLine.length() + " (" + inLine + ")");
            } else if (inLine.length() < LINE_LENGTH && lineNumber < text.length-1) {
                throw new RuntimeException("Can't parse line[" + lineNumber + "] previous line was last: " + inLine);
            }
            if (inLine.charAt(7) != ':') {
                throw new RuntimeException("Can't parse line[" + lineNumber + "]: - no ':' " + inLine);
            }
            String byteNumberString = inLine.substring(0, 7);
            int byteNumber = Integer.parseInt(byteNumberString, 16);
            Assert.assertSame(nextByteNumber, byteNumber);
            nextByteNumber = byteNumber+BYTES_PER_LINE;

            String dataString = inLine.substring(7+2, MIN_LINE_LENGTH-1);
            data.add(Algorithms.stringToBytes(dataString));
        }
        byte[] bytes = Algorithms.concat(data.toArray());
        return bytes;
    }
}
