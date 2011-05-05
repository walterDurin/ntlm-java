/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import static org.microsoft.security.ntlm.impl.Algorithms.ByteArray;
import static org.microsoft.security.ntlm.impl.Algorithms.bytesTo2;
import static org.microsoft.security.ntlm.impl.Algorithms.bytesTo4;

/**
 *
 * How NTLM version is detected: http://davenport.sourceforge.net/ntlm.html#ntlmVersion2
 * Also NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is used to negotiate
 *
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class NtlmRoutines {

    public static final byte[] NTLM_MESSAGE_SIGNATURE = "NTLMSSP\0".getBytes();

/*
[MS-NLMP]
2.2.2.5 NEGOTIATE
During NTLM authentication, each of the following flags is a possible value of the NegotiateFlags
field of the NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE, unless
otherwise noted. These flags define client or server NTLM capabilities supported by the sender.
*/
    public static final int NTLMSSP_NEGOTIATE_UNICODE_FLAG =0x00000001;	/* A  */
    public static final int NTLMSSP_NEGOTIATE_OEM_FLAG =0x00000002;	/* B  */
    public static final int NTLMSSP_REQUEST_TARGET_FLAG =0x00000004;	/* C  */
//public static final int r9						0x00000008	/* r9 */
    public static final int NTLMSSP_NEGOTIATE_SIGN_FLAG =0x00000010;	/* D  */
    public static final int NTLMSSP_NEGOTIATE_SEAL_FLAG =0x00000020;	/* E  */
    public static final int NTLMSSP_NEGOTIATE_DATAGRAM_FLAG =0x00000040;	/* F  */
    public static final int NTLMSSP_NEGOTIATE_LM_KEY_FLAG =0x00000080;	/* G  */
//public static final int r8						0x00000100	/* r8 */
    public static final int NTLMSSP_NEGOTIATE_NTLM_FLAG =0x00000200;	/* H  */
    public static final int NTLMSSP_NEGOTIATE_NT_ONLY_FLAG =0x00000400;	/* I  */
    public static final int NTLMSSP_NEGOTIATE_anonymous_FLAG =0x00000800;	/* J  */
    public static final int NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED_FLAG =0x00001000;	/* K  */
    public static final int NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED_FLAG =0x00002000;	/* L  */
//public static final int r7						0x00004000	/* r7 */
    public static final int NTLMSSP_NEGOTIATE_ALWAYS_SIGN_FLAG =0x00008000;	/* M  */
    public static final int NTLMSSP_TARGET_TYPE_DOMAIN_FLAG =0x00010000;	/* N  */
    public static final int NTLMSSP_TARGET_TYPE_SERVER_FLAG =0x00020000;	/* O  */
//public static final int r6						0x00040000	/* r6 */
    public static final int NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG =0x00080000;	/* P  */
    public static final int NTLMSSP_NEGOTIATE_IDENTIFY_FLAG =0x00100000;	/* Q  */
//public static final int r5						0x00200000	/* r5 */
    public static final int NTLMSSP_REQUEST_NON_NT_SESSION_KEY_FLAG =0x00400000;	/* R  */
    public static final int NTLMSSP_NEGOTIATE_TARGET_INFO_FLAG =0x00800000;	/* S  */
//public static final int r4						0x01000000	/* r4 */
    public static final int NTLMSSP_NEGOTIATE_VERSION_FLAG =0x02000000;	/* T  */
//public static final int r3						0x04000000	/* r3 */
//public static final int r2						0x08000000	/* r2 */
//public static final int r1						0x10000000	/* r1 */
    public static final int NTLMSSP_NEGOTIATE_128_FLAG =0x20000000;	/* U  */
    public static final int NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG =0x40000000;	/* V  */
    public static final int NTLMSSP_NEGOTIATE_56_FLAG =0x80000000;	/* W  */

    /**
     * A (1 bit): If set, requests Unicode character set encoding. An alternate name for this field is
     NTLMSSP_NEGOTIATE_UNICODE.
     The A and B bits are evaluated together as follows:
     A==1: The choice of character set encoding MUST be Unicode.
     A==0 and B==1: The choice of character set encoding MUST be OEM.
     A==0 and B==0: The protocol MUST return SEC_E_INVALID_TOKEN.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_UNICODE = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_UNICODE_FLAG, "NTLMSSP_NEGOTIATE_UNICODE");

    /**
     * B (1 bit): If set, requests OEM character set encoding. An alternate name for this field is
     NTLM_NEGOTIATE_OEM. See bit A for details.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_OEM = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_OEM_FLAG, "NTLMSSP_NEGOTIATE_OEM");

    /**
     * C (1 bit): If set, a TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be
     supplied. An alternate name for this field is NTLMSSP_REQUEST_TARGET.

     */
    public static final NegotiateFlagInfo NTLMSSP_REQUEST_TARGET = new NegotiateFlagInfo(NTLMSSP_REQUEST_TARGET_FLAG, "NTLMSSP_REQUEST_TARGET");

    /**
     * D (1 bit): If set, requests session key negotiation for message signatures. If the client sends
     NTLMSSP_NEGOTIATE_SIGN to the server in the NEGOTIATE_MESSAGE, the server MUST
     return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE. An alternate
     name for this field is NTLMSSP_NEGOTIATE_SIGN.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_SIGN = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_SIGN_FLAG, "NTLMSSP_NEGOTIATE_SIGN");

    /**
     * E (1 bit): If set, requests session key negotiation for message confidentiality. If the client sends
     NTLMSSP_NEGOTIATE_SEAL to the server in the NEGOTIATE_MESSAGE, the server MUST
     return NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE. Clients and
     servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56
     and NTLMSSP_NEGOTIATE_128, if they are supported. An alternate name for this field is
     NTLMSSP_NEGOTIATE_SEAL.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_SEAL = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_SEAL_FLAG, "NTLMSSP_NEGOTIATE_SEAL");

    /**
     * F (1 bit): If set, requests connectionless authentication. If NTLMSSP_NEGOTIATE_DATAGRAM is
     set, then NTLMSSP_NEGOTIATE_KEY_EXCH MUST always be set in the
     AUTHENTICATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An
     alternate name for this field is NTLMSSP_NEGOTIATE_DATAGRAM.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_DATAGRAM = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_DATAGRAM_FLAG, "NTLMSSP_NEGOTIATE_DATAGRAM");

    /**
     * G (1 bit): If set, requests LAN Manager (LM) session key computation.
     NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
     are mutually exclusive. If both NTLMSSP_NEGOTIATE_LM_KEY and
     NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested,
     NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client.
     NTLM v2 authentication session key generation MUST be supported by both the client and the
     DC in order to be used, and extended session security signing and sealing requires support
     from the client and the server to be used. An alternate name for this field is
     NTLMSSP_NEGOTIATE_LM_KEY.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_LM_KEY = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_LM_KEY_FLAG, "NTLMSSP_NEGOTIATE_LM_KEY");

    /**
     * H (1 bit): If set, requests usage of the NTLM v1 session security protocol.
     NTLMSSP_NEGOTIATE_NTLM MUST be set in the NEGOTIATE_MESSAGE to the server and the
     CHALLENGE_MESSAGE to the client. An alternate name for this field is
     NTLMSSP_NEGOTIATE_NTLM.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_NTLM = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_NTLM_FLAG, "NTLMSSP_NEGOTIATE_NTLM");

    /**
     * r8 (1 bit): This bit is unused and SHOULD be zero. <26>
     <26> Section 2.2.2.5: Windows NTLM clients can set this bit. No versions of Windows NTLM servers
     support it, so this bit is never used.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_NT_ONLY = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_NT_ONLY_FLAG, "NTLMSSP_NEGOTIATE_NT_ONLY");

    /**
     * J (1 bit): If set, the connection SHOULD be anonymous. <25>
     <25> Section 2.2.2.5: Windows sends this bit for anonymous connections, but a Windows-based
     NTLM server does not use this bit when establishing the session.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_anonymous = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_anonymous_FLAG, "NTLMSSP_NEGOTIATE_anonymous");

    /**
     * K (1 bit): If set, the domain name is provided (section 2.2.1.1).<24> An alternate name for
     this field is NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.
     <24> Section 2.2.2.5: The NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not
     supported in Windows NT and Windows 2000.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED_FLAG, "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED");

    /**
     * L (1 bit): This flag indicates whether the Workstation field is present. If this flag is not set, the
     Workstation field MUST be ignored. If this flag is set, the length field of the Workstation
     field specifies whether the workstation name is nonempty or not.<23> An alternate name for
     this field is NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED_FLAG, "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED");

    /**
     * M (1 bit): If set, requests the presence of a signature block on all messages.
NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be set in the NEGOTIATE_MESSAGE to the
server and the CHALLENGE_MESSAGE to the client. NTLMSSP_NEGOTIATE_ALWAYS_SIGN is
overridden by NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL, if they are
supported. An alternate name for this field is NTLMSSP_NEGOTIATE_ALWAYS_SIGN.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_ALWAYS_SIGN = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_ALWAYS_SIGN_FLAG, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN");

    /**
     * N (1 bit): If set, TargetName MUST be a domain name. The data corresponding to this flag is
provided by the server in the TargetName field of the CHALLENGE_MESSAGE. If set, then
NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST be ignored in the
NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is
NTLMSSP_TARGET_TYPE_DOMAIN.

     */
    public static final NegotiateFlagInfo NTLMSSP_TARGET_TYPE_DOMAIN = new NegotiateFlagInfo(NTLMSSP_TARGET_TYPE_DOMAIN_FLAG, "NTLMSSP_TARGET_TYPE_DOMAIN");

    /**
     * O (1 bit): If set, TargetName MUST be a server name. The data corresponding to this flag is
provided by the server in the TargetName field of the CHALLENGE_MESSAGE. If this bit is
set, then NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set. This flag MUST be ignored in
the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field
is NTLMSSP_TARGET_TYPE_SERVER.

     */
    public static final NegotiateFlagInfo NTLMSSP_TARGET_TYPE_SERVER = new NegotiateFlagInfo(NTLMSSP_TARGET_TYPE_SERVER_FLAG, "NTLMSSP_TARGET_TYPE_SERVER");

    /**
     * P (1 bit): If set, requests usage of the NTLM v2 session security. NTLM v2 session security is a
misnomer because it is not NTLM v2. It is NTLM v1 using the extended session security that is
also in NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and NTLMSSP_NEGOTIATE_LM_KEY
are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be
returned to the client. NTLM v2 authentication session key generation MUST be supported by
both the client and the DC in order to be used, and extended session security signing and
sealing requires support from the client and the server in order to be used.<22> An alternate
name for this field is NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY");

    /**
     * Q (1 bit): If set, requests an identify level token. An alternate name for this field is
NTLMSSP_NEGOTIATE_IDENTIFY.

 identify level token: A security token resulting from authentication that represents the
authenticated user but does not allow the service holding the token to impersonate that user
to other resources.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_IDENTIFY = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_IDENTIFY_FLAG, "NTLMSSP_NEGOTIATE_IDENTIFY");

    /**
     * R (1 bit): If set, requests the usage of the LMOWF (section 3.3). An alternate name for this
field is NTLMSSP_REQUEST_NON_NT_SESSION_KEY.

     */
    public static final NegotiateFlagInfo NTLMSSP_REQUEST_NON_NT_SESSION_KEY = new NegotiateFlagInfo(NTLMSSP_REQUEST_NON_NT_SESSION_KEY_FLAG, "NTLMSSP_REQUEST_NON_NT_SESSION_KEY");

    /**
     * S (1 bit): If set, indicates that the TargetInfo fields in the CHALLENGE_MESSAGE (section
2.2.1.2) are populated. An alternate name for this field is
NTLMSSP_NEGOTIATE_TARGET_INFO.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_TARGET_INFO = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_TARGET_INFO_FLAG, "NTLMSSP_NEGOTIATE_TARGET_INFO");

    /**
     * T (1 bit): If set, requests the protocol version number. The data corresponding to this flag is
provided in the Version field of the NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and
the AUTHENTICATE_MESSAGE.<21> An alternate name for this field is
NTLMSSP_NEGOTIATE_VERSION.

 <21> Section 2.2.2.5: The NTLMSSP_NEGOTIATE_VERSION flag is not supported in Windows NT
and Windows 2000. This flag is used for debug purposes only.
    
     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_VERSION = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_VERSION_FLAG, "NTLMSSP_NEGOTIATE_VERSION");

    /**
     * U (1 bit): If set, requests 128-bit session key negotiation. An alternate name for this field is
NTLMSSP_NEGOTIATE_128. If the client sends NTLMSSP_NEGOTIATE_128 to the server in the
NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_128 to the client in the
CHALLENGE_MESSAGE only if the client sets NTLMSSP_NEGOTIATE_SEAL or
NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and
NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server,
NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client.
Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set
NTLMSSP_NEGOTIATE_128 if it is supported. An alternate name for this field is
NTLMSSP_NEGOTIATE_128. <20>

<20> Section 2.2.2.5: Windows 7, and Windows Server 2008 R2 support only 128-bit session key
negotiation by default, therefore this bit will always be set.
     
     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_128 = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_128_FLAG, "NTLMSSP_NEGOTIATE_128");

    /**
     * V (1 bit): If set, requests an explicit key exchange. This capability SHOULD be used because it
improves security for message integrity or confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1,
and 3.2.5.2.2 for details. An alternate name for this field is
NTLMSSP_NEGOTIATE_KEY_EXCH.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_KEY_EXCH = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG, "NTLMSSP_NEGOTIATE_KEY_EXCH");

    /**
     * W (1 bit): If set, requests 56-bit encryption. If the client sends NTLMSSP_NEGOTIATE_SEAL or
NTLMSSP_NEGOTIATE_SIGN with NTLMSSP_NEGOTIATE_56 to the server in the
NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_56 to the client in the
CHALLENGE_MESSAGE. Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and
NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server,
NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client.
Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set
NTLMSSP_NEGOTIATE_56 if it is supported. An alternate name for this field is
NTLMSSP_NEGOTIATE_56.

     */
    public static final NegotiateFlagInfo NTLMSSP_NEGOTIATE_56 = new NegotiateFlagInfo(NTLMSSP_NEGOTIATE_56_FLAG, "NTLMSSP_NEGOTIATE_56");

    public static final NegotiateFlagInfo[] NEGOTIATE_FLAGS = {
            NTLMSSP_NEGOTIATE_UNICODE,
            NTLMSSP_NEGOTIATE_OEM,
            NTLMSSP_REQUEST_TARGET,
            new NegotiateFlagInfo(0x00000008, "r9"),
            NTLMSSP_NEGOTIATE_SIGN,
            NTLMSSP_NEGOTIATE_SEAL,
            NTLMSSP_NEGOTIATE_DATAGRAM,
            NTLMSSP_NEGOTIATE_LM_KEY,
            new NegotiateFlagInfo(0x00000100,"r8"),
            NTLMSSP_NEGOTIATE_NTLM,
            NTLMSSP_NEGOTIATE_NT_ONLY,
            NTLMSSP_NEGOTIATE_anonymous,
            NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED,
            NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
            new NegotiateFlagInfo(0x00004000, "r7"),
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
            NTLMSSP_TARGET_TYPE_DOMAIN,
            NTLMSSP_TARGET_TYPE_SERVER,
            new NegotiateFlagInfo(0x00040000, "r6"),
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
            NTLMSSP_NEGOTIATE_IDENTIFY,
            new NegotiateFlagInfo(0x00200000, "r5"),
            NTLMSSP_REQUEST_NON_NT_SESSION_KEY,
            NTLMSSP_NEGOTIATE_TARGET_INFO,
            new NegotiateFlagInfo(0x01000000, "r4"),
            NTLMSSP_NEGOTIATE_VERSION,
            new NegotiateFlagInfo(0x04000000, "r3"),
            new NegotiateFlagInfo(0x08000000, "r2"),
            new NegotiateFlagInfo(0x10000000, "r1"),
            NTLMSSP_NEGOTIATE_128,
            NTLMSSP_NEGOTIATE_KEY_EXCH,
            NTLMSSP_NEGOTIATE_56,
    };

    public static final class NegotiateFlagInfo {
        private int flag;
        private String description;

        public NegotiateFlagInfo(int flag, String description) {
            this.flag = flag;
            this.description = description;
        }

        public boolean isSet(int negotiateInfo) {
            return (negotiateInfo & flag) != 0;
        }

        public int getFlag() {
            return flag;
        }

        public String getDescription() {
            return description;
        }
    }


    /*
2.2.2.1 AV_PAIR
The AV_PAIR structure defines an attribute/value pair. Sequences of AV_PAIR structures are used in
the CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE messages.
Although the following figure suggests that the most significant bit (MSB) of AvId is aligned with
the MSB of a 32-bit word, an AV_PAIR can be aligned on any byte boundary and can be 4+N bytes
long for arbitrary N (N = the contents of AvLen).
     */

    /**
     * Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0.
This type of information MUST be present in the AV pair list.
     */
    public static final int MsvAvEOL = 0;

    /**
     * The server's NetBIOS computer name. The name MUST be in Unicode,
and is not null-terminated. This type of information MUST be present
 in the AV_pair list if confidentiality or integrity is requested.
     */
    public static final int MsvAvNbComputerName = 1;

    /**
     * The server's NetBIOS domain name. The name MUST be in Unicode,
and is not null-terminated. This type of information MUST be present
in the AV_pair list if confidentiality or integrity is requested.
     */
    public static final int MsvAvNbDomainName = 2;

    /**
     * The fully qualified domain name (FQDN (1)) of the computer. The
name MUST be in Unicode, and is not null-terminated.
     */
    public static final int MsvAvDnsComputerName = 3;

    /**
     * The FQDN (2) of the domain. The name MUST be in Unicode, and is
not null-terminated.
     */
    public static final int MsvAvDnsDomainName = 4;

    /**
     * The FQDN (2) of the forest. The name MUST be in Unicode, and is not
null-terminated.<11>
<11> Section 2.2.2.1: MsvAvDnsTreeName AV_PAIR type is not supported in Windows NT and
Windows 2000.

     */
    public static final int MsvAvDnsTreeName = 5;


    /**
     * A 32-bit value indicating server or client configuration.
0x00000001: indicates to the client that the account authentication is
constrained.
0x00000002: indicates that the client is providing message integrity in
the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.<12>

     <12> Section 2.2.2.1: MsvAvFlags AV_PAIR type is not supported in Windows NT and
     Windows 2000.

     */
    public static final int MsvAvFlags = 6;

    enum MsvAvFlag {
        accountAuthenticationIsConstrained, clientIsProvidingMessageIntegrity
    }

    /**
     * A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte
order that contains the server local time.<13>
     <13> Section 2.2.2.1: MsvAvTimestamp AV_PAIR type is not supported in Windows NT,
     Windows 2000, Windows XP, and Windows Server 2003.
     */
    public static final int MsvAvTimestamp = 7;

    /**
     * A Restriction_Encoding structure (section 2.2.2.2). The Value field
contains a structure representing the integrity level of the security
 principal, as well as a MachineID created at computer startup to
identify the calling machine. <14>

<14> Section 2.2.2.1: MsAvRestrictions AV_PAIR type is not supported in Windows NT,
Windows 2000, Windows XP, and Windows Server 2003.

     */
    public static final int MsAvRestrictions = 8;

    /**
     * The SPN of the target server. The name MUST be in Unicode and is not
null-terminated. <15>

     <15> Section 2.2.2.1: MsvAvTargetName AV_PAIR type is not supported in Windows NT,
     Windows 2000, Windows XP, Windows Server 2003, Windows Vista, or Windows Server 2008.

     */
    public static final int MsvAvTargetName = 9;

    /**
     * A channel bindings hash. The Value field contains an MD5 hash
([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct
  ([RFC2744] section 3.11). An all-zero value of the hash is used to
 indicate absence of channel bindings. <16>
     <16> Section 2.2.2.1: MsvChannelBindings AV_PAIR type is not supported in Windows NT,
     Windows 2000, Windows XP, Windows Server 2003, Windows Vista, or Windows Server 2008.

     */
    public static final int MsvChannelBindings = 10;


    /**
     * Create ByteArray for referenced data
     *
     * @param data
     * @param offset
     * @return
     */
    public static ByteArray getMicrosoftArray(byte[] data, int offset) {
        int len = bytesTo2(data, offset);
        int maxLen = bytesTo2(data, offset+2);
        int arrayOffset = bytesTo4(data, offset+4);
        return len > 0 ? new ByteArray(data, arrayOffset, len) : null;
    }

    private static final byte[] Z_ARRAY = new byte[8];
    public static ByteArray Z(int length) {
        if (length > Z_ARRAY.length) {
            throw new RuntimeException("Legth exceed: " + length);
        }
        return new ByteArray(Z_ARRAY, 0, length);
    }

    public static RandomDataProvider randomDataProvider = new RandomDataProvider() {
        @Override
        public byte[] nonce(int length) {
            return Algorithms.nonce(length);
        }

        @Override
        public byte[] msTimestamp() {
            return Algorithms.msTimestamp();
        }
    };
}
