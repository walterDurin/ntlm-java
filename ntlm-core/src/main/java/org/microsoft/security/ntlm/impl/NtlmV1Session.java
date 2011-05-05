package org.microsoft.security.ntlm.impl;

import org.microsoft.security.ntlm.NtlmSession;

import static org.microsoft.security.ntlm.NtlmAuthenticator.ConnectionType;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Id:$
 */
public class NtlmV1Session implements NtlmSession {
    public NtlmV1Session(ConnectionType connectionType, byte[] ntowf, byte[] lmowfv1, String hostname) {
    }

    @Override
    public byte[] generateNegotiateMessage() {
        return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void processChallengeMessage(byte[] challengeMessageData) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void updateSequenceNumber(int seqNum) {
    }

    @Override
    public byte[] calculateMac(byte[] message) {
        return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public byte[] sign(byte[] message) {
        return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public byte[] seal(byte[] message) {
        return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public byte[] generateAuthenticateMessage() {
        return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
    }
}
